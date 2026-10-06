#!/usr/bin/env python3
"""Record the W5 pre-database restart experiment on the tracked EC2 host."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
sys.path.insert(0, str(ROOT))
from scripts.lab import LabError, run_aws, verify  # noqa: E402


def tokens():
    path = LOCAL / "app.env"
    if not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
        raise LabError(".local/app.env must exist with permissions 600.")
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in {"REPORTER_TOKEN", "OPERATOR_TOKEN"} or not value or key in values:
            raise LabError("Invalid local W4 token file format.")
        values[key] = value
    if set(values) != {"REPORTER_TOKEN", "OPERATOR_TOKEN"}:
        raise LabError("Both local role tokens are required.")
    return values


def request(base, path, method="GET", payload=None, token=None):
    headers = {}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read().decode())


def restart(key_path, known_hosts, host):
    command = ["ssh", "-i", str(key_path), "-o", "BatchMode=yes", "-o",
               "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(known_hosts),
               "-o", "ConnectTimeout=10", f"ec2-user@{host}", "sudo systemctl restart inspection"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    if result.returncode:
        raise LabError("Could not restart inspection service; remote output suppressed.")


def main():
    try:
        token_values = tokens()
        settings = json.loads((LOCAL / "config.json").read_text(encoding="utf-8"))
        record = json.loads((LOCAL / "resources.json").read_text(encoding="utf-8"))
        resources = record["resources"]
        key_path = Path(settings["key_path"])
        known_hosts = LOCAL / "w04_known_hosts"
        if not key_path.is_file() or key_path.stat().st_mode & 0o777 != 0o600:
            raise LabError("Tracked SSH key must exist with permissions 600.")
        if not known_hosts.is_file():
            raise LabError("Pinned known_hosts file is missing; deploy to the tracked host first.")
        region = verify()["region"]
        instance = run_aws(["ec2", "describe-instances", "--instance-ids", resources["instance_id"]], region)["Reservations"][0]["Instances"][0]
        if instance["State"]["Name"] != "running" or not instance.get("PublicIpAddress"):
            raise LabError("Tracked EC2 host must be running before W5 T1.")
        host = instance["PublicIpAddress"]
        base = "http://" + host
        status, health = request(base, "/health")
        if status != 200 or health.get("db_configured") is not False:
            raise LabError("T1 is only valid before W5 DB settings are deployed (db_configured=false).")
        event = json.loads((ROOT / "tests/fixtures/event-valid.json").read_text(encoding="utf-8"))
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        event["event_id"] = f"{settings['group']}-{settings['owner']}-{run_id}"
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", event["event_id"]):
            raise LabError("Generated T1 event_id is invalid.")
        before_status, before_list = request(base, "/events", token=token_values["OPERATOR_TOKEN"])
        if before_status != 200:
            raise LabError("Could not read the pre-restart event list.")
        post_status, post_event = request(base, "/events", "POST", event, token_values["REPORTER_TOKEN"])
        if post_status != 201:
            raise LabError("T1 event was not newly created; use a fresh run after checking service state.")
        present_status, present_list = request(base, "/events", token=token_values["OPERATOR_TOKEN"])
        if present_status != 200:
            raise LabError("Could not verify the event before restarting inspection.")
        restart(key_path, known_hosts, host)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                health_status, health = request(base, "/health")
                if health_status == 200 and health.get("db_configured") is False:
                    break
            except (OSError, urllib.error.URLError, json.JSONDecodeError):
                pass
            time.sleep(2)
        else:
            raise LabError("Health endpoint did not return after service restart.")
        after_status, after_list = request(base, "/events", token=token_values["OPERATOR_TOKEN"])
        if after_status != 200:
            raise LabError("Could not read the post-restart event list.")
        result = {
            "event_id": event["event_id"],
            "before_count": len(before_list["events"]),
            "after_insert_count": len(present_list["events"]),
            "after_restart_count": len(after_list["events"]),
            "event_survived_restart": any(item["event_id"] == event["event_id"] for item in after_list["events"]),
        }
        if result["event_survived_restart"]:
            raise LabError("W5 T1 expected the in-memory W4 event to disappear after restart.")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (LabError, OSError, ValueError, KeyError, subprocess.SubprocessError, urllib.error.URLError) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, LabError) else type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
