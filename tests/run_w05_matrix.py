#!/usr/bin/env python3
"""Run the W5 five-row persistence/idempotency acceptance matrix."""
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
sys.path.insert(0, str(ROOT))
from scripts.lab import LabError, run_aws, verify  # noqa: E402


def read_tokens():
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
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode()
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read().decode())


def ssh(key_path, known_hosts, host, command, payload=None):
    args = ["ssh", "-i", str(key_path), "-o", "BatchMode=yes", "-o",
            "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(known_hosts),
            "-o", "ConnectTimeout=10", f"ec2-user@{host}", command]
    try:
        result = subprocess.run(args, input=payload, capture_output=True, text=True, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LabError("SSH matrix check failed; inspect host state before retrying.") from exc
    if result.returncode:
        raise LabError("SSH matrix check failed; remote output was suppressed.")
    return result.stdout.strip()


def main():
    try:
        tokens = read_tokens()
        record = json.loads((LOCAL / "resources.json").read_text(encoding="utf-8"))
        resources = record["resources"]
        settings = json.loads((LOCAL / "config.json").read_text(encoding="utf-8"))
        key_path = Path(settings["key_path"])
        if not key_path.is_file() or key_path.stat().st_mode & 0o777 != 0o600:
            raise LabError("Tracked SSH private key must exist with permissions 600.")
        instance_id = resources["instance_id"]
        region = verify()["region"]
        instance = run_aws(["ec2", "describe-instances", "--instance-ids", instance_id], region)["Reservations"][0]["Instances"][0]
        if instance["State"]["Name"] != "running" or not instance.get("PublicIpAddress"):
            raise LabError("Tracked EC2 host must be running before the W5 matrix.")
        host = instance["PublicIpAddress"]
        known_hosts = LOCAL / "w04_known_hosts"
        if not known_hosts.is_file():
            raise LabError("Missing pinned SSH known_hosts file; deploy to this host first.")
        base = "http://" + host
        health_status, health = request(base, "/health")
        if health_status != 200 or health.get("db_configured") is not True:
            raise LabError("Host health must be 200 with db_configured=true.")
        version = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD^{commit}"], cwd=ROOT, text=True).strip()
        if health.get("version") != version:
            raise LabError("Host /health version does not match committed source; deploy first.")
        event = json.loads((ROOT / "tests/fixtures/event-valid.json").read_text(encoding="utf-8"))
        settings = json.loads((LOCAL / "config.json").read_text(encoding="utf-8"))
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        event["event_id"] = f"{settings['group']}-{settings['owner']}-{run_id}"
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", event["event_id"]):
            raise LabError("Fixture event_id is outside the W5 contract.")
        print("version=" + health["version"])
        print("db_configured=" + str(health["db_configured"]).lower())

        created_status, created = request(base, "/events", "POST", event, tokens["REPORTER_TOKEN"])
        same_status, same = request(base, "/events", "POST", event, tokens["REPORTER_TOKEN"])
        changed_event = dict(event, note=(event.get("note") or "") + " changed")
        conflict_status, conflict = request(base, "/events", "POST", changed_event, tokens["REPORTER_TOKEN"])
        expected = ((created_status, 201), (same_status, 200), (conflict_status, 409))
        for row, (actual, expected_status) in enumerate(expected, start=1):
            if actual != expected_status:
                raise LabError(f"Matrix row {row} returned {actual}; expected {expected_status}.")
        print(json.dumps({"row": 1, "http": created_status, "body": created}, ensure_ascii=False))
        print(json.dumps({"row": 2, "http": same_status, "body": same}, ensure_ascii=False))
        print(json.dumps({"row": 3, "http": conflict_status, "body": conflict}, ensure_ascii=False))

        ssh(key_path, known_hosts, host, "sudo systemctl restart inspection")
        detail_status, detail = request(base, "/events/" + event["event_id"], token=tokens["OPERATOR_TOKEN"])
        if detail_status != 200 or detail.get("event_id") != event["event_id"]:
            raise LabError("Matrix row 4 did not find the event after service restart.")
        print(json.dumps({"row": 4, "http": detail_status, "body": detail}, ensure_ascii=False))

        # Event IDs are restricted above, so they cannot inject shell syntax into the remote psql variable.
        psql = (
            "sudo bash -c 'set -a; . /etc/inspection/app.env; set +a; "
            "PGPASSWORD=\"$DB_PASSWORD\" psql \"host=$DB_HOST dbname=$DB_NAME user=$DB_USER "
            "sslmode=verify-full sslrootcert=/etc/inspection/rds-ca.pem\" "
            "-v event_id=\"" + event["event_id"] + "\" -At'"
        )
        query = "SELECT count(*) FROM events WHERE event_id = :'event_id';\n"
        count_text = ssh(key_path, known_hosts, host, psql, query)
        if count_text != "1":
            raise LabError("Matrix row 5 expected one matching database row.")
        print(json.dumps({"row": 5, "psql_count": int(count_text)}, ensure_ascii=False))
        print("All five W5 matrix rows passed.")
        return 0
    except (LabError, OSError, ValueError, KeyError, subprocess.CalledProcessError, urllib.error.URLError) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, LabError) else type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
