#!/usr/bin/env python3
"""Run the seven W4 auth, authorization, validation and duplicate checks."""
import json
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


def load_tokens():
    path = LOCAL / "app.env"
    if not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
        raise LabError(".local/app.env must exist with permissions 600.")
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in {"REPORTER_TOKEN", "OPERATOR_TOKEN"} or not value:
            raise LabError("Invalid local token file format.")
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
    return response.status, json.loads(response.read().decode())


def main():
    try:
        tokens = load_tokens()
        record = json.loads((LOCAL / "resources.json").read_text(encoding="utf-8"))
        instance_id = record["resources"]["instance_id"]
        region = verify()["region"]
        instance = run_aws(["ec2", "describe-instances", "--instance-ids", instance_id], region)["Reservations"][0]["Instances"][0]
        if instance["State"]["Name"] != "running" or not instance.get("PublicIpAddress"):
            raise LabError("Tracked host must be running before the refusal matrix.")
        base = "http://" + instance["PublicIpAddress"]
        status, health = request(base, "/health")
        if status != 200:
            raise LabError("Health endpoint is unavailable.")
        deployed_commit = subprocess.check_output(
            ["git", "rev-parse", "--verify", "HEAD^{commit}"], cwd=ROOT, text=True
        ).strip()
        if health.get("version") != deployed_commit:
            raise LabError("Host /health version does not match the committed source. Deploy first.")
        valid = json.loads((ROOT / "tests/fixtures/event-valid.json").read_text(encoding="utf-8"))
        invalid = json.loads((ROOT / "tests/fixtures/event-invalid-timezone.json").read_text(encoding="utf-8"))
        print("version=" + health["version"])
        results = []
        results.append(request(base, "/events", "POST", valid, tokens["REPORTER_TOKEN"]))
        results.append(request(base, "/events", "POST", valid))
        results.append(request(base, "/events", "POST", {**valid, "event_id": valid["event_id"] + "-op"}, tokens["OPERATOR_TOKEN"]))
        results.append(request(base, "/events", "POST", invalid, tokens["REPORTER_TOKEN"]))
        results.append(request(base, "/events", "POST", valid, tokens["REPORTER_TOKEN"]))
        results.append(request(base, "/events", token=tokens["REPORTER_TOKEN"]))
        results.append(request(base, "/events", token=tokens["OPERATOR_TOKEN"]))
        expected = [201, 401, 403, 400, 409, 403, 200]
        for number, ((status, body), code) in enumerate(zip(results, expected), start=1):
            if status != code:
                raise LabError(f"Matrix row {number} returned {status}, expected {code}.")
            detail = body if number in (1, 7) else {key: body.get(key) for key in ("error", "field") if key in body}
            print(json.dumps({"row": number, "http": status, "body": detail}, ensure_ascii=False))
        print("All seven matrix rows passed.")
        return 0
    except (LabError, OSError, ValueError, KeyError, urllib.error.URLError) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, LabError) else type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
