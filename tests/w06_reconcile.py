#!/usr/bin/env python3
"""Compare gateway PUBACKs, consumer log results, DB rows and the device filter for one run."""
import argparse
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from deploy import w04_deploy as w4  # noqa: E402
from scripts.lab import LabError, run_aws, verify  # noqa: E402

LAST_RUN = ROOT / ".local" / "w06-last-run.json"
SAFE = re.compile(r"[A-Za-z0-9-]{1,40}")
COUNT = re.compile(r"(\d+)\s+result=([a-z]+)")


def remote_counts(key, host, known, prefix):
    command = ("sudo journalctl -u inspection-consumer -o cat --no-pager | grep -F 'event_id=" + prefix
               + "-' | grep -o 'result=[a-z]*' | sort | uniq -c")
    return w4.ssh_command(key, known, host, command).decode("utf-8")


def remote_rows(key, host, known, prefix):
    sql = "SELECT count(*) FROM events WHERE left(event_id, length(:'prefix')) = :'prefix';\n"
    command = ("sudo bash -c 'set -a; . /etc/inspection/app.env; set +a; "
               "PGPASSWORD=\"$DB_PASSWORD\" psql \"host=$DB_HOST dbname=$DB_NAME user=$DB_USER "
               "sslmode=verify-full sslrootcert=/etc/inspection/rds-ca.pem\" -At -v prefix=" + prefix + "-'")
    return int(w4.ssh_command(key, known, host, command, sql.encode()).decode().strip() or 0)


def operator_token():
    for line in (ROOT / ".local" / "app.env").read_text(encoding="utf-8").splitlines():
        if line.startswith("OPERATOR_TOKEN="):
            return line.partition("=")[2]
    raise LabError("OPERATOR_TOKEN missing from .local/app.env")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    if not SAFE.fullmatch(args.code) or not SAFE.fullmatch(args.run):
        raise LabError("code and run must match [A-Za-z0-9-]{1,40}")
    prefix = f"{args.code}-{args.run}"
    last = json.loads(LAST_RUN.read_text(encoding="utf-8"))
    if last.get("prefix") != prefix:
        raise LabError("Last gateway run does not match this prefix; run gateway_sim.py first.")

    record = json.loads((ROOT / ".local" / "resources.json").read_text(encoding="utf-8"))
    ctx = verify()
    instance = run_aws(["ec2", "describe-instances", "--instance-ids", record["resources"]["instance_id"]],
                       ctx["region"])["Reservations"][0]["Instances"][0]
    host = instance["PublicIpAddress"]
    key = Path(json.loads((ROOT / ".local" / "config.json").read_text(encoding="utf-8"))["key_path"])
    known = ROOT / ".local" / "w04_known_hosts"

    health = json.loads(urllib.request.urlopen(f"http://{host}/health", timeout=8).read().decode())
    print(f"version={health.get('version')} db_configured={health.get('db_configured')} prefix={prefix}")
    print(f"puback_ok={last['puback_ok']}/{last['published']}")

    deadline = time.monotonic() + 60
    results, rows = {}, 0
    while True:
        results = {name: int(num) for num, name in COUNT.findall(remote_counts(key, host, known, prefix))}
        rows = remote_rows(key, host, known, prefix)
        if sum(results.values()) >= last["published"] or time.monotonic() >= deadline:
            break
        time.sleep(5)
    print("consumer " + " ".join(f"{name}={results.get(name, 0)}" for name in
                                 ("created", "duplicate", "rejected", "error")))
    print(f"db_rows={rows}")

    request = urllib.request.Request(f"http://{host}/events?device_id={args.code}-d01",
                                     headers={"Authorization": "Bearer " + operator_token()})
    events = json.loads(urllib.request.urlopen(request, timeout=8).read().decode())["events"]
    mine = [item["event_id"] for item in events if item["event_id"].startswith(prefix + "-")]
    print(f"filter device={args.code}-d01 rows={len(mine)}")
    for event_id in mine:
        print(event_id)


if __name__ == "__main__":
    try:
        main()
    except LabError as exc:
        print("STOP: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
