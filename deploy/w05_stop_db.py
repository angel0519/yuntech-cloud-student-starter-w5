#!/usr/bin/env python3
"""Stop only the RDS DB instance recorded in .local/resources.json."""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.lab import LabError, approve, run_aws, verify  # noqa: E402


def main():
    record = json.loads((ROOT / ".local/resources.json").read_text(encoding="utf-8"))
    resources = record.get("resources", {})
    identifier = resources.get("db_instance_identifier")
    if not identifier:
        raise LabError("No tracked W5 DB instance identifier in resources.json.")
    ctx = verify()
    result = run_aws(["rds", "describe-db-instances", "--db-instance-identifier", identifier], ctx["region"])
    instance = result["DBInstances"][0]
    if instance.get("PubliclyAccessible") is not False:
        raise LabError("Refusing to stop a DB that is not confirmed private.")
    expected = record.get("db_tags", {})
    arn = instance.get("DBInstanceArn")
    if not expected or not arn:
        raise LabError("Missing W5 ownership tags or DB ARN; refusing to stop.")
    tags = run_aws(["rds", "list-tags-for-resource", "--resource-name", arn], ctx["region"])["TagList"]
    actual = {item["Key"]: item["Value"] for item in tags}
    if any(actual.get(key) != value for key, value in expected.items()):
        raise LabError("DB tags do not match resources.json; refusing to stop.")
    state = instance["DBInstanceStatus"]
    print("將要停止：")
    print(f"- RDS PostgreSQL {identifier} ({state}), PubliclyAccessible=false")
    print("- RDS 停止最多 7 天；其後 AWS 會自動啟動並恢復計費。儲存與備份費仍可能產生。")
    approve("", "CONFIRM")
    if state != "stopped":
        run_aws(["rds", "stop-db-instance", "--db-instance-identifier", identifier], ctx["region"])
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            final = run_aws(["rds", "describe-db-instances", "--db-instance-identifier", identifier], ctx["region"])["DBInstances"][0]
            if final["DBInstanceStatus"] == "stopped":
                break
            if final["DBInstanceStatus"] in {"failed", "incompatible-restore"}:
                raise LabError("RDS entered terminal state while stopping; inspect before retrying.")
            time.sleep(15)
        else:
            raise LabError("Timed out waiting for RDS stopped state; do not submit another stop request.")
    final = run_aws(["rds", "describe-db-instances", "--db-instance-identifier", identifier], ctx["region"])["DBInstances"][0]
    if final["DBInstanceStatus"] != "stopped":
        raise LabError("RDS did not reach stopped state.")
    print("Confirmed DBInstanceStatus=stopped")


if __name__ == "__main__":
    try:
        main()
    except (LabError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, LabError) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(1)
