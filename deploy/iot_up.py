#!/usr/bin/env python3
"""Create the W6 IoT Core endpoint, two X.509 identities and least-privilege policies (keys stay in .local/iot)."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.lab import LabError, atomic_write, run_aws, verify  # noqa: E402

IOT = ROOT / ".local" / "iot"
RESOURCES = ROOT / ".local" / "resources.json"


def policies(account, region, code):
    def arn(kind, name):
        return f"arn:aws:iot:{region}:{account}:{kind}/{name}"
    topic = f"cxe/{code}/gw/events"
    return {
        "gw": (f"cxe-{code}-gw", [
            {"Effect": "Allow", "Action": "iot:Connect", "Resource": arn("client", f"gw-{code}")},
            {"Effect": "Allow", "Action": "iot:Publish", "Resource": arn("topic", topic)},
        ]),
        "consumer": (f"cxe-{code}-consumer", [
            {"Effect": "Allow", "Action": "iot:Connect", "Resource": arn("client", f"consumer-{code}")},
            {"Effect": "Allow", "Action": "iot:Subscribe", "Resource": arn("topicfilter", topic)},
            {"Effect": "Allow", "Action": "iot:Receive", "Resource": arn("topic", topic)},
        ]),
    }


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r"[A-Za-z0-9-]{1,40}", sys.argv[1]):
        raise LabError("usage: deploy/iot-up.sh <代號>（只含英數字與連字號）")
    code = sys.argv[1]
    ctx = verify()
    region, account = ctx["region"], ctx["account"]
    record = json.loads(RESOURCES.read_text(encoding="utf-8"))
    res = record["resources"]

    def save():
        atomic_write(RESOURCES, json.dumps(record, indent=2, ensure_ascii=False) + "\n")

    os.umask(0o077)
    IOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    IOT.chmod(0o700)
    code_file = IOT / "code"
    if code_file.exists() and code_file.read_text(encoding="utf-8").strip() != code:
        raise LabError(".local/iot/code belongs to another code; stop.")
    atomic_write(code_file, code + "\n")

    endpoint_file = IOT / "endpoint"
    if not endpoint_file.exists():
        endpoint = run_aws(["iot", "describe-endpoint", "--endpoint-type", "iot:Data-ATS"], region)["endpointAddress"]
        atomic_write(endpoint_file, endpoint + "\n")

    ca = IOT / "AmazonRootCA1.pem"
    if not ca.exists():
        subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https",
                        "--tlsv1.2", "https://www.amazontrust.com/repository/AmazonRootCA1.pem",
                        "-o", str(ca)], check=True)
        ca.chmod(0o600)

    for role in ("gw", "consumer"):
        key = f"iot_{role}_cert_id"
        if key in res:
            continue
        cert_file, private_file = IOT / f"{role}.cert.pem", IOT / f"{role}.private.key"
        if cert_file.exists() or private_file.exists():
            raise LabError(f"{role} key files exist without a resources.json record; stop and inspect.")
        # 憑證與私鑰直接寫進檔案；stdout 只回傳憑證 ID 和 ARN
        out = run_aws(["iot", "create-keys-and-certificate", "--set-as-active",
                       "--certificate-pem-outfile", str(cert_file),
                       "--private-key-outfile", str(private_file),
                       "--query", "{id:certificateId,arn:certificateArn}", "--output", "json"],
                      region, raw=True)
        info = json.loads(out)
        private_file.chmod(0o600)
        cert_file.chmod(0o600)
        res[key] = info["id"]
        res[f"iot_{role}_cert_arn"] = info["arn"]
        save()

    for role, (name, statements) in policies(account, region, code).items():
        key = f"iot_{role}_policy"
        if key in res:
            continue
        document = json.dumps({"Version": "2012-10-17", "Statement": statements})
        run_aws(["iot", "create-policy", "--policy-name", name, "--policy-document", document], region)
        run_aws(["iot", "attach-policy", "--policy-name", name, "--target", res[f"iot_{role}_cert_arn"]], region)
        res[key] = name
        save()

    for role in ("gw", "consumer"):
        status = run_aws(["iot", "describe-certificate", "--certificate-id", res[f"iot_{role}_cert_id"]],
                         region)["certificateDescription"]["status"]
        if status != "ACTIVE":
            raise LabError(f"{role} certificate status is {status}; stop.")
        print(f"{role}: certificate ACTIVE, policy {res[f'iot_{role}_policy']}")
    print("IoT setup complete. Key files: .local/iot (mode 600).")


if __name__ == "__main__":
    try:
        main()
    except LabError as exc:
        print("STOP: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
