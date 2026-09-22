#!/usr/bin/env python3
"""W3 deployment operations; all AWS calls go through scripts.lab."""
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
CONFIG = LOCAL / "config.json"
RESOURCES = LOCAL / "resources.json"

sys.path.insert(0, str(ROOT))
from scripts.lab import LabError, approve, run_aws, verify  # noqa: E402


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LabError(f"Missing {path}; create it from reviewed T1 values.") from exc


def save_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def config():
    value = load_json(CONFIG)
    required = ("vpc_id", "subnet_id", "ami_id", "source_cidr", "group", "owner", "commit", "key_path")
    missing = [key for key in required if not value.get(key)]
    if missing:
        raise LabError("Missing config values: " + ", ".join(missing))
    if not re.fullmatch(r"[0-9a-f]{40}", value["commit"]):
        raise LabError("commit must be a full 40-character SHA")
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}/32", value["source_cidr"]):
        raise LabError("source_cidr must be one IPv4 address in /32 form")
    return value


def tags(settings):
    return [
        {"Key": "course", "Value": "yuntech-115-1"},
        {"Key": "week", "Value": "w03"},
        {"Key": "group", "Value": settings["group"]},
        {"Key": "owner", "Value": settings["owner"]},
    ]


def tag_args(settings):
    return [{"ResourceType": "instance", "Tags": tags(settings)}]


def tag_arguments(settings):
    return [f"Key={item['Key']},Value={item['Value']}" for item in tags(settings)]


def resource_doc(settings):
    return {
        "region": verify()["region"],
        "tags": {item["Key"]: item["Value"] for item in tags(settings)},
        "resources": {},
    }


def confirm(label, items):
    description = label + "\n" + "\n".join(f"- {item}" for item in items)
    approve(description, "CONFIRM")


def package_user_data(commit):
    output = LOCAL / "w03-user-data.sh"
    output.unlink(missing_ok=True)
    subprocess.run(
        ["bash", "deploy/make-user-data.sh", commit, str(output)],
        cwd=ROOT,
        check=True,
    )
    return output


def validate_security_group(group, source_cidr):
    actual = []
    for permission in group.get("IpPermissions", []):
        if permission.get("IpProtocol") != "tcp":
            raise LabError("Security Group contains a non-TCP ingress rule.")
        ranges = permission.get("IpRanges", [])
        if (len(ranges) != 1 or ranges[0].get("CidrIp") != source_cidr
                or permission.get("Ipv6Ranges") or permission.get("UserIdGroupPairs")
                or permission.get("PrefixListIds")):
            raise LabError("Security Group source must be the single approved IPv4 /32.")
        actual.append((permission.get("FromPort"), permission.get("ToPort")))
    if sorted(actual) != [(22, 22), (80, 80)]:
        raise LabError("Security Group ingress must contain only TCP 22 and TCP 80.")


def up():
    settings = config()
    ctx = verify()
    public_key = Path(settings["key_path"] + ".pub")
    if not public_key.exists():
        raise LabError(f"Missing public key {public_key}; generate an ed25519 key first.")
    user_data = package_user_data(settings["commit"])
    resource_suffix = settings.get("resource_suffix", settings["owner"])
    key_name = f"w03-{resource_suffix}"
    sg_name = f"w03-{resource_suffix}-sg"
    confirm("將要建立：", [
        "1 個專用 Security Group，僅 TCP 22、80 來源 " + settings["source_cidr"],
        "1 個匯入的 EC2 key pair：" + key_name,
        "1 台 AL2023 x86_64 t3.micro，子網 " + settings["subnet_id"],
        "加密 gp3 根磁碟、DeleteOnTermination、IMDSv2 required",
        "user data commit " + settings["commit"],
    ])
    document = load_json(RESOURCES) if RESOURCES.exists() else resource_doc(settings)
    existing = document.get("resources", {})
    if existing.get("instance_id") or existing.get("key_name"):
        raise LabError("resources.json already contains key pair or instance; inspect it before deploying again.")
    sg_id = existing.get("security_group_id")
    if sg_id:
        details = run_aws(["ec2", "describe-security-groups", "--group-ids", sg_id], ctx["region"])
        group = details["SecurityGroups"][0]
        if group["VpcId"] != settings["vpc_id"] or group["GroupName"] != sg_name:
            raise LabError("Existing SG does not match this deployment; refusing to reuse it.")
    else:
        sg = run_aws(["ec2", "create-security-group", "--group-name", sg_name,
                      "--description", "W3 inspection service", "--vpc-id", settings["vpc_id"]], ctx["region"])
        sg_id = sg["GroupId"]
        document["resources"]["security_group_id"] = sg_id
        save_json(RESOURCES, document)
        run_aws(["ec2", "create-tags", "--resources", sg_id, "--tags", *tag_arguments(settings)], ctx["region"])
        run_aws(["ec2", "authorize-security-group-ingress", "--group-id", sg_id,
                  "--ip-permissions", json.dumps([
                      {"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                       "IpRanges": [{"CidrIp": settings["source_cidr"]}]} for port in (22, 80)
                  ])], ctx["region"])
    group = run_aws(["ec2", "describe-security-groups", "--group-ids", sg_id], ctx["region"])["SecurityGroups"][0]
    validate_security_group(group, settings["source_cidr"])
    print("Security Group verified: only TCP 22/80 from the approved /32")
    run_aws(["ec2", "import-key-pair", "--key-name", key_name,
             "--public-key-material", "fileb://" + str(public_key)], ctx["region"])
    document["resources"]["key_name"] = key_name
    save_json(RESOURCES, document)
    result = run_aws(["ec2", "run-instances", "--image-id", settings["ami_id"], "--instance-type", "t3.micro",
                      "--subnet-id", settings["subnet_id"], "--security-group-ids", sg_id,
                      "--key-name", key_name, "--user-data", "file://" + str(user_data),
                      "--metadata-options", "HttpTokens=required,HttpEndpoint=enabled",
                      "--block-device-mappings", json.dumps([{"DeviceName": "/dev/xvda", "Ebs": {
                          "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True}}]),
                      "--tag-specifications", json.dumps(tag_args(settings))], ctx["region"])
    instance_id = result["Instances"][0]["InstanceId"]
    document["resources"]["instance_id"] = instance_id
    save_json(RESOURCES, document)
    print(f"Created instance {instance_id}; waiting for running and /health...")
    run_aws(["ec2", "wait", "instance-running", "--instance-ids", instance_id], ctx["region"])
    detail = run_aws(["ec2", "describe-instances", "--instance-ids", instance_id], ctx["region"])
    instance = detail["Reservations"][0]["Instances"][0]
    public_ip = instance.get("PublicIpAddress")
    document["resources"]["public_ip"] = public_ip
    document["resources"]["eni_ids"] = [item["NetworkInterfaceId"] for item in instance.get("NetworkInterfaces", [])]
    root_device = instance.get("RootDeviceName")
    document["resources"]["root_volume_id"] = next(
        (item["Ebs"]["VolumeId"] for item in instance.get("BlockDeviceMappings", [])
         if item.get("DeviceName") == root_device and item.get("Ebs")),
        None,
    )
    save_json(RESOURCES, document)
    if not public_ip:
        raise LabError("Instance has no public IPv4; stop and diagnose before retrying.")
    deadline = time.time() + 300
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://{public_ip}/health", timeout=8) as response:
                payload = json.load(response)
            if response.status == 200 and payload.get("version") == settings["commit"]:
                print(json.dumps(payload, indent=2))
                return
        except (OSError, urllib.error.HTTPError, json.JSONDecodeError):
            pass
        time.sleep(5)
    raise LabError("/health did not return the requested commit within 300 seconds.")


def read_resources():
    document = load_json(RESOURCES)
    resources = document.get("resources", {})
    for key in ("instance_id", "security_group_id", "key_name", "root_volume_id"):
        if not resources.get(key):
            raise LabError(f"resources.json missing {key}")
    return document, resources


def instance_has_tags(instance, expected):
    actual = {item["Key"]: item["Value"] for item in instance.get("Tags", [])}
    return all(actual.get(key) == value for key, value in expected.items())


def stop():
    document, resources = read_resources()
    ctx = verify()
    details = run_aws(["ec2", "describe-instances", "--instance-ids", resources["instance_id"]], ctx["region"])
    instance = details["Reservations"][0]["Instances"][0]
    if not instance_has_tags(instance, document["tags"]):
        raise LabError("Instance tags do not match resources.json; refusing stop.")
    confirm("將要停止：", ["instance " + resources["instance_id"]])
    run_aws(["ec2", "stop-instances", "--instance-ids", resources["instance_id"]], ctx["region"])
    run_aws(["ec2", "wait", "instance-stopped", "--instance-ids", resources["instance_id"]], ctx["region"])
    print("Confirmed instance state: stopped")


def down():
    document, resources = read_resources()
    ctx = verify()
    details = run_aws(["ec2", "describe-instances", "--instance-ids", resources["instance_id"]], ctx["region"])
    instance = details["Reservations"][0]["Instances"][0]
    if not instance_has_tags(instance, document["tags"]):
        raise LabError("Instance tags do not match resources.json; refusing deletion.")
    confirm("將要刪除：", [
        "instance " + resources["instance_id"],
        "security group " + resources["security_group_id"],
        "key pair " + resources["key_name"],
    ])
    run_aws(["ec2", "terminate-instances", "--instance-ids", resources["instance_id"]], ctx["region"])
    run_aws(["ec2", "wait", "instance-terminated", "--instance-ids", resources["instance_id"]], ctx["region"])
    run_aws(["ec2", "delete-security-group", "--group-id", resources["security_group_id"]], ctx["region"])
    run_aws(["ec2", "delete-key-pair", "--key-name", resources["key_name"]], ctx["region"])
    for args in (
        ["ec2", "describe-instances", "--instance-ids", resources["instance_id"]],
        ["ec2", "describe-volumes", "--volume-ids", resources["root_volume_id"]],
        *(["ec2", "describe-network-interfaces", "--network-interface-ids", eni]
          for eni in resources.get("eni_ids", [])),
        ["ec2", "describe-security-groups", "--group-ids", resources["security_group_id"]],
        ["ec2", "describe-key-pairs", "--key-names", resources["key_name"]],
    ):
        try:
            run_aws(args, ctx["region"])
        except LabError:
            continue
        raise LabError("A tracked resource still exists after deletion: " + " ".join(args[:3]))
    RESOURCES.unlink()
    print("Confirmed tracked instance, security group and key pair are absent.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("up", "stop", "down"))
    args = parser.parse_args()
    try:
        {"up": up, "stop": stop, "down": down}[args.command]()
    except (LabError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print("STOP: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
