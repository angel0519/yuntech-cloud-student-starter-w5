#!/usr/bin/env python3
"""Deploy one committed W4 service version to the tracked W3 EC2 host."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
CONFIG = LOCAL / "config.json"
RESOURCES = LOCAL / "resources.json"
APP_ENV = LOCAL / "app.env"
sys.path.insert(0, str(ROOT))
from scripts.lab import LabError, approve, run_aws, verify  # noqa: E402


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise LabError(f"Missing or invalid local deployment file: {path.name}") from exc


def current_cidr():
    try:
        address = urllib.request.urlopen("https://checkip.amazonaws.com", timeout=5).read().decode().strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise LabError("Could not determine the Codespace public IPv4; stop before deployment.") from exc
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", address):
        raise LabError("Codespace IP service returned an invalid IPv4 address.")
    return address + "/32"


def read_secret_file():
    try:
        mode = APP_ENV.stat().st_mode & 0o777
        contents = APP_ENV.read_text(encoding="utf-8")
    except OSError as exc:
        raise LabError("Create .local/app.env with the two W4 tokens before deployment.") from exc
    if mode != 0o600:
        raise LabError(".local/app.env permissions must be exactly 600.")
    values = {}
    for line in contents.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in {"REPORTER_TOKEN", "OPERATOR_TOKEN"} or not value:
            raise LabError(".local/app.env must contain only REPORTER_TOKEN and OPERATOR_TOKEN assignments.")
        if key in values:
            raise LabError(".local/app.env contains a duplicate token assignment.")
        values[key] = value
    if set(values) != {"REPORTER_TOKEN", "OPERATOR_TOKEN"} or values["REPORTER_TOKEN"] == values["OPERATOR_TOKEN"]:
        raise LabError(".local/app.env must contain distinct reporter and operator tokens.")
    return APP_ENV.read_bytes()


def verify_ingress(group, source):
    observed = []
    for permission in group.get("IpPermissions", []):
        ranges = permission.get("IpRanges", [])
        if (permission.get("IpProtocol") != "tcp" or len(ranges) != 1
                or ranges[0].get("CidrIp") != source or permission.get("Ipv6Ranges")
                or permission.get("UserIdGroupPairs") or permission.get("PrefixListIds")):
            raise LabError("SG must allow only TCP 22/80 from current Codespace " + source)
        observed.append((permission.get("FromPort"), permission.get("ToPort")))
    if sorted(observed) != [(22, 22), (80, 80)]:
        raise LabError("SG ingress is not exactly TCP 22 and TCP 80 from current Codespace " + source)


def ssh_command(key_path, known_hosts, host, remote_command, payload=None):
    command = [
        "ssh", "-i", str(key_path), "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=" + str(known_hosts),
        "-o", "ConnectTimeout=10", f"ec2-user@{host}", remote_command,
    ]
    try:
        result = subprocess.run(command, input=payload, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LabError("SSH operation failed or timed out; inspect host state before retrying.") from exc
    if result.returncode:
        raise LabError("SSH operation failed; output was suppressed to protect deployment data.")
    return result.stdout


def deploy():
    if not sys.stdin.isatty():
        raise LabError("Deployment requires an interactive terminal for explicit approval.")
    secret_payload = read_secret_file()
    settings = load_json(CONFIG)
    record = load_json(RESOURCES)
    resources = record.get("resources", {})
    instance_id = resources.get("instance_id")
    key_name = resources.get("key_name")
    key_path = Path(settings.get("key_path", ""))
    if not instance_id or not key_name or not key_path.is_file():
        raise LabError("Tracked instance, key pair name, or local SSH private key is missing.")
    if key_path.stat().st_mode & 0o777 != 0o600:
        raise LabError("SSH private key permissions must be 600.")
    commit = subprocess.check_output(["git", "rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"], cwd=ROOT, text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain", "--", "app/service.py", "deploy/nginx.conf"], cwd=ROOT, text=True).strip():
        raise LabError("Commit app/service.py and deploy/nginx.conf before deployment.")
    ctx = verify()
    region = ctx["region"]
    instance = run_aws(["ec2", "describe-instances", "--instance-ids", instance_id], region)["Reservations"][0]["Instances"][0]
    expected_tags = record.get("tags", {})
    actual_tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
    if any(actual_tags.get(key) != value for key, value in expected_tags.items()):
        raise LabError("Instance tags do not match resources.json; refusing deployment.")
    if instance["State"]["Name"] != "running":
        raise LabError("The tracked EC2 instance must be running before W4 deployment.")
    host = instance.get("PublicIpAddress")
    if not host:
        raise LabError("The running instance has no public IPv4 address.")
    source = current_cidr()
    sg_id = resources.get("security_group_id")
    group = run_aws(["ec2", "describe-security-groups", "--group-ids", sg_id], region)["SecurityGroups"][0]
    verify_ingress(group, source)
    output = LOCAL / "w04-user-data.sh"
    output.unlink(missing_ok=True)
    subprocess.run(["bash", "deploy/make-user-data.sh", commit, str(output)], cwd=ROOT, check=True)
    payload = output.read_bytes()
    if len(payload) >= 16 * 1024:
        raise LabError("Generated installer exceeds the EC2 user-data size limit.")
    print("將要部署：")
    print(f"- instance {instance_id} at {host}")
    print(f"- committed service version {commit}")
    print("- install service, upload root-owned mode-600 /etc/inspection/app.env, restart inspection")
    approve("", "CONFIRM")
    LOCAL.mkdir(mode=0o700, exist_ok=True)
    known_hosts = LOCAL / "w04_known_hosts"
    known_hosts.touch(mode=0o600, exist_ok=True)
    known_hosts.chmod(0o600)
    ssh_command(key_path, known_hosts, host, "sudo bash -s", payload)
    install_secret = (
        "sudo bash -c 'install -d -o root -g root -m 700 /etc/inspection; "
        "umask 077; cat > /etc/inspection/app.env; "
        "chown root:root /etc/inspection/app.env; chmod 600 /etc/inspection/app.env'"
    )
    ssh_command(key_path, known_hosts, host, install_secret, secret_payload)
    ssh_command(key_path, known_hosts, host, "sudo systemctl restart inspection")
    deadline = time.monotonic() + 180
    url = f"http://{host}/health"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=8) as response:
                health = json.loads(response.read().decode())
            if response.status == 200 and health.get("version") == commit and health.get("auth_configured") is True:
                print(json.dumps(health, indent=2))
                return
        except (OSError, urllib.error.HTTPError, UnicodeDecodeError, json.JSONDecodeError):
            pass
        time.sleep(3)
    raise LabError("Health check did not report this commit and auth_configured=true within 180 seconds.")


if __name__ == "__main__":
    try:
        deploy()
    except (LabError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, LabError) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(1)
