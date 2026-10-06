#!/usr/bin/env python3
"""Create the W5 private PostgreSQL resources recorded in .local/resources.json."""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
CONFIG = LOCAL / "config.json"
RESOURCES = LOCAL / "resources.json"
DB_ENV = LOCAL / "db.env"
DB_NAME = "inspection"
DB_USER = "inspection_admin"

sys.path.insert(0, str(ROOT))
from scripts.lab import LabError, approve, run_aws, verify  # noqa: E402


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LabError(f"Missing or invalid local file: {path.name}") from exc


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".w05-resources-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_private(path, text):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".w05-secret-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    path.chmod(0o600)


def read_db_env():
    if not DB_ENV.exists():
        return {}
    if DB_ENV.stat().st_mode & 0o777 != 0o600:
        raise LabError(".local/db.env permissions must be exactly 600.")
    result = {}
    for line in DB_ENV.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in {"DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"}:
            raise LabError(".local/db.env contains an unexpected setting.")
        if key in result:
            raise LabError(".local/db.env contains a duplicate setting.")
        result[key] = value
    return result


def write_db_env(values):
    keys = ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD")
    write_private(DB_ENV, "".join(f"{key}={values.get(key, '')}\n" for key in keys))


def aws_tags(tags):
    return [{"Key": key, "Value": value} for key, value in tags.items()]


def tag_specifications(resource_type, tags):
    return json.dumps([{"ResourceType": resource_type, "Tags": aws_tags(tags)}])


def get_vpc_cidrs(vpc):
    cidrs = [vpc["CidrBlock"]]
    cidrs.extend(item["CidrBlock"] for item in vpc.get("CidrBlockAssociationSet", [])
                 if item.get("CidrBlockState", {}).get("State") == "associated")
    return [ipaddress.ip_network(value) for value in cidrs]


def choose_private_subnets(vpc, existing_subnets, zones, already_created):
    used_networks = [ipaddress.ip_network(item["CidrBlock"]) for item in existing_subnets]
    used_networks.extend(ipaddress.ip_network(item["CidrBlock"]) for item in already_created)
    used_zones = {item["AvailabilityZone"] for item in already_created}
    free_zones = [zone for zone in zones if zone not in used_zones]
    candidates = []
    for vpc_cidr in get_vpc_cidrs(vpc):
        if vpc_cidr.version != 4 or vpc_cidr.prefixlen > 24:
            continue
        candidates.extend(network for network in vpc_cidr.subnets(new_prefix=24)
                          if not any(network.overlaps(used) for used in used_networks))
    if len(candidates) < 2 or len(free_zones) < 2:
        raise LabError("Could not find two unused IPv4 /24s and two available AZs in the host VPC.")
    return [(str(candidates[index]), free_zones[index]) for index in range(2)]


def ensure_private_subnets(document, settings, region, vpc):
    resources = document["resources"]
    subnets = run_aws(["ec2", "describe-subnets", "--filters", f"Name=vpc-id,Values={vpc['VpcId']}"], region)["Subnets"]
    ids = resources.setdefault("db_private_subnet_ids", [])
    created_info = []
    if ids:
        for subnet_id in ids:
            subnet = run_aws(["ec2", "describe-subnets", "--subnet-ids", subnet_id], region)["Subnets"][0]
            if subnet["VpcId"] != vpc["VpcId"]:
                raise LabError("Tracked W5 subnet is outside the host VPC.")
            created_info.append({"SubnetId": subnet_id, "CidrBlock": subnet["CidrBlock"],
                                 "AvailabilityZone": subnet["AvailabilityZone"]})
    if len(ids) < 2:
        zones = [item["ZoneName"] for item in run_aws(
            ["ec2", "describe-availability-zones", "--filters", "Name=state,Values=available"], region
        )["AvailabilityZones"]]
        allocations = choose_private_subnets(vpc, subnets, zones, created_info)
        for cidr, zone in allocations:
            result = run_aws(["ec2", "create-subnet", "--vpc-id", vpc["VpcId"],
                              "--cidr-block", cidr, "--availability-zone", zone,
                              "--tag-specifications", tag_specifications("subnet", settings["tags"])], region)
            subnet_id = result["Subnet"]["SubnetId"]
            ids.append(subnet_id)
            document["resources"]["db_private_subnet_ids"] = ids
            save_json(RESOURCES, document)
            created_info.append({"SubnetId": subnet_id, "CidrBlock": cidr, "AvailabilityZone": zone})
            subnets.append({"SubnetId": subnet_id, "CidrBlock": cidr, "AvailabilityZone": zone})
    if len(ids) != 2 or created_info[0]["AvailabilityZone"] == created_info[1]["AvailabilityZone"]:
        raise LabError("Tracked W5 private subnet IDs must identify exactly two different AZs.")
    if ipaddress.ip_network(created_info[0]["CidrBlock"]).overlaps(ipaddress.ip_network(created_info[1]["CidrBlock"])):
        raise LabError("Tracked W5 private subnet CIDRs overlap.")
    return created_info


def ensure_isolated_route_table(document, settings, region, vpc_id, subnets):
    resources = document["resources"]
    route_table_id = resources.get("db_route_table_id")
    if route_table_id:
        table = run_aws(["ec2", "describe-route-tables", "--route-table-ids", route_table_id], region)["RouteTables"][0]
    else:
        result = run_aws(["ec2", "create-route-table", "--vpc-id", vpc_id,
                          "--tag-specifications", tag_specifications("route-table", settings["tags"])], region)
        table = result["RouteTable"]
        route_table_id = table["RouteTableId"]
        resources["db_route_table_id"] = route_table_id
        save_json(RESOURCES, document)
    routes = table.get("Routes", [])
    local_routes = [route for route in routes if route.get("GatewayId") == "local"]
    nonlocal_routes = [route for route in routes if route.get("GatewayId") != "local"]
    if nonlocal_routes:
        raise LabError("Tracked W5 route table is not isolated; refusing to use it.")
    if len(local_routes) != 1:
        raise LabError("Tracked W5 route table is missing its local route.")
    associated = {item.get("SubnetId") for item in table.get("Associations", []) if not item.get("Main")}
    for subnet in subnets:
        subnet_id = subnet["SubnetId"]
        if subnet_id not in associated:
            result = run_aws(["ec2", "associate-route-table", "--route-table-id", route_table_id,
                              "--subnet-id", subnet_id], region)
            resources.setdefault("db_route_association_ids", []).append(result["AssociationId"])
            save_json(RESOURCES, document)
    table = run_aws(["ec2", "describe-route-tables", "--route-table-ids", route_table_id], region)["RouteTables"][0]
    associated = {item.get("SubnetId") for item in table.get("Associations", []) if not item.get("Main")}
    if associated != {item["SubnetId"] for item in subnets}:
        raise LabError("W5 isolated route table must be explicitly associated only to the two tracked subnets.")
    return route_table_id


def ensure_db_subnet_group(document, settings, region, subnet_ids):
    resources = document["resources"]
    name = resources.get("db_subnet_group_name", "w05-" + settings["resource_suffix"] + "-subnets")
    try:
        result = run_aws(["rds", "describe-db-subnet-groups", "--db-subnet-group-name", name], region)
    except LabError as exc:
        if "DBSubnetGroupNotFound" not in str(exc):
            raise
        result = run_aws(["rds", "create-db-subnet-group", "--db-subnet-group-name", name,
                          "--db-subnet-group-description", "Private W5 inspection database subnets",
                          "--subnet-ids", *subnet_ids, "--tags", json.dumps(aws_tags(settings["tags"]))], region)
        result = {"DBSubnetGroups": [result["DBSubnetGroup"]]}
    group = result["DBSubnetGroups"][0]
    actual_subnets = {item["SubnetIdentifier"] for item in group.get("Subnets", [])}
    if group.get("VpcId") != settings["vpc_id"] or actual_subnets != set(subnet_ids):
        raise LabError("DB subnet group does not exactly match the tracked private subnets.")
    resources["db_subnet_group_name"] = name
    save_json(RESOURCES, document)
    return name


def ensure_db_security_group(document, settings, region, vpc_id, host_sg_id):
    resources = document["resources"]
    sg_id = resources.get("db_security_group_id")
    if sg_id:
        group = run_aws(["ec2", "describe-security-groups", "--group-ids", sg_id], region)["SecurityGroups"][0]
        if group["VpcId"] != vpc_id:
            raise LabError("Tracked DB security group is in a different VPC.")
    else:
        name = "w05-" + settings["resource_suffix"] + "-db-sg"
        result = run_aws(["ec2", "create-security-group", "--group-name", name,
                          "--description", "W5 private PostgreSQL; ingress only from inspection host SG",
                          "--vpc-id", vpc_id], region)
        sg_id = result["GroupId"]
        resources["db_security_group_id"] = sg_id
        save_json(RESOURCES, document)
        run_aws(["ec2", "create-tags", "--resources", sg_id, "--tags", *[
            f"Key={key},Value={value}" for key, value in settings["tags"].items()
        ]], region)
    group = run_aws(["ec2", "describe-security-groups", "--group-ids", sg_id], region)["SecurityGroups"][0]
    expected = {("tcp", 5432, 5432, host_sg_id)}
    actual = set()
    for permission in group.get("IpPermissions", []):
        for pair in permission.get("UserIdGroupPairs", []):
            actual.add((permission.get("IpProtocol"), permission.get("FromPort"),
                        permission.get("ToPort"), pair.get("GroupId")))
        if permission.get("IpRanges") or permission.get("Ipv6Ranges") or permission.get("PrefixListIds"):
            raise LabError("DB security group contains a CIDR or prefix-list ingress rule.")
    if actual and actual != expected:
        raise LabError("DB security group has unexpected ingress rules; refusing to alter it.")
    if not actual:
        run_aws(["ec2", "authorize-security-group-ingress", "--group-id", sg_id,
                 "--ip-permissions", json.dumps([{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                  "UserIdGroupPairs": [{"GroupId": host_sg_id}]}])], region)
    return sg_id


def password_from_local_file():
    values = read_db_env()
    return values.get("DB_PASSWORD", "")


def create_request_file(payload):
    fd, path = tempfile.mkstemp(prefix=".w05-rds-create-", suffix=".json", dir=LOCAL)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream)
            stream.write("\n")
    except Exception:
        os.close(fd)
        os.unlink(path)
        raise
    return Path(path)


def wait_for_db_status(identifier, desired_status, region, timeout_seconds=900):
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        instance = run_aws(["rds", "describe-db-instances", "--db-instance-identifier", identifier], region)["DBInstances"][0]
        status = instance["DBInstanceStatus"]
        if status == desired_status:
            return instance
        if status in {"failed", "incompatible-restore", "storage-full"}:
            raise LabError("RDS entered terminal state " + status + "; inspect the tracked DB before retrying.")
        print("RDS state=" + status + "; waiting for " + desired_status)
        time.sleep(15)
    raise LabError("Timed out waiting for RDS to reach " + desired_status + "; do not create another DB.")


def ensure_rds_instance(document, settings, region, subnet_group, db_sg_id, password):
    resources = document["resources"]
    identifier = resources.get("db_instance_identifier", "w05-" + settings["resource_suffix"] + "-pg")
    try:
        result = run_aws(["rds", "describe-db-instances", "--db-instance-identifier", identifier], region)
        instance = result["DBInstances"][0]
    except LabError as exc:
        if "DBInstanceNotFound" not in str(exc):
            raise
        request = {
            "DBInstanceIdentifier": identifier,
            "Engine": "postgres",
            "DBInstanceClass": "db.t3.micro",
            "AllocatedStorage": 20,
            "StorageType": "gp3",
            "DBName": DB_NAME,
            "MasterUsername": DB_USER,
            "MasterUserPassword": password,
            "VpcSecurityGroupIds": [db_sg_id],
            "DBSubnetGroupName": subnet_group,
            "PubliclyAccessible": False,
            "StorageEncrypted": True,
            "MultiAZ": False,
            "BackupRetentionPeriod": 0,
            "Port": 5432,
            "Tags": aws_tags(settings["tags"]),
        }
        request_file = create_request_file(request)
        try:
            result = run_aws(["rds", "create-db-instance", "--cli-input-json", "file://" + str(request_file)], region)
            instance = result["DBInstance"]
        finally:
            request_file.unlink(missing_ok=True)
    resources["db_instance_identifier"] = identifier
    resources["db_instance_resource_id"] = instance.get("DbiResourceId")
    save_json(RESOURCES, document)
    print("RDS create requested; waiting for available...")
    instance = wait_for_db_status(identifier, "available", region)
    if instance["DBInstanceStatus"] != "available" or instance["PubliclyAccessible"]:
        raise LabError("RDS read-back failed: expected available and PubliclyAccessible=false.")
    endpoint = instance.get("Endpoint", {}).get("Address")
    if not endpoint:
        raise LabError("RDS endpoint is not present after the instance became available.")
    resources["db_endpoint"] = endpoint
    save_json(RESOURCES, document)
    db_values = read_db_env()
    db_values.update({"DB_HOST": endpoint, "DB_PORT": "5432", "DB_NAME": DB_NAME,
                     "DB_USER": DB_USER, "DB_PASSWORD": password})
    write_db_env(db_values)
    return instance


def main():
    if not sys.stdin.isatty():
        raise LabError("W5 RDS provisioning requires interactive approval.")
    ctx = verify()
    settings = load_json(CONFIG)
    document = load_json(RESOURCES)
    resources = document.get("resources", {})
    instance_id = resources.get("instance_id")
    if not instance_id:
        raise LabError("No tracked W3/W4 instance ID in .local/resources.json.")
    host = run_aws(["ec2", "describe-instances", "--instance-ids", instance_id], ctx["region"])["Reservations"][0]["Instances"][0]
    if host["State"]["Name"] != "running":
        raise LabError("Start the tracked EC2 host and finish W5 T1 before creating RDS.")
    expected_host_tags = document.get("tags", {})
    actual_host_tags = {item["Key"]: item["Value"] for item in host.get("Tags", [])}
    if not expected_host_tags or any(actual_host_tags.get(key) != value for key, value in expected_host_tags.items()):
        raise LabError("Host ownership tags do not match resources.json; refusing RDS creation.")
    vpc_id = host["VpcId"]
    if vpc_id != settings["vpc_id"]:
        raise LabError("Tracked host VPC does not match local deployment configuration.")
    host_sg_id = host["SecurityGroups"][0]["GroupId"]
    if len(host["SecurityGroups"]) != 1:
        raise LabError("Expected exactly one host security group so DB SG reference is unambiguous.")
    vpcs = run_aws(["ec2", "describe-vpcs", "--vpc-ids", vpc_id], ctx["region"])["Vpcs"]
    if len(vpcs) != 1:
        raise LabError("Could not read the tracked host VPC.")
    subnets = run_aws(["ec2", "describe-subnets", "--filters", f"Name=vpc-id,Values={vpc_id}"], ctx["region"])["Subnets"]
    existing_private = []
    already_tracked = resources.get("db_private_subnet_ids", [])
    if already_tracked:
        existing_private = [run_aws(["ec2", "describe-subnets", "--subnet-ids", subnet_id], ctx["region"])["Subnets"][0]
                            for subnet_id in already_tracked]
    zones = [item["ZoneName"] for item in run_aws(
        ["ec2", "describe-availability-zones", "--filters", "Name=state,Values=available"], ctx["region"]
    )["AvailabilityZones"]]
    planned_subnets = existing_private + [
        {"SubnetId": "<new>", "CidrBlock": cidr, "AvailabilityZone": zone}
        for cidr, zone in choose_private_subnets(vpcs[0], subnets, zones, existing_private)
    ] if len(existing_private) < 2 else existing_private
    next_index = len(existing_private)
    needed = 2 - len(existing_private)
    if needed < 0:
        raise LabError("More than two W5 private subnet IDs are tracked; inspect resources.json.")
    if needed:
        allocations = choose_private_subnets(vpcs[0], subnets, zones, existing_private)[:needed]
        planned_subnets = existing_private + [
            {"SubnetId": "<new>", "CidrBlock": cidr, "AvailabilityZone": zone}
            for cidr, zone in allocations
        ]
    tags = {"course": "yuntech-115-1", "week": "w05", "group": settings["group"], "owner": settings["owner"]}
    settings["tags"] = tags
    password = password_from_local_file()
    database_identifier = resources.get("db_instance_identifier", "w05-" + settings["resource_suffix"] + "-pg")
    if not password:
        try:
            run_aws(["rds", "describe-db-instances", "--db-instance-identifier", database_identifier], ctx["region"])
        except LabError as exc:
            if "DBInstanceNotFound" not in str(exc):
                raise
        else:
            raise LabError("Tracked RDS already exists but .local/db.env has no password; refusing to replace local credentials.")
    print("將要建立或補建：")
    for item in planned_subnets:
        print(f"- private subnet {item['CidrBlock']} in {item['AvailabilityZone']} (ID {item['SubnetId']})")
    print("- 1 isolated route table with only the VPC local route; explicitly associated to both private subnets")
    print("- 1 RDS DB subnet group spanning the two private subnets")
    print(f"- 1 DB security group: TCP 5432 only from host SG {host_sg_id}")
    print(f"- RDS PostgreSQL {database_identifier}: db.t3.micro, 20 GiB gp3, encrypted, single-AZ, non-public")
    print("- password stored only in .local/db.env (600); request sent through a 600-mode JSON file, never argv")
    print("費用依當期 RDS PostgreSQL、gp3 儲存與既有 EC2 官方計價；回收方式是依 resources.json 的精確 ID 停止 RDS/EC2，保留網路資源。")
    approve("", "CONFIRM")

    if not password:
        password = secrets.token_urlsafe(32)
        write_db_env({"DB_HOST": "", "DB_PORT": "5432", "DB_NAME": DB_NAME,
                      "DB_USER": DB_USER, "DB_PASSWORD": password})
    document["db_tags"] = tags
    save_json(RESOURCES, document)
    private_subnets = ensure_private_subnets(document, settings, ctx["region"], vpcs[0])
    route_table_id = ensure_isolated_route_table(document, settings, ctx["region"], vpc_id, private_subnets)
    subnet_ids = [item["SubnetId"] for item in private_subnets]
    subnet_group = ensure_db_subnet_group(document, settings, ctx["region"], subnet_ids)
    db_sg_id = ensure_db_security_group(document, settings, ctx["region"], vpc_id, host_sg_id)
    instance = ensure_rds_instance(document, settings, ctx["region"], subnet_group, db_sg_id, password)
    print(json.dumps({"DBInstanceIdentifier": instance["DBInstanceIdentifier"],
                      "DBInstanceStatus": instance["DBInstanceStatus"],
                      "PubliclyAccessible": instance["PubliclyAccessible"],
                      "DBInstanceClass": instance["DBInstanceClass"],
                      "AllocatedStorage": instance["AllocatedStorage"],
                      "StorageType": instance["StorageType"],
                      "StorageEncrypted": instance["StorageEncrypted"],
                      "MultiAZ": instance["MultiAZ"],
                      "DBSubnetGroupName": instance["DBSubnetGroup"]["DBSubnetGroupName"],
                      "route_table_id": route_table_id}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (LabError, OSError, ValueError, KeyError) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, LabError) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(1)
