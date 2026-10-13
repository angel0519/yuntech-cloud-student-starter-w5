"""Offline W5 persistence and idempotency contract tests."""
from datetime import datetime, timezone
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w05_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)
FIXTURE = json.loads((ROOT / "tests/fixtures/event-valid.json").read_text(encoding="utf-8"))
REPORTER = "offline-reporter-token"
OPERATOR = "offline-operator-token"
from deploy import w04_deploy  # noqa: E402
from deploy import w05_db  # noqa: E402


class SQLiteStore:
    """Use a real local SQL database to exercise the HTTP store contract offline."""
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                type TEXT NOT NULL,
                note TEXT,
                received_at TEXT NOT NULL
            )""")

    def connect(self):
        return sqlite3.connect(self.path)

    @staticmethod
    def event_from_row(row):
        return dict(zip(("event_id", "device_id", "observed_at", "type", "note", "received_at"), row))

    def create(self, event):
        with self.connect() as connection:
            cursor = connection.execute(
                """INSERT INTO events (event_id, device_id, observed_at, type, note, received_at)
                VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(event_id) DO NOTHING""",
                (event["event_id"], event["device_id"], event["observed_at"], event["type"],
                 event.get("note"), datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
            )
            row = connection.execute(
                "SELECT event_id, device_id, observed_at, type, note, received_at FROM events WHERE event_id = ?",
                (event["event_id"],),
            ).fetchone()
            existing = self.event_from_row(row)
            if cursor.rowcount == 1:
                return 201, existing
            return (200, existing) if service._same_event(existing, event) else (409, None)

    def latest(self, device_id=None):
        with self.connect() as connection:
            if device_id is None:
                rows = connection.execute(
                    "SELECT event_id, device_id, observed_at, type, note, received_at FROM events ORDER BY received_at DESC LIMIT ?",
                    (50,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT event_id, device_id, observed_at, type, note, received_at FROM events WHERE device_id = ? ORDER BY received_at DESC LIMIT ?",
                    (device_id, 50),
                ).fetchall()
        return [self.event_from_row(row) for row in rows]

    def get(self, event_id):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT event_id, device_id, observed_at, type, note, received_at FROM events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        return self.event_from_row(row) if row else None


class W05PersistenceContract(unittest.TestCase):
    def start_server(self, version_file, store):
        server = service.make_server(
            version_file, port=0, reporter_token=REPORTER, operator_token=OPERATOR, event_store=store
        )
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        return server, worker, f"http://127.0.0.1:{server.server_port}"

    @staticmethod
    def request(base, path, method="GET", body=None, token=None):
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read().decode())

    def test_idempotent_create_and_restart_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.sqlite3"
            version = Path(directory) / "version"
            version.write_text("c" * 40, encoding="ascii")
            server, worker, base = self.start_server(version, SQLiteStore(database))
            try:
                health_status, health = self.request(base, "/health")
                self.assertEqual(health_status, 200)
                self.assertTrue(health["db_configured"])
                created_status, created = self.request(base, "/events", "POST", FIXTURE, REPORTER)
                self.assertEqual(created_status, 201)
                repeated_status, repeated = self.request(base, "/events", "POST", FIXTURE, REPORTER)
                self.assertEqual(repeated_status, 200)
                self.assertEqual(repeated, created)
                changed_status, changed = self.request(
                    base, "/events", "POST", {**FIXTURE, "note": "內容不同"}, REPORTER
                )
                self.assertEqual(changed_status, 409)
                self.assertEqual(changed["field"], "event_id")
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=2)

            restarted, restarted_worker, restarted_base = self.start_server(version, SQLiteStore(database))
            try:
                list_status, result = self.request(restarted_base, "/events", token=OPERATOR)
                self.assertEqual(list_status, 200)
                self.assertEqual(len(result["events"]), 1)
                self.assertEqual(result["events"][0], created)
            finally:
                restarted.shutdown()
                restarted.server_close()
                restarted_worker.join(timeout=2)

    def test_health_stays_available_without_database_configuration(self):
        version = ROOT / "tests/.w05-version-test"
        version.write_text("d" * 40, encoding="ascii")
        with patch.dict(os.environ, {"DB_HOST": "", "DB_NAME": "", "DB_USER": "", "DB_PASSWORD": ""}):
            server = service.make_server(version, port=0, reporter_token=REPORTER, operator_token=OPERATOR)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            status, health = self.request(f"http://127.0.0.1:{server.server_port}", "/health")
            self.assertEqual(status, 200)
            self.assertFalse(health["db_configured"])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
            version.unlink(missing_ok=True)

    def test_deployment_secret_payload_combines_w4_and_w5_files(self):
        with tempfile.TemporaryDirectory() as directory:
            app_env = Path(directory) / "app.env"
            db_env = Path(directory) / "db.env"
            app_contents = b"REPORTER_TOKEN=offline-report\nOPERATOR_TOKEN=offline-operator\n"
            db_contents = b"DB_HOST=db.invalid\nDB_PORT=5432\nDB_NAME=inspection\nDB_USER=inspection_admin\nDB_PASSWORD=offline-password\n"
            app_env.write_bytes(app_contents)
            db_env.write_bytes(db_contents)
            app_env.chmod(0o600)
            db_env.chmod(0o600)
            previous_app, previous_db = w04_deploy.APP_ENV, w04_deploy.DB_ENV
            try:
                w04_deploy.APP_ENV, w04_deploy.DB_ENV = app_env, db_env
                payload = w04_deploy.read_secret_file()
                self.assertEqual(payload, app_contents.rstrip() + b"\n" + db_contents)
            finally:
                w04_deploy.APP_ENV, w04_deploy.DB_ENV = previous_app, previous_db

    def test_private_subnet_plan_avoids_existing_cidrs_and_uses_distinct_zones(self):
        vpc = {"CidrBlock": "10.20.0.0/16", "CidrBlockAssociationSet": []}
        existing = [
            {"SubnetId": "subnet-a", "CidrBlock": "10.20.0.0/24", "AvailabilityZone": "us-east-1a"},
            {"SubnetId": "subnet-b", "CidrBlock": "10.20.1.0/24", "AvailabilityZone": "us-east-1b"},
        ]
        plan = w05_db.choose_private_subnets(
            vpc, existing, ["us-east-1a", "us-east-1b", "us-east-1c"], []
        )
        self.assertEqual(len(plan), 2)
        self.assertNotEqual(plan[0][1], plan[1][1])
        for cidr, _zone in plan:
            network = ipaddress.ip_network(cidr)
            self.assertFalse(any(network.overlaps(ipaddress.ip_network(item["CidrBlock"])) for item in existing))
        self.assertFalse(ipaddress.ip_network(plan[0][0]).overlaps(ipaddress.ip_network(plan[1][0])))


if __name__ == "__main__":
    unittest.main()
