#!/usr/bin/env python3
"""Inspection service with in-memory W4 events and role-based bearer auth."""
from datetime import datetime, timezone
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
from pathlib import Path
import re
import threading
from urllib.parse import parse_qs, urlsplit

EVENT_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
DEVICE_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
EVENT_TYPES = {"status", "anomaly", "test"}
EVENT_FIELDS = {"event_id", "device_id", "observed_at", "type", "note"}
MAX_BODY = 4096
EVENT_COLUMNS = "event_id, device_id, observed_at, type, note, received_at"

PAGE = """<!doctype html>
<html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>巡檢事件</title>
<main><h1>巡檢事件</h1><label>Operator 權杖 <input id="token" type="password" autocomplete="off"></label>
<label>設備編號 <input id="device" autocomplete="off"></label>
<button id="load" type="button">載入事件</button><p id="message" role="status"></p><ul id="events"></ul></main>
<script>
const tokenInput = document.querySelector('#token');
const deviceInput = document.querySelector('#device');
const message = document.querySelector('#message');
const list = document.querySelector('#events');
document.querySelector('#load').addEventListener('click', async () => {
  const token = tokenInput.value;
  tokenInput.value = '';
  list.replaceChildren();
  try {
    const device = deviceInput.value.trim();
    const url = device ? `/events?device_id=${encodeURIComponent(device)}` : '/events';
    const response = await fetch(url, {headers: {Authorization: `Bearer ${token}`}});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'request_failed');
    message.textContent = `共 ${result.events.length} 筆`;
    for (const event of result.events) {
      const item = document.createElement('li');
            item.textContent = `${event.event_id} | ${event.device_id} | ${event.observed_at} | ${event.received_at} | ${event.type} | ${event.note || ''}`;
      list.append(item);
    }
  } catch (error) {
    message.textContent = '讀取失敗';
  }
});
</script></html>"""


def _parse_timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _same_event(existing, incoming):
    fields_match = all(existing.get(field) == incoming.get(field) for field in EVENT_FIELDS if field != "observed_at")
    try:
        times_match = _parse_timestamp(existing["observed_at"]) == _parse_timestamp(incoming["observed_at"])
    except (KeyError, TypeError, ValueError):
        times_match = existing.get("observed_at") == incoming.get("observed_at")
    return fields_match and times_match


def _utc_text(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class MemoryStore:
    def __init__(self):
        self.events = []
        self.lock = threading.Lock()

    def create(self, event):
        with self.lock:
            existing = next((item for item in self.events if item["event_id"] == event["event_id"]), None)
            if existing is not None:
                return (200, dict(existing)) if _same_event(existing, event) else (409, None)
            stored = dict(event)
            stored["received_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            self.events.append(stored)
            return 201, dict(stored)

    def latest(self, device_id=None):
        with self.lock:
            items = [item for item in self.events if device_id in (None, item["device_id"])]
            return [dict(item) for item in reversed(items[-50:])]

    def get(self, event_id):
        with self.lock:
            item = next((item for item in self.events if item["event_id"] == event_id), None)
            return dict(item) if item is not None else None


class PostgresStore:
    def __init__(self, config):
        self.config = config

    def connect(self):
        import psycopg2

        return psycopg2.connect(
            host=self.config["DB_HOST"],
            port=int(self.config.get("DB_PORT", "5432")),
            dbname=self.config["DB_NAME"],
            user=self.config["DB_USER"],
            password=self.config["DB_PASSWORD"],
            sslmode="verify-full",
            sslrootcert="/etc/inspection/rds-ca.pem",
            connect_timeout=5,
        )

    @contextmanager
    def db_session(self):
        connection = self.connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def ensure_table(self, cursor):
        cursor.execute("""CREATE TABLE IF NOT EXISTS events (
            event_id VARCHAR(64) PRIMARY KEY,
            device_id VARCHAR(32) NOT NULL,
            observed_at TIMESTAMPTZ NOT NULL,
            type VARCHAR(16) NOT NULL,
            note TEXT,
            received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")

    @staticmethod
    def event_from_row(row):
        event_id, device_id, observed_at, event_type, note, received_at = row
        return {
            "event_id": event_id,
            "device_id": device_id,
            "observed_at": _utc_text(observed_at),
            "type": event_type,
            "note": note,
            "received_at": _utc_text(received_at),
        }

    def create(self, event):
        with self.db_session() as connection:
            with connection.cursor() as cursor:
                self.ensure_table(cursor)
                cursor.execute(
                    """INSERT INTO events (event_id, device_id, observed_at, type, note)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    RETURNING """ + EVENT_COLUMNS,
                    (event["event_id"], event["device_id"], event["observed_at"], event["type"], event.get("note")),
                )
                row = cursor.fetchone()
                if row is not None:
                    return 201, self.event_from_row(row)
                cursor.execute("SELECT " + EVENT_COLUMNS + " FROM events WHERE event_id = %s", (event["event_id"],))
                existing = self.event_from_row(cursor.fetchone())
                return (200, existing) if _same_event(existing, event) else (409, None)

    def latest(self, device_id=None):
        with self.db_session() as connection:
            with connection.cursor() as cursor:
                self.ensure_table(cursor)
                if device_id is None:
                    cursor.execute("SELECT " + EVENT_COLUMNS + " FROM events ORDER BY received_at DESC LIMIT %s", (50,))
                else:
                    cursor.execute("SELECT " + EVENT_COLUMNS + " FROM events WHERE device_id = %s ORDER BY received_at DESC LIMIT %s", (device_id, 50))
                return [self.event_from_row(row) for row in cursor.fetchall()]

    def get(self, event_id):
        with self.db_session() as connection:
            with connection.cursor() as cursor:
                self.ensure_table(cursor)
                cursor.execute("SELECT " + EVENT_COLUMNS + " FROM events WHERE event_id = %s", (event_id,))
                row = cursor.fetchone()
                return self.event_from_row(row) if row is not None else None


def _db_config_from_env():
    keys = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
    values = {key: os.environ.get(key, "") for key in keys}
    return values if all(values.values()) else None


def make_server(version_file, port=8080, reporter_token=None, operator_token=None, db_config=None, event_store=None):
    version = Path(version_file).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise ValueError("version must contain the deployed 40-character Git commit SHA")
    reporter_token = os.environ.get("REPORTER_TOKEN", "") if reporter_token is None else reporter_token
    operator_token = os.environ.get("OPERATOR_TOKEN", "") if operator_token is None else operator_token
    db_config = _db_config_from_env() if db_config is None else db_config
    store = event_store or (PostgresStore(db_config) if db_config else MemoryStore())
    db_configured = db_config is not None or event_store is not None
    started = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def respond(self, status, value, content_type="application/json; charset=utf-8"):
            data = value.encode("utf-8") if isinstance(value, str) else json.dumps(value).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def error(self, status, reason, field):
            self.respond(status, {"error": reason, "field": field})

        def role(self, required):
            header = self.headers.get("Authorization", "")
            scheme, separator, supplied = header.partition(" ")
            if scheme.lower() != "bearer" or not separator or not supplied:
                self.error(401, "unauthorized", "authorization")
                return False
            if reporter_token and hmac.compare_digest(supplied, reporter_token):
                actual = "reporter"
            elif operator_token and hmac.compare_digest(supplied, operator_token):
                actual = "operator"
            else:
                self.error(401, "unauthorized", "authorization")
                return False
            if actual != required:
                self.error(403, "forbidden", "authorization")
                return False
            return True

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/health":
                self.respond(200, {"status": "ok", "service": "inspection", "version": version,
                                   "started_at": started,
                                   "auth_configured": bool(reporter_token and operator_token),
                                   "db_configured": db_configured})
                return
            if path == "/":
                self.respond(200, PAGE, "text/html; charset=utf-8")
                return
            if path == "/events":
                if not self.role("operator"):
                    return
                device_id = parse_qs(urlsplit(self.path).query, keep_blank_values=True).get("device_id", [None])[0]
                if device_id is not None and not DEVICE_ID.fullmatch(device_id):
                    self.error(400, "invalid_value", "device_id")
                    return
                try:
                    self.respond(200, {"events": store.latest(device_id)})
                except Exception:
                    self.error(503, "database_unavailable", "database")
                return
            if path.startswith("/events/"):
                if not self.role("operator"):
                    return
                event_id = path[len("/events/"):]
                if not EVENT_ID.fullmatch(event_id):
                    self.error(404, "not_found", "event_id")
                    return
                try:
                    found = store.get(event_id)
                except Exception:
                    self.error(503, "database_unavailable", "database")
                    return
                if found is None:
                    self.error(404, "not_found", "event_id")
                else:
                    self.respond(200, found)
                return
            self.error(404, "not_found", "path")

        def do_POST(self):
            if urlsplit(self.path).path != "/events":
                self.error(404, "not_found", "path")
                return
            if not self.role("reporter"):
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                self.error(400, "invalid_content_type", "Content-Type")
                return
            try:
                size = int(self.headers.get("Content-Length", ""))
            except ValueError:
                size = -1
            if size < 0:
                self.error(400, "invalid_content_length", "body")
                return
            if size > MAX_BODY:
                self.error(400, "body_too_large", "body")
                return
            try:
                event = json.loads(self.rfile.read(size).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.error(400, "invalid_json", "body")
                return
            if not isinstance(event, dict):
                self.error(400, "invalid_event", "body")
                return
            unexpected = next((field for field in event if field not in EVENT_FIELDS), None)
            if unexpected is not None:
                self.error(400, "unexpected_field", unexpected)
                return
            for field in ("event_id", "device_id", "observed_at", "type"):
                if field not in event:
                    self.error(400, "required", field)
                    return
            if not isinstance(event["event_id"], str) or not EVENT_ID.fullmatch(event["event_id"]):
                self.error(400, "invalid_value", "event_id")
                return
            if not isinstance(event["device_id"], str) or not DEVICE_ID.fullmatch(event["device_id"]):
                self.error(400, "invalid_value", "device_id")
                return
            observed = event["observed_at"]
            if not isinstance(observed, str):
                self.error(400, "invalid_datetime", "observed_at")
                return
            try:
                parsed = datetime.fromisoformat(observed.replace("Z", "+00:00"))
            except ValueError:
                parsed = None
            if parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None:
                self.error(400, "timezone_required", "observed_at")
                return
            if not isinstance(event["type"], str) or event["type"] not in EVENT_TYPES:
                self.error(400, "invalid_value", "type")
                return
            if "note" in event and (not isinstance(event["note"], str) or len(event["note"]) > 200):
                self.error(400, "invalid_value", "note")
                return
            try:
                status, stored = store.create(event)
            except Exception:
                self.error(503, "database_unavailable", "database")
                return
            if status == 409:
                self.error(409, "duplicate", "event_id")
                return
            self.respond(status, stored)

        def log_message(self, fmt, *args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    make_server(Path(__file__).with_name("version")).serve_forever()
