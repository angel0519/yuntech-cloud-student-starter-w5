#!/usr/bin/env python3
"""Inspection service with in-memory W4 events and role-based bearer auth."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
from pathlib import Path
import re
import threading
from urllib.parse import urlsplit

EVENT_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
DEVICE_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
EVENT_TYPES = {"status", "anomaly", "test"}
EVENT_FIELDS = {"event_id", "device_id", "observed_at", "type", "note"}
MAX_BODY = 4096

PAGE = """<!doctype html>
<html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>巡檢事件</title>
<main><h1>巡檢事件</h1><label>Operator 權杖 <input id="token" type="password" autocomplete="off"></label>
<button id="load" type="button">載入事件</button><p id="message" role="status"></p><ul id="events"></ul></main>
<script>
const tokenInput = document.querySelector('#token');
const message = document.querySelector('#message');
const list = document.querySelector('#events');
document.querySelector('#load').addEventListener('click', async () => {
  const token = tokenInput.value;
  tokenInput.value = '';
  list.replaceChildren();
  try {
    const response = await fetch('/events', {headers: {Authorization: `Bearer ${token}`}});
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


def make_server(version_file, port=8080, reporter_token=None, operator_token=None):
    version = Path(version_file).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise ValueError("version must contain the deployed 40-character Git commit SHA")
    reporter_token = os.environ.get("REPORTER_TOKEN", "") if reporter_token is None else reporter_token
    operator_token = os.environ.get("OPERATOR_TOKEN", "") if operator_token is None else operator_token
    started = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    events = []
    events_lock = threading.Lock()

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
                                   "auth_configured": bool(reporter_token and operator_token)})
                return
            if path == "/":
                self.respond(200, PAGE, "text/html; charset=utf-8")
                return
            if path == "/events":
                if not self.role("operator"):
                    return
                with events_lock:
                    latest = list(reversed(events[-50:]))
                self.respond(200, {"events": latest})
                return
            if path.startswith("/events/"):
                if not self.role("operator"):
                    return
                event_id = path[len("/events/"):]
                if not EVENT_ID.fullmatch(event_id):
                    self.error(404, "not_found", "event_id")
                    return
                with events_lock:
                    found = next((event for event in events if event["event_id"] == event_id), None)
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
            with events_lock:
                if any(item["event_id"] == event["event_id"] for item in events):
                    self.error(409, "duplicate", "event_id")
                    return
                stored = dict(event)
                stored["received_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                events.append(stored)
            self.respond(201, stored)

        def log_message(self, fmt, *args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    make_server(Path(__file__).with_name("version")).serve_forever()
