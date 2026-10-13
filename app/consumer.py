#!/usr/bin/env python3
"""MQTT consumer: drops devices outside the allowlist, then posts the rest to the local API."""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

import paho.mqtt.client as mqtt

API_URL = "http://127.0.0.1:8080/events"
REQUIRED = ("IOT_ENDPOINT", "IOT_TOPIC", "IOT_CLIENT_ID", "IOT_DEVICE_IDS",
            "IOT_CA", "IOT_CERT", "IOT_KEY", "REPORTER_TOKEN")


def load_config():
    config = {key: os.environ.get(key, "") for key in REQUIRED}
    missing = [key for key, value in config.items() if not value]
    if missing:
        sys.exit("missing settings: " + ", ".join(missing))
    config["allowed"] = {item.strip() for item in config["IOT_DEVICE_IDS"].split(",") if item.strip()}
    return config


def post_event(config, event):
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(event).encode("utf-8"),
        method="POST",
        headers={"Authorization": "Bearer " + config["REPORTER_TOKEN"], "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except OSError:
        return None


def classify(status):
    if status == 201:
        return "created"
    if status == 200:
        return "duplicate"
    if status is None or status >= 500:
        return "error"
    return "rejected"


def handle(config, payload):
    try:
        event = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        event = None
    if not isinstance(event, dict):
        print("event_id=- result=rejected", flush=True)
        return
    event_id = re.sub(r"[^A-Za-z0-9_-]", "?", str(event.get("event_id", "-")))[:64]
    device = event.get("device_id")
    if isinstance(device, str) and device in config["allowed"]:
        result = classify(post_event(config, event))
    else:
        result = "rejected"
    print(f"event_id={event_id} result={result}", flush=True)


def run(config):
    import ssl

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code.is_failure:
            print(f"connect_failed rc={reason_code.value}", flush=True)
            return
        client.subscribe(config["IOT_TOPIC"], qos=1)

    def on_subscribe(client, userdata, mid, reason_codes, properties):
        print(f"subscribed rc={reason_codes[0].value}", flush=True)

    def on_message(client, userdata, message):
        handle(config, message.payload)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=config["IOT_CLIENT_ID"], protocol=mqtt.MQTTv5)
    client.tls_set(ca_certs=config["IOT_CA"], certfile=config["IOT_CERT"], keyfile=config["IOT_KEY"],
                   cert_reqs=ssl.CERT_REQUIRED)
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.connect(config["IOT_ENDPOINT"], 8883, keepalive=30)
    client.loop_forever(retry_first_connection=True)


if __name__ == "__main__":
    try:
        run(load_config())
    except OSError as exc:
        print(f"consumer_stopped error={type(exc).__name__}", flush=True)
        time.sleep(1)
        raise SystemExit(1)
