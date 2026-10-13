#!/usr/bin/env python3
"""Simulated gateway: publishes 32 events (10 devices x 3, one resend, one unlisted device)."""
import argparse
import json
import re
import ssl
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parents[1]
IOT = ROOT / ".local" / "iot"
LAST_RUN = ROOT / ".local" / "w06-last-run.json"
SAFE = re.compile(r"[A-Za-z0-9-]{1,40}")


def build_events(code, run):
    prefix = f"{code}-{run}"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    events = []
    for number in range(1, 11):
        for seq in range(1, 4):
            events.append({"event_id": f"{prefix}-d{number:02d}-{seq:02d}", "device_id": f"{code}-d{number:02d}",
                           "observed_at": now, "type": "status"})
    events.append(dict(events[0]))
    events.append({"event_id": f"{prefix}-d99-01", "device_id": f"{code}-d99", "observed_at": now, "type": "status"})
    return prefix, events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    if not SAFE.fullmatch(args.code) or not SAFE.fullmatch(args.run):
        sys.exit("STOP: code and run must match [A-Za-z0-9-]{1,40}")
    if (IOT / "code").read_text(encoding="utf-8").strip() != args.code:
        sys.exit("STOP: --code does not match .local/iot/code")

    prefix, events = build_events(args.code, args.run)
    acks = {}
    cond = threading.Condition()
    connected = threading.Event()

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code.is_failure:
            print(f"connack={reason_code.value}", flush=True)
            sys.exit(1)
        connected.set()

    def on_publish(client, userdata, mid, reason_code, properties):
        with cond:
            acks[mid] = reason_code.value
            cond.notify_all()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"gw-{args.code}", protocol=mqtt.MQTTv5)
    client.tls_set(ca_certs=str(IOT / "AmazonRootCA1.pem"), certfile=str(IOT / "gw.cert.pem"),
                   keyfile=str(IOT / "gw.private.key"), cert_reqs=ssl.CERT_REQUIRED)
    client.on_connect = on_connect
    client.on_publish = on_publish
    endpoint = (IOT / "endpoint").read_text(encoding="utf-8").strip()
    topic = f"cxe/{args.code}/gw/events"
    client.connect(endpoint, 8883, keepalive=30)
    client.loop_start()
    try:
        if not connected.wait(20):
            sys.exit("STOP: not connected within 20 seconds")
        ok = 0
        for event in events:
            info = client.publish(topic, json.dumps(event).encode("utf-8"), qos=1)
            with cond:
                cond.wait_for(lambda: info.mid in acks, timeout=10)
                ok += acks.get(info.mid) == 0
    finally:
        client.disconnect()
        client.loop_stop()

    LAST_RUN.write_text(json.dumps({"code": args.code, "run": args.run, "prefix": prefix,
                                    "published": len(events), "puback_ok": ok}, indent=2) + "\n", encoding="utf-8")
    LAST_RUN.chmod(0o600)
    print(f"prefix={prefix} puback_ok={ok}/{len(events)}")


if __name__ == "__main__":
    main()
