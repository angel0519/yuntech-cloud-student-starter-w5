#!/usr/bin/env python3
"""Connection check for one W6 identity: publish once, or subscribe and print reason codes."""
import argparse
import json
import re
import ssl
import sys
import threading
import time
from pathlib import Path

import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parents[1]
IOT = ROOT / ".local" / "iot"


def load_identity(name):
    code = (IOT / "code").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", code):
        sys.exit("STOP: .local/iot/code is invalid")
    if name == "gw":
        return f"gw-{code}", code, "gw.cert.pem", "gw.private.key"
    return f"consumer-{code}", code, "consumer.cert.pem", "consumer.private.key"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--as", dest="identity", required=True, choices=["gw", "consumer"])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pub", metavar="TOPIC")
    mode.add_argument("--sub", metavar="FILTER")
    parser.add_argument("--wait", type=int, default=10, help="seconds to keep receiving after SUBACK")
    args = parser.parse_args()

    client_id, code, cert, key = load_identity(args.identity)
    endpoint = (IOT / "endpoint").read_text(encoding="utf-8").strip()
    finished = threading.Event()
    state = {"suback_ok": False}

    def on_connect(client, userdata, flags, reason_code, properties):
        print(f"connack={reason_code.value}", flush=True)
        if reason_code.is_failure:
            finished.set()
            return
        if args.sub:
            client.subscribe(args.sub, qos=1)
        else:
            body = json.dumps({"check": "t2", "code": code}).encode("utf-8")
            state["mid"] = client.publish(args.pub, body, qos=1).mid

    def on_publish(client, userdata, mid, reason_code, properties):
        if mid == state.get("mid"):
            print(f"puback={reason_code.value}", flush=True)
            finished.set()

    def on_subscribe(client, userdata, mid, reason_codes, properties):
        print(f"suback={reason_codes[0].value}", flush=True)
        state["suback_ok"] = reason_codes[0].value < 128
        finished.set()

    def on_message(client, userdata, message):
        print(f"recv topic={message.topic} payload={message.payload.decode('utf-8', 'replace')}", flush=True)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, protocol=mqtt.MQTTv5)
    client.tls_set(ca_certs=str(IOT / "AmazonRootCA1.pem"), certfile=str(IOT / cert),
                   keyfile=str(IOT / key), cert_reqs=ssl.CERT_REQUIRED)
    client.on_connect = on_connect
    client.on_publish = on_publish
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    try:
        client.connect(endpoint, 8883, keepalive=30)
    except OSError as exc:
        sys.exit(f"STOP: connect failed ({type(exc).__name__})")
    client.loop_start()
    try:
        finished.wait(20)
        if args.sub and state["suback_ok"]:
            time.sleep(args.wait)
    finally:
        client.disconnect()
        client.loop_stop()


if __name__ == "__main__":
    main()
