"""Offline tests for the W4 event API contract."""
import importlib.util
import json
from pathlib import Path
import subprocess
import threading
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w04_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)
FIXTURES = ROOT / "tests/fixtures"
REPORTER = "offline-reporter-test-token"
OPERATOR = "offline-operator-test-token"


class EventApiContract(unittest.TestCase):
    def setUp(self):
        self.version_file = ROOT / "tests/.w04-version-test"
        self.version_file.write_text("b" * 40, encoding="ascii")
        self.server = service.make_server(
            self.version_file, port=0, reporter_token=REPORTER, operator_token=OPERATOR
        )
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.version_file.unlink(missing_ok=True)

    def request(self, path, method="GET", body=None, token=None):
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=3) as result:
                return result.status, json.loads(result.read().decode())
        except urllib.error.HTTPError as error:
            with error:
                return error.status, json.loads(error.read().decode())

    def fixture(self, name):
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    def test_health_and_seven_row_rejection_matrix(self):
        status, health = self.request("/health")
        self.assertEqual(status, 200)
        self.assertEqual(health["version"], "b" * 40)
        self.assertTrue(health["auth_configured"])

        valid = self.fixture("event-valid.json")
        timezone_error = self.fixture("event-invalid-timezone.json")
        extra_error = self.fixture("event-invalid-extra-field.json")
        self.assertEqual(self.request("/events", "POST", valid, REPORTER)[0], 201)
        self.assertEqual(self.request("/events", "POST", valid)[0], 401)
        self.assertEqual(self.request("/events", "POST", valid, OPERATOR)[0], 403)
        bad_status, bad_body = self.request("/events", "POST", timezone_error, REPORTER)
        self.assertEqual(bad_status, 400)
        self.assertEqual(bad_body["field"], "observed_at")
        self.assertEqual(self.request("/events", "POST", valid, REPORTER)[0], 200)
        self.assertEqual(self.request("/events", token=REPORTER)[0], 403)
        list_status, result = self.request("/events", token=OPERATOR)
        self.assertEqual(list_status, 200)
        self.assertEqual(result["events"][0]["event_id"], valid["event_id"])

        extra_status, extra_body = self.request("/events", "POST", extra_error, REPORTER)
        self.assertEqual(extra_status, 400)
        self.assertEqual(extra_body["field"], "unexpected")
        detail_status, detail = self.request("/events/" + valid["event_id"], token=OPERATOR)
        self.assertEqual(detail_status, 200)
        self.assertEqual(detail["event_id"], valid["event_id"])

    def test_display_uses_text_content_and_no_browser_storage(self):
        with urllib.request.urlopen(self.base + "/", timeout=3) as response:
            self.assertEqual(response.status, 200)
            markup = response.read().decode()
        self.assertIn("textContent", markup)
        self.assertIn("event.received_at", markup)
        self.assertNotIn("innerHTML", markup)
        self.assertNotIn("localStorage", markup)

    def test_auth_precedes_body_validation_and_size_is_limited(self):
        request = urllib.request.Request(
            self.base + "/events", data=b"not-json", headers={"Content-Type": "text/plain"}, method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(caught.exception.code, 401)

        request = urllib.request.Request(
            self.base + "/events", data=b" " * 4097,
            headers={"Authorization": "Bearer " + REPORTER, "Content-Type": "application/json"}, method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(caught.exception.code, 400)

    def test_content_type_validation_and_invalid_field_types(self):
        valid = self.fixture("event-valid.json")
        request = urllib.request.Request(
            self.base + "/events", data=json.dumps(valid).encode(),
            headers={"Authorization": "Bearer " + REPORTER, "Content-Type": "text/plain"}, method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(caught.exception.code, 400)

        malformed_type = dict(valid, event_id="group-demo-07-4-bad-type", type=[])
        status, body = self.request("/events", "POST", malformed_type, REPORTER)
        self.assertEqual(status, 400)
        self.assertEqual(body["field"], "type")

    def test_matrix_data_is_pinned_to_a_real_committed_fixture(self):
        valid = self.fixture("event-valid.json")
        self.assertRegex(valid["event_id"], r"^[A-Za-z0-9_-]{1,64}$")
        self.assertEqual(subprocess.check_output(
            ["git", "rev-parse", "--is-inside-work-tree"], cwd=ROOT, text=True
        ).strip(), "true")


if __name__ == "__main__":
    unittest.main()
