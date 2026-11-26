import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from uuid import UUID

from kibana import setup_alerting


class AlertSetupTests(unittest.TestCase):
    def test_auth_is_omitted_when_kibana_security_is_disabled(self):
        requests = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b"{}"

        def fake_urlopen(request, timeout):
            requests.append(request)
            return FakeResponse()

        with patch.dict(
            "os.environ",
            {
                "KIBANA_API_KEY": "",
                "KIBANA_USERNAME": "",
                "KIBANA_PASSWORD": "",
            },
        ):
            with patch.object(setup_alerting, "BASE_URL", "http://kibana.example"):
                with patch.object(setup_alerting, "urlopen", fake_urlopen):
                    setup_alerting.api_request("/api/status")

        self.assertIsNone(requests[0].get_header("Authorization"))

    def test_http_errors_include_kibana_response_body(self):
        error = HTTPError(
            "https://kibana.example/api/alerting/rule",
            400,
            "Bad Request",
            {},
            io.BytesIO(b'{"message":"unknown field: enabled"}'),
        )
        with patch.object(setup_alerting, "BASE_URL", "http://kibana.example"):
            with patch.object(setup_alerting, "urlopen", side_effect=error):
                with self.assertRaises(HTTPError) as raised:
                    setup_alerting.api_request("/api/alerting/rule")

        self.assertEqual(400, raised.exception.code)
        self.assertIn("unknown field: enabled", str(raised.exception))

    def test_partial_kibana_credentials_are_rejected(self):
        with patch.dict(
            "os.environ",
            {"KIBANA_API_KEY": "", "KIBANA_USERNAME": "user", "KIBANA_PASSWORD": ""},
        ):
            with self.assertRaisesRegex(RuntimeError, "Both KIBANA_USERNAME"):
                setup_alerting.kibana_authorization()

    def test_alert_payload_matches_agent_schema_and_uses_trigger_time(self):
        requests = []

        def fake_api_request(path, method="GET", body=None):
            requests.append((path, method, body))
            if path.startswith("/api/alerting/rules/_find?"):
                return {"data": []}
            return {}

        with patch.object(setup_alerting, "api_request", fake_api_request):
            setup_alerting.ensure_rule("connector-id")

        create = next(
            request
            for request in requests
            if request[1] == "POST" and request[0].startswith("/api/alerting/rule/")
        )
        UUID(create[0].rsplit("/", 1)[1])
        rule = create[2]
        self.assertEqual(["logs-app-*"], rule["params"]["index"])
        self.assertEqual(60, rule["params"]["timeWindowSize"])
        self.assertEqual(
            {
                "source": "kibana",
                "rule_id": "{{rule.id}}",
                "rule_name": "{{rule.name}}",
                "alert_id": "{{alert.id}}",
                "triggered_at": "{{context.date}}",
            },
            json.loads(rule["actions"][0]["params"]["body"]),
        )

    def test_rule_update_omits_immutable_fields(self):
        requests = []

        def fake_api_request(path, method="GET", body=None):
            requests.append((path, method, body))
            if path.startswith("/api/alerting/rules/_find?"):
                return {"data": [{"id": "existing-id", "name": setup_alerting.RULE_NAME}]}
            return {"id": "existing-id"}

        with patch.object(setup_alerting, "api_request", fake_api_request):
            setup_alerting.ensure_rule("connector-id")

        update = next(request for request in requests if request[1] == "PUT")
        self.assertEqual("/api/alerting/rule/existing-id", update[0])
        self.assertNotIn("rule_type_id", update[2])
        self.assertNotIn("consumer", update[2])
        self.assertNotIn("enabled", update[2])

if __name__ == "__main__":
    unittest.main()
