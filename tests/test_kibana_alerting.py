import json
import unittest
from unittest.mock import patch
from uuid import UUID

from kibana import setup_alerting


class AlertSetupTests(unittest.TestCase):
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
                "triggered_at": "{{context.date}}",
            },
            json.loads(rule["actions"][0]["params"]["body"]),
        )


if __name__ == "__main__":
    unittest.main()
