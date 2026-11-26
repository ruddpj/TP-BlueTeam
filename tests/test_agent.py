import asyncio
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi import BackgroundTasks, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agent import main


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


class AgentTests(unittest.TestCase):
    def test_kibana_trigger_shape_is_accepted_and_extras_are_rejected(self):
        payload = {
            "source": "kibana",
            "rule_id": "rule-1",
            "rule_name": "High risk",
            "triggered_at": "2026-11-26T10:00:00Z",
        }
        trigger = main.AlertTrigger.model_validate(payload)
        self.assertEqual("rule-1", trigger.rule_id)

        with self.assertRaises(ValidationError):
            main.AlertTrigger.model_validate({**payload, "unexpected": True})

    def test_handler_returns_accepted_and_defers_graph(self):
        trigger = main.AlertTrigger(
            rule_id="rule-1",
            rule_name="High risk",
            triggered_at=datetime(2026, 11, 26, 10, tzinfo=timezone.utc),
        )
        tasks = BackgroundTasks()

        with (
            patch.dict("os.environ", {"AGENT_WEBHOOK_TOKEN": "test-token"}),
            patch.object(main.agent_graph, "invoke", return_value={"events": {"values": []}}) as invoke,
        ):
            response = main.handle_kibana_alert(
                trigger, tasks, "Bearer test-token"
            )

            self.assertEqual("accepted", response["status"])
            self.assertEqual("rule-1", response["rule_id"])
            invoke.assert_not_called()
            self.assertEqual(1, len(tasks.tasks))

            asyncio.run(tasks())
            invoke.assert_called_once()

    def test_http_endpoint_returns_202(self):
        payload = {
            "source": "kibana",
            "rule_id": "rule-1",
            "rule_name": "High risk",
            "triggered_at": "2026-11-26T10:00:00Z",
        }
        with (
            patch.dict("os.environ", {"AGENT_WEBHOOK_TOKEN": "test-token"}),
            patch.object(
                main.agent_graph, "invoke", return_value={"events": {"values": []}}
            ),
        ):
            response = TestClient(main.app).post(
                "/webhook/kibana",
                json=payload,
                headers={"Authorization": "Bearer test-token"},
            )

        self.assertEqual(202, response.status_code)
        self.assertEqual("accepted", response.json()["status"])

    def test_handler_rejects_bad_token(self):
        trigger = main.AlertTrigger(rule_id="rule-1", rule_name="High risk")
        with patch.dict("os.environ", {"AGENT_WEBHOOK_TOKEN": "expected"}):
            with self.assertRaises(HTTPException) as error:
                main.handle_kibana_alert(trigger, BackgroundTasks(), "Bearer wrong")

        self.assertEqual(401, error.exception.status_code)

    def test_query_is_bounded_by_trigger_time_and_target_data_stream(self):
        trigger_time = datetime(2026, 11, 26, 10, tzinfo=timezone.utc)
        captured = {}

        def fake_urlopen(request, timeout):
            captured["query"] = json.loads(request.data)["query"]
            return FakeResponse({"columns": [], "values": []})

        state = {
            "trigger": {"triggered_at": trigger_time.isoformat()},
            "events": {},
        }
        with patch.dict("os.environ", {"ALERT_LOOKBACK_MINUTES": "60"}):
            with patch.object(main, "urlopen", fake_urlopen):
                result = main.query_high_risk_events(state)

        self.assertEqual([], result["events"]["values"])
        self.assertIn("FROM logs-app-*", captured["query"])
        self.assertIn(
            'TO_DATETIME("2026-11-26T09:00:00+00:00")', captured["query"]
        )
        self.assertIn(
            'TO_DATETIME("2026-11-26T10:02:00+00:00")', captured["query"]
        )


if __name__ == "__main__":
    unittest.main()
