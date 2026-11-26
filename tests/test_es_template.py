import unittest
from unittest.mock import call, patch
from urllib.error import HTTPError

from scripts import setup_es_template


class IndexTemplateTests(unittest.TestCase):
    def test_installs_template_and_updates_current_data_stream_mappings(self):
        with patch.object(setup_es_template, "api_request") as request:
            setup_es_template.install_template()

        self.assertEqual(
            call(
                f"/_index_template/{setup_es_template.TEMPLATE_NAME}",
                method="PUT",
                body=setup_es_template.INDEX_TEMPLATE,
            ),
            request.call_args_list[0],
        )
        self.assertEqual(
            call(
                "/logs-app-*/_mapping",
                method="PUT",
                body={"properties": setup_es_template.RISK_FIELD_MAPPINGS},
            ),
            request.call_args_list[1],
        )
        self.assertEqual(
            "long",
            setup_es_template.RISK_FIELD_MAPPINGS["event"]["properties"][
                "risk_score"
            ]["type"],
        )
        status = setup_es_template.RISK_FIELD_MAPPINGS["soc"]["properties"][
            "risk"
        ]["properties"]["status"]
        self.assertEqual("keyword", status["fields"]["keyword"]["type"])

    def test_ignores_missing_existing_data_stream_only(self):
        missing_stream = HTTPError(
            "/logs-app-*/_mapping", 404, "not found", {}, None
        )
        with patch.object(
            setup_es_template, "api_request", side_effect=[{}, missing_stream]
        ):
            setup_es_template.install_template()

    def test_propagates_other_mapping_errors(self):
        error = HTTPError("/logs-app-*/_mapping", 400, "bad mapping", {}, None)
        with patch.object(setup_es_template, "api_request", side_effect=[{}, error]):
            with self.assertRaises(HTTPError):
                setup_es_template.install_template()


if __name__ == "__main__":
    unittest.main()
