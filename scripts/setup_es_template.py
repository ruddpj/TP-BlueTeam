import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ELASTICSEARCH_URL = os.getenv(
    "ELASTICSEARCH_URL", "http://elasticsearch:9200"
).rstrip("/")
TEMPLATE_NAME = "tp-blue-team-logs-app"

RISK_FIELD_MAPPINGS = {
    "@timestamp": {"type": "date"},
    "event": {
        "properties": {
            "risk_score": {"type": "long"},
        }
    },
    "soc": {
        "properties": {
            "risk": {
                "properties": {
                    "status": {
                        "type": "text",
                        "fields": {
                            "keyword": {"type": "keyword", "ignore_above": 256}
                        },
                    },
                    "reasons": {
                        "type": "text",
                        "fields": {
                            "keyword": {"type": "keyword", "ignore_above": 256}
                        },
                    },
                }
            }
        }
    },
    "source": {"properties": {"ip": {"type": "ip"}}},
    "destination": {"properties": {"ip": {"type": "ip"}}},
}

INDEX_TEMPLATE = {
    "index_patterns": ["logs-app-*"],
    "priority": 500,
    "data_stream": {},
    "template": {"mappings": {"properties": RISK_FIELD_MAPPINGS}},
}


def api_request(path, method="GET", body=None):
    request = Request(
        f"{ELASTICSEARCH_URL}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urlopen(request, timeout=10) as response:
        payload = response.read()
        return json.loads(payload) if payload else {}


def wait_for_elasticsearch():
    for attempt in range(60):
        try:
            api_request("/")
            return
        except HTTPError as error:
            if error.code in (401, 403) or attempt == 59:
                raise
            time.sleep(5)
        except (URLError, TimeoutError):
            if attempt == 59:
                raise
            time.sleep(5)


def install_template():
    api_request(
        f"/_index_template/{TEMPLATE_NAME}",
        method="PUT",
        body=INDEX_TEMPLATE,
    )
    try:
        api_request(
            "/logs-app-*/_mapping",
            method="PUT",
            body={"properties": RISK_FIELD_MAPPINGS},
        )
    except HTTPError as error:
        if error.code != 404:
            raise


def main():
    wait_for_elasticsearch()
    install_template()
    print(f"Installed risk field mappings for logs-app-*")


if __name__ == "__main__":
    main()
