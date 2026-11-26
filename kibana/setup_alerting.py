import base64
import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


BASE_URL = os.getenv("KIBANA_URL", "").rstrip("/")
CONNECTOR_NAME = "Threat analysis FastAPI webhook"
RULE_NAME = "High-risk events to LangGraph"
RULE_ID = "68a9139d-30d3-4f4e-9d18-a9be56c87c2a"
THRESHOLD = int(os.getenv("RISK_SCORE_THRESHOLD", "70"))
ALERT_LOOKBACK_MINUTES = int(os.getenv("ALERT_LOOKBACK_MINUTES", "60"))
AGENT_WEBHOOK_URL = os.getenv("AGENT_WEBHOOK_URL", "")
AGENT_WEBHOOK_TOKEN = os.getenv("AGENT_WEBHOOK_TOKEN", "")


def kibana_authorization() -> str | None:
    api_key = os.getenv("KIBANA_API_KEY")
    username = os.getenv("KIBANA_USERNAME")
    password = os.getenv("KIBANA_PASSWORD")
    if api_key:
        return f"ApiKey {api_key}"
    if username or password:
        if not username or not password:
            raise RuntimeError(
                "Both KIBANA_USERNAME and KIBANA_PASSWORD are required"
            )
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        return f"Basic {credentials}"
    return None


def api_request(path, method="GET", body=None):
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    authorization = kibana_authorization()
    if authorization:
        headers["Authorization"] = authorization
    request = Request(
        f"{BASE_URL}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=10) as response:
            payload = response.read()
            return json.loads(payload) if payload else {}
    except HTTPError as error:
        response_body = error.read().decode("utf-8", errors="replace").strip()
        reason = str(error.reason)
        if response_body:
            reason = f"{reason}; response body: {response_body}"
        raise HTTPError(
            error.geturl(), error.code, reason, error.headers, None
        ) from error


def wait_for_kibana():
    for attempt in range(60):
        try:
            api_request("/api/status")
            return
        except HTTPError as error:
            if error.code in (401, 403) or attempt == 59:
                raise
            time.sleep(5)
        except (URLError, TimeoutError):
            if attempt == 59:
                raise
            time.sleep(5)


def find_connector():
    connectors = api_request("/api/actions/connectors")
    return next(
        (connector for connector in connectors if connector["name"] == CONNECTOR_NAME),
        None,
    )


def find_rule():
    query = urlencode(
        {"per_page": 100, "search": RULE_NAME, "search_fields": "name"}
    )
    response = api_request(f"/api/alerting/rules/_find?{query}")
    return next(
        (rule for rule in response.get("data", []) if rule["name"] == RULE_NAME),
        None,
    )


def ensure_connector():
    if not AGENT_WEBHOOK_URL or not AGENT_WEBHOOK_TOKEN:
        raise RuntimeError("AGENT_WEBHOOK_URL and AGENT_WEBHOOK_TOKEN must be configured")

    connector = find_connector()
    config = {
        "url": AGENT_WEBHOOK_URL,
        "method": "post",
        "headers": {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {AGENT_WEBHOOK_TOKEN}",
        },
    }
    if connector:
        connector = api_request(
            f"/api/actions/connector/{connector['id']}",
            method="PUT",
            body={"name": CONNECTOR_NAME, "config": config, "secrets": {}},
        )
    else:
        connector = api_request(
            "/api/actions/connector",
            method="POST",
            body={
                "name": CONNECTOR_NAME,
                "connector_type_id": ".webhook",
                "config": config,
                "secrets": {},
            },
        )
    return connector["id"]


def ensure_rule(connector_id):
    query = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"event.risk_score": {"gte": THRESHOLD}}},
                    {"term": {"soc.risk.status.keyword": "high"}},
                ]
            }
        }
    }
    rule = {
        "name": RULE_NAME,
        "rule_type_id": ".es-query",
        "consumer": "alerts",
        "schedule": {"interval": "1m"},
        "notify_when": "onThrottleInterval",
        "throttle": "5m",
        "actions": [
            {
                "group": "query matched",
                "id": connector_id,
                "params": {
                    "body": json.dumps(
                        {
                            "source": "kibana",
                            "rule_id": "{{rule.id}}",
                            "rule_name": "{{rule.name}}",
                            "alert_id": "{{alert.id}}",
                            "triggered_at": "{{context.date}}",
                        }
                    )
                },
            }
        ],
        "params": {
            "searchType": "esQuery",
            "timeWindowSize": ALERT_LOOKBACK_MINUTES,
            "timeWindowUnit": "m",
            "threshold": [0],
            "thresholdComparator": ">",
            "size": 100,
            "aggType": "count",
            "groupBy": "all",
            "termField": "",
            "termSize": 5,
            "index": ["logs-app-*"],
            "timeField": "@timestamp",
            "esQuery": json.dumps(query),
            "excludeHitsFromPreviousRun": True,
        },
        "tags": ["threat-intel", "high-risk"],
        "enabled": True,
    }
    existing = find_rule()
    if existing:
        update_rule = {
            key: value
            for key, value in rule.items()
            if key not in {"rule_type_id", "consumer", "enabled"}
        }
        api_request(
            f"/api/alerting/rule/{existing['id']}",
            method="PUT",
            body=update_rule,
        )
    else:
        api_request(
            f"/api/alerting/rule/{RULE_ID}",
            method="POST",
            body=rule,
        )


def main():
    wait_for_kibana()
    connector_id = ensure_connector()
    ensure_rule(connector_id)
    print(f"Configured Kibana high-risk alert at threshold {THRESHOLD}")


if __name__ == "__main__":
    main()
