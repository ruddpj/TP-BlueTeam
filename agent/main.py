import base64
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, TypedDict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException
from langgraph.graph import END, START, StateGraph
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


logger = logging.getLogger(__name__)
FUTURE_TIMESTAMP_TOLERANCE_MINUTES = 2
AUDIT_INDEX = "agent-audit-logs"


class AlertTrigger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = "kibana"
    rule_id: str = Field(min_length=1, max_length=128)
    rule_name: str = Field(min_length=1, max_length=256)
    alert_id: str | None = Field(default=None, max_length=128)
    triggered_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class TriggerState(TypedDict):
    source: str
    rule_id: str
    rule_name: str
    alert_id: str | None
    triggered_at: str


class AnalysisState(TypedDict):
    trigger: TriggerState
    events: dict[str, Any]


def query_high_risk_events(state: AnalysisState) -> dict[str, dict[str, Any]]:
    threshold = int(os.getenv("RISK_SCORE_THRESHOLD", "70"))
    lookback_minutes = int(os.getenv("ALERT_LOOKBACK_MINUTES", "60"))
    triggered_at = datetime.fromisoformat(
        state["trigger"]["triggered_at"].replace("Z", "+00:00")
    ).astimezone(timezone.utc)
    window_start = triggered_at - timedelta(minutes=lookback_minutes)
    window_end = triggered_at + timedelta(
        minutes=FUTURE_TIMESTAMP_TOLERANCE_MINUTES
    )
    query = (
        "FROM logs-app-* "
        f"| WHERE event.risk_score >= {threshold} "
        'AND soc.risk.status.keyword == "high" '
        f"| WHERE @timestamp >= TO_DATETIME({json.dumps(window_start.isoformat())}) "
        f"AND @timestamp <= TO_DATETIME({json.dumps(window_end.isoformat())}) "
        "| SORT @timestamp DESC "
        "| LIMIT 100 "
        "| KEEP @timestamp, event.risk_score, soc.risk.status.keyword, "
        "soc.risk.reasons.keyword, source.ip, destination.ip"
    )
    headers = elasticsearch_headers()
    request = Request(
        f"{os.getenv('ELASTICSEARCH_URL', 'http://elasticsearch:9200').rstrip('/')}/_query",
        data=json.dumps({"query": query}).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=15) as response:
            results = json.loads(response.read())
    except (HTTPError, URLError, TimeoutError) as error:
        raise RuntimeError(f"Elasticsearch ES|QL query failed: {error}") from error

    return {"events": results}


def elasticsearch_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    api_key = os.getenv("ELASTICSEARCH_API_KEY")
    username = os.getenv("ELASTICSEARCH_USERNAME")
    password = os.getenv("ELASTICSEARCH_PASSWORD")
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    elif username or password:
        if not username or not password:
            raise RuntimeError(
                "Both ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD are required"
            )
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {credentials}"
    return headers


def write_audit_record(
    trigger_id: str, trigger_data: TriggerState, matched_events: int
) -> None:
    document = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "trigger_id": trigger_id,
        "alert_id": trigger_data["alert_id"],
        "rule_id": trigger_data["rule_id"],
        "rule_name": trigger_data["rule_name"],
        "triggered_at": trigger_data["triggered_at"],
        "status": "completed",
        "matched_events": matched_events,
    }
    request = Request(
        f"{os.getenv('ELASTICSEARCH_URL', 'http://elasticsearch:9200').rstrip('/')}/{AUDIT_INDEX}/_doc",
        data=json.dumps(document).encode(),
        headers=elasticsearch_headers(),
        method="POST",
    )
    try:
        with urlopen(request, timeout=15) as response:
            response.read()
    except (HTTPError, URLError, TimeoutError) as error:
        raise RuntimeError(f"Writing the agent audit record failed: {error}") from error


def process_alert(trigger_id: str, trigger_data: TriggerState) -> None:
    try:
        result = agent_graph.invoke({"trigger": trigger_data, "events": {}})
        values = result["events"].get("values", [])
        write_audit_record(trigger_id, trigger_data, len(values))
    except (RuntimeError, ValueError):
        logger.exception("Analysis failed for accepted trigger %s", trigger_id)
        raise

    logger.info(
        "Analysis completed for trigger %s (alert %s, rule %s): %d matching events",
        trigger_id,
        trigger_data["alert_id"],
        trigger_data["rule_id"],
        len(values),
    )


workflow = StateGraph(AnalysisState)
workflow.add_node("query_high_risk_events", query_high_risk_events)
workflow.add_edge(START, "query_high_risk_events")
workflow.add_edge("query_high_risk_events", END)
agent_graph = workflow.compile()

app = FastAPI(title="Threat analysis trigger", version="1.0.0")


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook/kibana", status_code=202)
def handle_kibana_alert(
    trigger: AlertTrigger,
    background_tasks: BackgroundTasks,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    expected_token = os.getenv("AGENT_WEBHOOK_TOKEN")
    if not expected_token:
        raise HTTPException(status_code=503, detail="Webhook authentication is not configured")
    if not secrets.compare_digest(
        authorization or "", f"Bearer {expected_token}"
    ):
        raise HTTPException(status_code=401, detail="Invalid webhook authorization")

    trigger_id = str(uuid4())
    trigger_data: TriggerState = {
        "source": trigger.source,
        "rule_id": trigger.rule_id,
        "rule_name": trigger.rule_name,
        "alert_id": trigger.alert_id,
        "triggered_at": trigger.triggered_at.isoformat(),
    }
    background_tasks.add_task(process_alert, trigger_id, trigger_data)
    return {
        "status": "accepted",
        "trigger_id": trigger_id,
        "rule_id": trigger.rule_id,
    }
