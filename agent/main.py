import base64
import json
import os
import secrets
from datetime import datetime, timezone
from typing import TypedDict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, ConfigDict, Field


class AlertTrigger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = "kibana"
    rule_id: str = Field(min_length=1, max_length=128)
    rule_name: str = Field(min_length=1, max_length=256)
    alert_id: str | None = Field(default=None, max_length=128)
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AnalysisState(TypedDict):
    trigger: dict
    events: dict


def query_high_risk_events(_state: AnalysisState) -> dict:
    threshold = int(os.getenv("RISK_SCORE_THRESHOLD", "70"))
    query = (
        "FROM logs-* "
        f"| WHERE event.risk_score >= {threshold} AND soc.risk.status == \"high\" "
        "| WHERE @timestamp >= NOW() - 10 minutes "
        "| SORT @timestamp DESC "
        "| LIMIT 100 "
        "| KEEP @timestamp, event.risk_score, soc.risk.status, "
        "soc.risk.reasons, source.ip, destination.ip, message"
    )
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


workflow = StateGraph(AnalysisState)
workflow.add_node("query_high_risk_events", query_high_risk_events)
workflow.add_edge(START, "query_high_risk_events")
workflow.add_edge("query_high_risk_events", END)
agent_graph = workflow.compile()

app = FastAPI(title="Threat analysis trigger", version="1.0.0")


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook/kibana")
def handle_kibana_alert(
    trigger: AlertTrigger,
    authorization: str | None = Header(default=None),
) -> dict:
    expected_token = os.getenv("AGENT_WEBHOOK_TOKEN")
    if not expected_token:
        raise HTTPException(status_code=503, detail="Webhook authentication is not configured")
    if not secrets.compare_digest(
        authorization or "", f"Bearer {expected_token}"
    ):
        raise HTTPException(status_code=401, detail="Invalid webhook authorization")

    try:
        result = agent_graph.invoke(
            {"trigger": trigger.model_dump(mode="json"), "events": {}}
        )
    except (RuntimeError, ValueError) as error:
        raise HTTPException(status_code=502, detail=str(error)) from error

    values = result["events"].get("values", [])
    return {
        "trigger_id": str(uuid4()),
        "rule_id": trigger.rule_id,
        "matched_events": len(values),
    }
