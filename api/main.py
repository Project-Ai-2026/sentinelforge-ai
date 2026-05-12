from fastapi import FastAPI
from pydantic import BaseModel

import json

from enrichment.ioc_classifier import classify_ioc

from ai_analysis.threat_summary import generate_ioc_summary
from ai_analysis.supplier_summary import generate_supplier_summary

from agent.workflow_health_agent import run_workflow_health_agent

from suppliers.resilience_score import calculate_resilience_score


app = FastAPI(title="SentinelForge AI")


class IOCRequest(BaseModel):
    ioc: str
    include_ai: bool = True


@app.get("/")
def home():
    return {
        "message": "SentinelForge AI is running"
    }


@app.post("/analyze-ioc")
def analyze_ioc(request: IOCRequest):

    ioc_type = classify_ioc(request.ioc)

    result = {
        "ioc": request.ioc,
        "ioc_type": ioc_type,
        "status": "ingested"
    }

    if request.include_ai:

        result["ai_analysis"] = generate_ioc_summary(
            request.ioc,
            ioc_type
        )

    return result


@app.get("/health/feeds")
def health_feeds():

    return {
        "workflow_health": run_workflow_health_agent()
    }


@app.get("/supplier/example")
def supplier_example():

    with open("suppliers/example_supplier.json", "r") as f:
        profile = json.load(f)

    resilience = calculate_resilience_score(profile)

    ai_summary = generate_supplier_summary(
        profile,
        resilience
    )

    return {
        "supplier_profile": profile,
        "resilience_assessment": resilience,
        "ai_summary": ai_summary
    }
