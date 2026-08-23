import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import config
from app.routes.explanation import router as explanation_router

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="M6 - Explainable AI Security Advisor",
    description="Consumes M5's RiskAssessedFinding and produces an "
    "ExplainedFinding for M7, per PS4 Interface Contract v1.0. "
    "Never computes or modifies risk_score / risk_level.",
    version=config.APP_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # fine for a hackathon demo; tighten for prod
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(explanation_router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "M6"}


@app.get("/api/v1/version")
def version():
    return {
        "service": "M6 - Explainable AI Security Advisor",
        "app_version": config.APP_VERSION,
        "contract_version": config.CONTRACT_VERSION,
    }
