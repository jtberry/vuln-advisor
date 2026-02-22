"""
api/main.py — FastAPI entry point for the VulnAdvisor REST API.

Walk phase — exposes the core engine over HTTP so the web UI and
external tools can consume triage results without running the CLI.

Install deps:  pip install -r requirements-api.txt
Run with:      make run-api
               uvicorn api.main:app --reload
"""

# TODO: implement FastAPI app
# from fastapi import FastAPI
# from api.routes import cve
#
# app = FastAPI(
#     title="VulnAdvisor API",
#     description="CVE triage and remediation guidance",
#     version="0.2.0",
# )
# app.include_router(cve.router)
