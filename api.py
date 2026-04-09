from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from detector.detector import run_full_scan
from ai_engine.risk_scorer import analyze_findings
from logs.audit_logger import save_log, view_logs
from remediation.remediator import auto_remediate
import json, os

app = FastAPI(title="AutoShield AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "AutoShield AI API Running 🛡️"}

@app.get("/scan")
def scan():
    findings = run_full_scan()
    analyzed = analyze_findings(findings)
    save_log(analyzed)
    return {"findings": analyzed}

@app.get("/logs")
def get_logs():
    log_file = "logs/audit_log.json"
    if not os.path.exists(log_file):
        return {"logs": []}
    with open(log_file, "r") as f:
        logs = json.load(f)
    return {"logs": logs}

@app.post("/remediate")
def remediate():
    findings = run_full_scan()
    analyzed = analyze_findings(findings)
    fixed, skipped = auto_remediate(analyzed)
    return {"fixed": fixed, "skipped": skipped}