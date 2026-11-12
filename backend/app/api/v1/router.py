from fastapi import APIRouter
from app.api.v1.endpoints import (
    accounts,
    analyzers,
    audit,
    auth,
    compliance,
    dashboard,
    findings,
    health,
    remediation,
    reports,
    scans,
    threats,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(accounts.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(analyzers.router)
api_router.include_router(threats.router)
api_router.include_router(remediation.router)
api_router.include_router(compliance.router)
api_router.include_router(audit.router)
api_router.include_router(reports.router)
