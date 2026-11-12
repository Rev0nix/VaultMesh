from fastapi import APIRouter
from app.api.v1.endpoints import accounts, analyzers, auth, dashboard, findings, health, scans, threats

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(accounts.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(analyzers.router)
api_router.include_router(threats.router)
