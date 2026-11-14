from contextlib import asynccontextmanager
from backend.app.api.deps import get_db
from backend.app.api.v1 import router
from backend.app.models.domain import ScanJob
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.database import Base, engine
from app.worker import run_aws_cspm_scan
import app.models  # noqa: F401 - ensures all ORM tables register with Base.metadata

from app.remediation import RemediationEngine

@router.post("/findings/{finding_id}/remediate")
def remediate_finding_endpoint(
    finding_id: int,
    dry_run: bool = True,
    db: Session = Depends(get_db)
):
    engine = RemediationEngine(db)
    return engine.remediate_finding(finding_id=finding_id, dry_run=dry_run)
    

@router.post("/scans/run")
def trigger_scan(payload: ScanCreateRequest, db: Session = Depends(get_db)):
    new_scan = ScanJob(aws_account_id=payload.aws_account_id, status="QUEUED", findings_count=0)
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Dispatch async task to Redis/Celery
    run_aws_cspm_scan.delay(new_scan.id, payload.aws_account_id)

    return new_scan

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables cleanly on application startup."""
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AWS Cloud Security Posture Management & Threat Detection Platform",
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Attach baseline defensive HTTP security headers to every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["Root"])
def root():
    return {
        "message": "VaultMesh API is online",
        "docs": f"{settings.API_V1_PREFIX}/docs",
    }
