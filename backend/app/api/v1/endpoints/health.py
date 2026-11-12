from datetime import datetime, timezone
from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()


@router.get("/health", tags=["System"])
def health_check():
    """Verify API availability, environment, and AWS integration mode."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "aws_mode": settings.AWS_INTEGRATION_MODE,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
