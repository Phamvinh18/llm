from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "message": "VA-WebSec Assistant API is running",
            "version": "1.0.0"
        }
    )

# Core API routers
try:
    from app.api.chat import router as chat_router
    router.include_router(chat_router, prefix='/chat')
except Exception:
    pass

try:
    from app.api.chat_assistant import router as chat_assistant_router
    router.include_router(chat_assistant_router, prefix='/chat-assistant')
except Exception:
    pass

try:
    from app.api.scan import router as scan_router
    router.include_router(scan_router, prefix='/scan')
except Exception:
    pass

try:
    from app.api.smart_scan import router as smart_scan_router
    router.include_router(smart_scan_router, prefix='/smart-scan')
except Exception:
    pass

try:
    from app.api.analyze import router as analyze_router
    router.include_router(analyze_router, prefix='')
except Exception:
    pass

try:
    from app.api.workflow import router as workflow_router
    router.include_router(workflow_router, prefix='/workflow')
except Exception:
    pass

try:
    from app.api.attack import router as attack_router
    router.include_router(attack_router, prefix='/attack')
except Exception:
    pass

try:
    from app.api.nikto import router as nikto_router
    router.include_router(nikto_router, prefix='/nikto')
except Exception:
    pass

try:
    from app.api.kb import router as kb_router
    router.include_router(kb_router, prefix='/kb')
except Exception:
    pass

try:
    from app.api.intent_scan import router as intent_router
    router.include_router(intent_router, prefix='/intent')
except Exception:
    pass

try:
    from app.api.monitoring import router as monitoring_router
    router.include_router(monitoring_router, prefix='/monitoring')
except Exception:
    pass


# Scan Orchestrator
try:
    from app.api.scan_orchestrator import router as scan_orchestrator_router
    router.include_router(scan_orchestrator_router, prefix='/scan-orchestrator')
except Exception:
    pass

# Professional Scan API
try:
    from app.api.professional_scan import router as professional_scan_router
    router.include_router(professional_scan_router, prefix='/professional-scan')
except Exception:
    pass
