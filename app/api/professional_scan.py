"""
Professional Scan API - FastAPI endpoints for job-based scanning
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, HttpUrl, Field
from typing import Dict, Any, Optional, List
from app.core.job_orchestrator import JobOrchestrator, ScanProfile

router = APIRouter()

# Initialize job orchestrator
job_orchestrator = JobOrchestrator()

class ScanRequest(BaseModel):
    target: HttpUrl = Field(..., description="Target URL to scan")
    profile: str = Field(default="fast", description="Scan profile: fast, enhanced, deep")
    auth: Optional[Dict[str, Any]] = Field(default=None, description="Authentication credentials")
    notify_webhook: Optional[str] = Field(default=None, description="Webhook URL for notifications")
    consent: bool = Field(default=False, description="User consent for scanning")

class ScanResponse(BaseModel):
    job_id: str
    status: str
    message: str

class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    stage: str
    progress: int
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error_message: Optional[str] = None

class JobResultsResponse(BaseModel):
    job_id: str
    status: str
    target_url: str
    profile: str
    findings: List[Dict[str, Any]]
    raw_outputs: Dict[str, str]
    report: Dict[str, Any]
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

class CancelRequest(BaseModel):
    job_id: str

class ConsentRequest(BaseModel):
    target: HttpUrl
    consent: bool
    user_id: str = "default"

@router.post("/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest):
    """
    Create a new scan job
    """
    try:
        # Validate profile
        try:
            profile = ScanProfile(request.profile.lower())
        except ValueError:
            raise HTTPException(
                status_code=400, 
                detail="Invalid profile. Must be one of: fast, enhanced, deep"
            )
        
        # Create scan job
        job_id = job_orchestrator.create_scan_job(
            user_id="default",  # TODO: Get from auth
            target_url=str(request.target),
            profile=profile,
            consent=request.consent
        )
        
        return ScanResponse(
            job_id=job_id,
            status="accepted",
            message=f"Scan job created successfully. Use /scan/{job_id}/status to check progress."
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create scan job: {str(e)}")

@router.get("/scan/{job_id}/status", response_model=JobStatusResponse)
async def get_scan_status(job_id: str):
    """
    Get scan job status
    """
    try:
        status = job_orchestrator.get_job_status(job_id)
        if not status:
            raise HTTPException(status_code=404, detail="Job not found")
        
        return JobStatusResponse(**status)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get job status: {str(e)}")

@router.get("/scan/{job_id}/results", response_model=JobResultsResponse)
async def get_scan_results(job_id: str):
    """
    Get scan job results
    """
    try:
        results = job_orchestrator.get_job_results(job_id)
        if not results:
            raise HTTPException(status_code=404, detail="Job not found")
        
        if results.get("status") != "completed":
            raise HTTPException(
                status_code=202, 
                detail=f"Job not completed yet. Status: {results.get('status')}"
            )
        
        return JobResultsResponse(**results)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get job results: {str(e)}")

@router.post("/scan/{job_id}/cancel")
async def cancel_scan(job_id: str):
    """
    Cancel a scan job
    """
    try:
        success = job_orchestrator.cancel_job(job_id)
        if not success:
            raise HTTPException(status_code=404, detail="Job not found or cannot be cancelled")
        
        return {"message": "Job cancelled successfully", "job_id": job_id}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel job: {str(e)}")

@router.post("/consent")
async def record_consent(request: ConsentRequest):
    """
    Record user consent for scanning
    """
    try:
        # TODO: Implement consent recording in database
        # For now, just return success
        return {
            "message": "Consent recorded successfully",
            "target": str(request.target),
            "consent": request.consent,
            "user_id": request.user_id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to record consent: {str(e)}")

@router.get("/jobs")
async def list_jobs(
    user_id: Optional[str] = Query(default=None, description="Filter by user ID"),
    limit: int = Query(default=50, description="Maximum number of jobs to return")
):
    """
    List scan jobs
    """
    try:
        jobs = job_orchestrator.list_jobs(user_id)
        return {
            "jobs": jobs[:limit],
            "total": len(jobs),
            "returned": min(len(jobs), limit)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list jobs: {str(e)}")

@router.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    return {
        "status": "healthy",
        "service": "Professional Scan API",
        "active_jobs": len(job_orchestrator.jobs),
        "features": [
            "Job-based scanning",
            "Background processing",
            "Multiple scan profiles",
            "Consent management",
            "Raw output storage",
            "Structured reporting"
        ]
    }

@router.post("/cleanup")
async def cleanup_old_jobs(days: int = Query(default=7, description="Days to keep completed jobs")):
    """
    Clean up old completed jobs
    """
    try:
        removed_count = job_orchestrator.cleanup_old_jobs(days)
        return {
            "message": f"Cleaned up {removed_count} old jobs",
            "days": days,
            "removed_count": removed_count
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cleanup jobs: {str(e)}")

