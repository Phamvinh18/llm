"""
Scan Orchestrator API - Endpoints cho hệ thống scan chuyên nghiệp
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import Dict, Any, Optional, List
import asyncio
from app.core.scan_orchestrator import ScanOrchestrator

router = APIRouter()

# Global orchestrator instance
orchestrator = ScanOrchestrator()

class ScanRequest(BaseModel):
    target_url: HttpUrl
    user_id: Optional[str] = "default"

class ScanResponse(BaseModel):
    success: bool
    job_id: Optional[str] = None
    message: str
    estimated_time: Optional[str] = None
    error: Optional[str] = None

class JobStatusResponse(BaseModel):
    job_id: str
    target_url: str
    status: str
    current_stage: str
    progress: int
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    summary: Optional[str] = None
    findings_count: int

class JobResultsResponse(BaseModel):
    job_id: str
    target_url: str
    summary: str
    findings: List[Dict[str, Any]]
    raw_outputs: Dict[str, Any]
    scan_duration: str
    report_url: Optional[str] = None

@router.post('/start', response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    """
    Bắt đầu scan job
    """
    try:
        result = await orchestrator.start_scan(str(request.target_url), request.user_id)
        
        if result['success']:
            return ScanResponse(
                success=True,
                job_id=result['job_id'],
                message=result['message'],
                estimated_time=result['estimated_time']
            )
        else:
            return ScanResponse(
                success=False,
                message=result['error']
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

@router.get('/status/{job_id}', response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    """
    Lấy trạng thái job
    """
    try:
        status = orchestrator.get_job_status(job_id)
        
        if not status:
            raise HTTPException(status_code=404, detail="Job not found")
        
        return JobStatusResponse(**status)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get job status: {str(e)}")

@router.get('/results/{job_id}', response_model=JobResultsResponse)
async def get_job_results(job_id: str):
    """
    Lấy kết quả job (chỉ khi completed)
    """
    try:
        results = orchestrator.get_job_results(job_id)
        
        if not results:
            raise HTTPException(status_code=404, detail="Job not found or not completed")
        
        return JobResultsResponse(**results)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get job results: {str(e)}")

@router.get('/jobs')
async def list_jobs():
    """
    Liệt kê tất cả jobs
    """
    try:
        jobs = []
        for job_id, job in orchestrator.active_jobs.items():
            status = orchestrator.get_job_status(job_id)
            if status:
                jobs.append(status)
        
        return {
            'total_jobs': len(jobs),
            'jobs': jobs
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list jobs: {str(e)}")

@router.delete('/jobs/{job_id}')
async def cancel_job(job_id: str):
    """
    Hủy job (nếu đang chạy)
    """
    try:
        if job_id not in orchestrator.active_jobs:
            raise HTTPException(status_code=404, detail="Job not found")
        
        job = orchestrator.active_jobs[job_id]
        if job.status.value in ['completed', 'failed', 'cancelled']:
            raise HTTPException(status_code=400, detail="Job cannot be cancelled")
        
        job.status = job.status.CANCELLED
        job.completed_at = job.completed_at or "Cancelled"
        
        return {
            'success': True,
            'message': f"Job {job_id} has been cancelled"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel job: {str(e)}")

@router.get('/health')
async def health_check():
    """
    Health check cho scan orchestrator
    """
    try:
        return {
            'status': 'healthy',
            'service': 'Scan Orchestrator',
            'active_jobs': len(orchestrator.active_jobs),
            'tools_available': orchestrator.scan_tools.tools_available,
            'allowlist_count': len(orchestrator.allowlist)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@router.get('/tools')
async def get_available_tools():
    """
    Lấy danh sách tools có sẵn
    """
    try:
        return {
            'tools': orchestrator.scan_tools.tools_available,
            'total_available': sum(1 for available in orchestrator.scan_tools.tools_available.values() if available)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get tools info: {str(e)}")

@router.get('/allowlist')
async def get_allowlist():
    """
    Lấy danh sách allowlist
    """
    try:
        return {
            'allowlist': orchestrator.allowlist,
            'count': len(orchestrator.allowlist)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get allowlist: {str(e)}")

