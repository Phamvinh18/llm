"""
Monitoring API - Professional monitoring system endpoints
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
import asyncio
import logging

from app.core.monitoring_system import monitoring_system, log_info, log_warning, log_error, record_metric, start_timer, end_timer, get_health_status

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

# Request/Response models
class LogRequest(BaseModel):
    level: str = Field(..., description="Log level (INFO, WARNING, ERROR, DEBUG)")
    message: str = Field(..., description="Log message")
    module: Optional[str] = Field(None, description="Module name")
    function: Optional[str] = Field(None, description="Function name")
    line_number: Optional[int] = Field(None, description="Line number")
    tags: Optional[Dict[str, str]] = Field(None, description="Additional tags")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class MetricRequest(BaseModel):
    name: str = Field(..., description="Metric name")
    value: Union[int, float, str] = Field(..., description="Metric value")
    tags: Optional[Dict[str, str]] = Field(None, description="Additional tags")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class TimerRequest(BaseModel):
    operation: str = Field(..., description="Operation name")
    success: bool = Field(True, description="Operation success status")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class AlertRuleRequest(BaseModel):
    name: str = Field(..., description="Alert rule name")
    condition: str = Field(..., description="Alert condition (simplified)")
    severity: str = Field(..., description="Alert severity")
    message: str = Field(..., description="Alert message")

class HealthResponse(BaseModel):
    status: str = Field(..., description="Health status")
    timestamp: float = Field(..., description="Timestamp")
    summary: Dict[str, Any] = Field(..., description="Summary metrics")
    recent_alerts: List[Dict[str, Any]] = Field(..., description="Recent alerts")
    system_metrics: Optional[Dict[str, Any]] = Field(None, description="System metrics")

# API Endpoints

@router.post("/log")
async def log_message(request: LogRequest):
    """
    Log a message
    """
    try:
        monitoring_system.log(
            level=request.level,
            message=request.message,
            module=request.module,
            function=request.function,
            line_number=request.line_number,
            tags=request.tags,
            metadata=request.metadata
        )
        
        return {
            "status": "success",
            "message": "Log message recorded",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Logging failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Logging failed: {str(e)}")

@router.post("/metric")
async def record_metric_endpoint(request: MetricRequest):
    """
    Record a metric
    """
    try:
        monitoring_system.record_metric(
            name=request.name,
            value=request.value,
            tags=request.tags,
            metadata=request.metadata
        )
        
        return {
            "status": "success",
            "message": "Metric recorded",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Metric recording failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Metric recording failed: {str(e)}")

@router.post("/timer/start")
async def start_operation_timer(request: TimerRequest):
    """
    Start operation timer
    """
    try:
        timer_id = monitoring_system.start_operation_timer(request.operation)
        
        return {
            "status": "success",
            "timer_id": timer_id,
            "operation": request.operation,
            "message": "Timer started",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Timer start failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Timer start failed: {str(e)}")

@router.post("/timer/end")
async def end_operation_timer(request: TimerRequest):
    """
    End operation timer
    """
    try:
        # Extract timer_id from metadata or use operation name
        timer_id = request.metadata.get('timer_id', f"{request.operation}_{int(datetime.now().timestamp() * 1000)}")
        
        monitoring_system.end_operation_timer(
            timer_id=timer_id,
            success=request.success,
            error_message=request.error_message,
            metadata=request.metadata
        )
        
        return {
            "status": "success",
            "timer_id": timer_id,
            "operation": request.operation,
            "message": "Timer ended",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Timer end failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Timer end failed: {str(e)}")

@router.get("/health", response_model=HealthResponse)
async def get_health():
    """
    Get system health status
    """
    try:
        health_status = monitoring_system.get_health_status()
        return HealthResponse(**health_status)
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@router.get("/metrics/summary")
async def get_metrics_summary():
    """
    Get metrics summary
    """
    try:
        summary = monitoring_system.get_metrics_summary()
        return {
            "status": "success",
            "summary": summary,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Metrics summary failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Metrics summary failed: {str(e)}")

@router.get("/metrics/recent")
async def get_recent_metrics(name: Optional[str] = None, limit: int = 100):
    """
    Get recent metrics
    """
    try:
        metrics = monitoring_system.get_recent_metrics(name=name, limit=limit)
        return {
            "status": "success",
            "metrics": metrics,
            "count": len(metrics),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Recent metrics failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Recent metrics failed: {str(e)}")

@router.get("/logs/recent")
async def get_recent_logs(level: Optional[str] = None, limit: int = 100):
    """
    Get recent logs
    """
    try:
        logs = monitoring_system.get_recent_logs(level=level, limit=limit)
        return {
            "status": "success",
            "logs": logs,
            "count": len(logs),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Recent logs failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Recent logs failed: {str(e)}")

@router.get("/performance/recent")
async def get_recent_performance_metrics(operation: Optional[str] = None, limit: int = 100):
    """
    Get recent performance metrics
    """
    try:
        metrics = monitoring_system.get_recent_performance_metrics(operation=operation, limit=limit)
        return {
            "status": "success",
            "performance_metrics": metrics,
            "count": len(metrics),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Recent performance metrics failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Recent performance metrics failed: {str(e)}")

@router.get("/alerts/recent")
async def get_recent_alerts(severity: Optional[str] = None, limit: int = 100):
    """
    Get recent alerts
    """
    try:
        alerts = monitoring_system.get_recent_alerts(severity=severity, limit=limit)
        return {
            "status": "success",
            "alerts": alerts,
            "count": len(alerts),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Recent alerts failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Recent alerts failed: {str(e)}")

@router.post("/export")
async def export_metrics(background_tasks: BackgroundTasks, file_path: Optional[str] = None):
    """
    Export metrics to file
    """
    try:
        background_tasks.add_task(monitoring_system.export_metrics, file_path)
        
        return {
            "status": "success",
            "message": "Export started in background",
            "file_path": file_path or monitoring_system.metrics_file,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Export failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

@router.post("/cleanup")
async def cleanup_old_data(days: int = 7):
    """
    Cleanup old data
    """
    try:
        monitoring_system.cleanup_old_data(days=days)
        
        return {
            "status": "success",
            "message": f"Cleanup completed for data older than {days} days",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Cleanup failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {str(e)}")

@router.get("/system/status")
async def get_system_status():
    """
    Get system status
    """
    try:
        import psutil
        
        system_status = {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "process_count": len(psutil.pids()),
            "thread_count": psutil.Process().num_threads(),
            "network_io": dict(psutil.net_io_counters()._asdict()),
            "timestamp": datetime.now().timestamp()
        }
        
        return {
            "status": "success",
            "system_status": system_status,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"System status failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"System status failed: {str(e)}")

@router.get("/config")
async def get_monitoring_config():
    """
    Get monitoring configuration
    """
    try:
        return {
            "status": "success",
            "config": monitoring_system.config,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Config retrieval failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Config retrieval failed: {str(e)}")

@router.post("/config")
async def update_monitoring_config(config: Dict[str, Any]):
    """
    Update monitoring configuration
    """
    try:
        # Update configuration
        monitoring_system.config.update(config)
        
        # Restart system monitoring if needed
        if 'system_monitor_interval' in config:
            monitoring_system.stop_system_monitoring()
            monitoring_system.start_system_monitoring()
        
        return {
            "status": "success",
            "message": "Configuration updated",
            "config": monitoring_system.config,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Config update failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Config update failed: {str(e)}")

@router.get("/dashboard")
async def get_dashboard_data():
    """
    Get dashboard data
    """
    try:
        # Get comprehensive dashboard data
        health_status = monitoring_system.get_health_status()
        metrics_summary = monitoring_system.get_metrics_summary()
        recent_alerts = monitoring_system.get_recent_alerts(limit=10)
        recent_logs = monitoring_system.get_recent_logs(limit=20)
        recent_performance = monitoring_system.get_recent_performance_metrics(limit=10)
        
        dashboard_data = {
            "health": health_status,
            "metrics": metrics_summary,
            "recent_alerts": recent_alerts,
            "recent_logs": recent_logs,
            "recent_performance": recent_performance,
            "timestamp": datetime.now().isoformat()
        }
        
        return {
            "status": "success",
            "dashboard": dashboard_data,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Dashboard data failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Dashboard data failed: {str(e)}")

# Health check endpoint
@router.get("/")
async def monitoring_health_check():
    """
    Health check for monitoring system
    """
    try:
        return {
            "status": "healthy",
            "message": "Monitoring system is operational",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Monitoring health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Monitoring health check failed: {str(e)}")
