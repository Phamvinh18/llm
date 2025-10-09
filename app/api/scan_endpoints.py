"""
Scan API Endpoints - FastAPI endpoints cho scan management
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from typing import Dict, List, Any, Optional
import json
import os
from pathlib import Path

from app.core.scan_orchestrator import ScanOrchestrator
from app.core.evidence_storage import EvidenceStorage
from app.core.llm_enrichment import LLMEnrichment
from app.core.enhanced_rag_retriever import EnhancedRAGRetriever
from app.clients.gemini_client import GeminiClient

router = APIRouter(prefix="/scan", tags=["scan"])

# Initialize components
scan_orchestrator = ScanOrchestrator()
evidence_storage = EvidenceStorage()
rag_retriever = EnhancedRAGRetriever()
llm_client = GeminiClient()
llm_enrichment = LLMEnrichment(llm_client, rag_retriever)

@router.post("/start")
async def start_scan(request: Dict[str, Any]):
    """Start a new scan job"""
    try:
        target_url = request.get("url")
        if not target_url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        # Start scan
        result = await scan_orchestrator.start_scan(target_url)
        
        if result["success"]:
            return {
                "success": True,
                "job_id": result["job_id"],
                "message": result["message"],
                "estimated_time": result["estimated_time"],
                "evidence_dir": result["evidence_dir"]
            }
        else:
            raise HTTPException(status_code=400, detail=result.get("error", "Scan failed to start"))
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status/{job_id}")
async def get_scan_status(job_id: str):
    """Get scan job status"""
    try:
        job = scan_orchestrator.get_scan_status(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        return {
            "job_id": job.job_id,
            "target_url": job.target_url,
            "status": job.status.value,
            "current_stage": job.current_stage.value,
            "progress": job.progress,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "error_message": job.error_message
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/results/{job_id}")
async def get_scan_results(job_id: str):
    """Get scan results"""
    try:
        results = scan_orchestrator.get_scan_results(job_id)
        if not results:
            raise HTTPException(status_code=404, detail="Job not found")
        
        # Get evidence summary
        evidence_summary = evidence_storage.get_evidence_summary(job_id)
        
        return {
            "job_id": results["job_id"],
            "target_url": results["target_url"],
            "status": results["status"],
            "current_stage": results["current_stage"],
            "progress": results["progress"],
            "created_at": results["created_at"],
            "started_at": results["started_at"],
            "completed_at": results["completed_at"],
            "findings": results["findings"],
            "raw_outputs": results["raw_outputs"],
            "evidence_dir": results["evidence_dir"],
            "evidence_summary": evidence_summary
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cancel/{job_id}")
async def cancel_scan(job_id: str):
    """Cancel a scan job"""
    try:
        success = scan_orchestrator.cancel_scan(job_id)
        if success:
            return {"success": True, "message": f"Scan {job_id} cancelled"}
        else:
            raise HTTPException(status_code=400, detail="Cannot cancel scan")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/evidence/{job_id}")
async def get_evidence_files(job_id: str):
    """Get list of evidence files for a job"""
    try:
        files = evidence_storage.list_evidence_files(job_id)
        return {
            "job_id": job_id,
            "files": files,
            "count": len(files)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/evidence/{job_id}/{filename}")
async def download_evidence_file(job_id: str, filename: str):
    """Download specific evidence file"""
    try:
        file_path = evidence_storage.get_evidence_file(job_id, filename)
        if not file_path:
            raise HTTPException(status_code=404, detail="File not found")
        
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type='application/octet-stream'
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/evidence/{job_id}/archive")
async def download_evidence_archive(job_id: str):
    """Download evidence archive"""
    try:
        archive_path = evidence_storage.create_evidence_archive(job_id)
        if not archive_path:
            raise HTTPException(status_code=404, detail="Archive not found")
        
        return FileResponse(
            path=archive_path,
            filename=f"evidence_{job_id}.zip",
            media_type='application/zip'
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/enrich/{job_id}")
async def enrich_findings(job_id: str):
    """Manually trigger LLM enrichment for findings"""
    try:
        results = scan_orchestrator.get_scan_results(job_id)
        if not results:
            raise HTTPException(status_code=404, detail="Job not found")
        
        findings = results.get("findings", [])
        if not findings:
            return {"message": "No findings to enrich"}
        
        enriched_findings = []
        for finding in findings:
            try:
                enrichment = await llm_enrichment.enrich_finding(finding)
                enriched_finding = llm_enrichment.merge_enrichment_with_finding(finding, enrichment)
                enriched_findings.append(enriched_finding)
            except Exception as e:
                print(f"Error enriching finding {finding.get('id', '')}: {e}")
                enriched_findings.append(finding)
        
        # Update job with enriched findings
        job = scan_orchestrator.get_scan_status(job_id)
        if job:
            job.findings = enriched_findings
        
        return {
            "success": True,
            "message": f"Enriched {len(enriched_findings)} findings",
            "enriched_findings": enriched_findings
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/report/{job_id}")
async def generate_report(job_id: str, format: str = "json"):
    """Generate scan report"""
    try:
        results = scan_orchestrator.get_scan_results(job_id)
        if not results:
            raise HTTPException(status_code=404, detail="Job not found")
        
        if format == "json":
            return results
        elif format == "html":
            # Generate HTML report
            html_report = generate_html_report(results)
            return JSONResponse(content={"html": html_report})
        else:
            raise HTTPException(status_code=400, detail="Invalid format")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/jobs")
async def list_jobs():
    """List all scan jobs"""
    try:
        jobs = []
        for job_id, job in scan_orchestrator.active_jobs.items():
            jobs.append({
                "job_id": job.job_id,
                "target_url": job.target_url,
                "status": job.status.value,
                "current_stage": job.current_stage.value,
                "progress": job.progress,
                "created_at": job.created_at,
                "started_at": job.started_at,
                "completed_at": job.completed_at
            })
        
        return {
            "jobs": jobs,
            "total": len(jobs)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/cleanup")
async def cleanup_old_evidence(days_old: int = 30):
    """Cleanup old evidence files"""
    try:
        evidence_storage.cleanup_old_evidence(days_old)
        return {
            "success": True,
            "message": f"Cleaned up evidence older than {days_old} days"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def generate_html_report(results: Dict[str, Any]) -> str:
    """Generate HTML report from scan results"""
    try:
        findings = results.get("findings", [])
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {results.get('target_url', '')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
                .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #dc3545; }}
                .high {{ border-left: 5px solid #fd7e14; }}
                .medium {{ border-left: 5px solid #ffc107; }}
                .low {{ border-left: 5px solid #28a745; }}
                .evidence {{ background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }}
                .provenance {{ background: #e9ecef; padding: 10px; border-radius: 3px; margin-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p><strong>Target:</strong> {results.get('target_url', '')}</p>
                <p><strong>Job ID:</strong> {results.get('job_id', '')}</p>
                <p><strong>Status:</strong> {results.get('status', '')}</p>
                <p><strong>Completed:</strong> {results.get('completed_at', '')}</p>
                <p><strong>Total Findings:</strong> {len(findings)}</p>
            </div>
        """
        
        for finding in findings:
            severity = finding.get('severity', 'Unknown').lower()
            html += f"""
            <div class="finding {severity}">
                <h3>{finding.get('type', 'Unknown')} - {finding.get('severity', 'Unknown')}</h3>
                <p><strong>Path:</strong> {finding.get('path', '')}</p>
                <p><strong>Parameter:</strong> {finding.get('param', '')}</p>
                <p><strong>Tool:</strong> {finding.get('tool', '')}</p>
                <p><strong>Confidence:</strong> {finding.get('confidence', 'Unknown')}</p>
                <p><strong>CVSS:</strong> {finding.get('cvss_v3', 'N/A')}</p>
                <p><strong>Exploitability Score:</strong> {finding.get('exploitability_score', 0)}/100</p>
                
                <h4>Evidence:</h4>
                <div class="evidence">{finding.get('evidence_snippet', '')}</div>
                
                <h4>Justification:</h4>
                <p>{finding.get('justification', '')}</p>
                
                <h4>Safe PoC Steps:</h4>
                <ul>
            """
            
            for step in finding.get('safe_poc_steps', []):
                html += f"<li>{step}</li>"
            
            html += """
                </ul>
                
                <h4>Remediation:</h4>
                <ul>
            """
            
            for rem in finding.get('remediation', []):
                html += f"<li><strong>{rem.get('type', '')}:</strong> {rem.get('description', '')}</li>"
                if rem.get('code'):
                    html += f"<pre>{rem.get('code', '')}</pre>"
            
            html += """
                </ul>
                
                <h4>References:</h4>
                <ul>
            """
            
            for ref in finding.get('references', []):
                html += f"<li><a href='{ref.get('url', '#')}'>{ref.get('title', '')}</a> ({ref.get('source', '')})</li>"
            
            html += """
                </ul>
            """
            
            # Add provenance if available
            if finding.get('provenance'):
                html += """
                <h4>RAG Provenance:</h4>
                <div class="provenance">
                """
                for prov in finding.get('provenance', []):
                    html += f"<p><strong>{prov.get('claim', '')}:</strong> {prov.get('snippet', '')} (Source: {prov.get('source_doc_id', '')})</p>"
                html += "</div>"
            
            html += "</div>"
        
        html += """
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        return f"<html><body><h1>Error generating report: {str(e)}</h1></body></html>"
