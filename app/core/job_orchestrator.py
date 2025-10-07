"""
Professional Job Orchestrator for Security Scanning
Implements background job processing with Celery/RQ
"""

import os
import json
import time
import uuid
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

class JobStatus(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanProfile(Enum):
    FAST = "fast"
    ENHANCED = "enhanced"
    DEEP = "deep"

@dataclass
class ScanJob:
    job_id: str
    user_id: str
    target_url: str
    profile: ScanProfile
    status: JobStatus
    stage: str
    progress: int
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    findings: List[Dict[str, Any]] = None
    raw_outputs: Dict[str, str] = None
    report_path: Optional[str] = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.raw_outputs is None:
            self.raw_outputs = {}

class JobOrchestrator:
    def __init__(self):
        self.jobs: Dict[str, ScanJob] = {}
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
        self.reports_dir = os.path.join(self.data_dir, 'reports')
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Ensure required directories exist"""
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(os.path.join(self.reports_dir, 'raw'), exist_ok=True)
        os.makedirs(os.path.join(self.reports_dir, 'screenshots'), exist_ok=True)
        os.makedirs(os.path.join(self.reports_dir, 'har'), exist_ok=True)
    
    def create_scan_job(self, user_id: str, target_url: str, profile: ScanProfile, consent: bool = False) -> str:
        """Create a new scan job"""
        # Validate target URL
        if not self._validate_target_url(target_url):
            raise ValueError("Invalid target URL")
        
        # Check consent/allowlist
        if not self._check_consent_or_allowlist(target_url, consent):
            raise ValueError("Target not in allowlist and consent not provided")
        
        # Generate job ID
        job_id = f"job_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        
        # Create job
        job = ScanJob(
            job_id=job_id,
            user_id=user_id,
            target_url=target_url,
            profile=profile,
            status=JobStatus.QUEUED,
            stage="queued",
            progress=0,
            created_at=datetime.now()
        )
        
        # Store job
        self.jobs[job_id] = job
        
        # Start job in background
        self.executor.submit(self._run_scan_job, job_id)
        
        return job_id
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status"""
        job = self.jobs.get(job_id)
        if not job:
            return None
        
        return {
            "job_id": job.job_id,
            "status": job.status.value,
            "stage": job.stage,
            "progress": job.progress,
            "created_at": job.created_at.isoformat(),
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "error_message": job.error_message
        }
    
    def get_job_results(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job results"""
        job = self.jobs.get(job_id)
        if not job:
            return None
        
        if job.status != JobStatus.COMPLETED:
            return {
                "job_id": job.job_id,
                "status": job.status.value,
                "message": "Job not completed yet"
            }
        
        # Load report if exists
        report_data = {}
        if job.report_path and os.path.exists(job.report_path):
            try:
                with open(job.report_path, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
            except Exception as e:
                report_data = {"error": f"Could not load report: {str(e)}"}
        
        return {
            "job_id": job.job_id,
            "status": job.status.value,
            "target_url": job.target_url,
            "profile": job.profile.value,
            "findings": job.findings,
            "raw_outputs": job.raw_outputs,
            "report": report_data,
            "created_at": job.created_at.isoformat(),
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None
        }
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a job"""
        job = self.jobs.get(job_id)
        if not job:
            return False
        
        if job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
            return False
        
        job.status = JobStatus.CANCELLED
        job.finished_at = datetime.now()
        job.error_message = "Cancelled by user"
        
        return True
    
    def _validate_target_url(self, url: str) -> bool:
        """Validate target URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.scheme in ['http', 'https'] and parsed.netloc
        except:
            return False
    
    def _check_consent_or_allowlist(self, url: str, consent: bool) -> bool:
        """Check if URL is in allowlist or consent provided"""
        # Check allowlist
        try:
            whitelist_file = os.path.join(self.data_dir, 'whitelist.json')
            if os.path.exists(whitelist_file):
                with open(whitelist_file, 'r', encoding='utf-8') as f:
                    whitelist = json.load(f)
                    if url in whitelist:
                        return True
        except Exception:
            pass
        
        # Check consent
        return consent
    
    def _run_scan_job(self, job_id: str):
        """Run scan job in background"""
        job = self.jobs.get(job_id)
        if not job:
            return
        
        try:
            # Update job status
            job.status = JobStatus.RUNNING
            job.started_at = datetime.now()
            job.stage = "initializing"
            job.progress = 5
            
            # Create job directory
            job_dir = os.path.join(self.reports_dir, job_id)
            os.makedirs(job_dir, exist_ok=True)
            os.makedirs(os.path.join(job_dir, 'raw'), exist_ok=True)
            
            # Import scan engine
            from app.core.enhanced_scan_engine import EnhancedScanEngine
            
            # Initialize scan engine
            scan_engine = EnhancedScanEngine()
            
            # Run scan based on profile
            if job.profile == ScanProfile.FAST:
                self._run_fast_scan(job, scan_engine, job_dir)
            elif job.profile == ScanProfile.ENHANCED:
                self._run_enhanced_scan(job, scan_engine, job_dir)
            elif job.profile == ScanProfile.DEEP:
                self._run_deep_scan(job, scan_engine, job_dir)
            
            # Complete job
            job.status = JobStatus.COMPLETED
            job.finished_at = datetime.now()
            job.stage = "completed"
            job.progress = 100
            
        except Exception as e:
            # Mark job as failed
            job.status = JobStatus.FAILED
            job.finished_at = datetime.now()
            job.error_message = str(e)
            job.stage = "failed"
    
    def _run_fast_scan(self, job: ScanJob, scan_engine, job_dir: str):
        """Run fast scan profile"""
        job.stage = "http-check"
        job.progress = 10
        
        # Basic HTTP check
        from app.core.enhanced_scan_engine import ScanProfile as EngineProfile
        scan_result = scan_engine.start_scan(job.target_url, EngineProfile.FAST)
        
        # Run security tools
        job.stage = "running-tools"
        job.progress = 30
        
        from app.core.security_tools_manager import SecurityToolsManager
        tools_manager = SecurityToolsManager()
        
        # Run fast scan tools
        tool_outputs = tools_manager.run_fast_scan(job.target_url, os.path.join(job_dir, 'raw'))
        
        # Parse tool outputs
        job.stage = "parsing-results"
        job.progress = 60
        
        from app.core.tool_parsers import ToolParsers
        parsers = ToolParsers()
        
        # Normalize findings from tools
        normalized_findings = parsers.normalize_all_findings(tool_outputs, job.job_id, job.target_url)
        
        # Combine with basic scan findings
        all_findings = [self._convert_finding_to_dict(f) for f in scan_result.findings]
        all_findings.extend([self._convert_normalized_finding_to_dict(f) for f in normalized_findings])
        
        # Enrich findings with LLM
        job.stage = "enriching-findings"
        job.progress = 80
        
        import asyncio
        try:
            from app.core.llm_enrichment import LLMEnrichment
            enrichment = LLMEnrichment()
            
            # Convert back to NormalizedFinding objects for enrichment
            normalized_for_enrichment = []
            for finding_dict in all_findings:
                from app.core.tool_parsers import NormalizedFinding
                normalized_finding = NormalizedFinding(
                    id=finding_dict.get('id', ''),
                    job_id=job.job_id,
                    target=job.target_url,
                    type=finding_dict.get('type', ''),
                    path=finding_dict.get('path', ''),
                    parameter=finding_dict.get('parameter'),
                    tool=finding_dict.get('tool', ''),
                    severity=finding_dict.get('severity', ''),
                    confidence=finding_dict.get('confidence', ''),
                    cvss_v3=finding_dict.get('cvss_v3'),
                    evidence_snippet=finding_dict.get('evidence', ''),
                    raw_outputs=finding_dict.get('raw_outputs', []),
                    safe_poc_steps=finding_dict.get('safe_poc_steps', []),
                    remediation=finding_dict.get('remediation', []),
                    created_at=finding_dict.get('created_at', '')
                )
                normalized_for_enrichment.append(normalized_finding)
            
            # Enrich findings
            enriched_findings = asyncio.run(enrichment.enrich_findings(normalized_for_enrichment, job.job_id))
            
            # Convert enriched findings back to dict
            job.findings = [self._convert_enriched_finding_to_dict(f) for f in enriched_findings]
            
        except Exception as e:
            print(f"Error enriching findings: {e}")
            job.findings = all_findings
        
        # Save raw outputs
        raw_outputs = {
            "http_response": os.path.join(job_dir, 'raw', 'http_response.json'),
            "headers_analysis": os.path.join(job_dir, 'raw', 'headers_analysis.json'),
            "body_analysis": os.path.join(job_dir, 'raw', 'body_analysis.json'),
            "technology_stack": os.path.join(job_dir, 'raw', 'technology_stack.json'),
            "discovered_paths": os.path.join(job_dir, 'raw', 'discovered_paths.json'),
            "findings": os.path.join(job_dir, 'raw', 'findings.json')
        }
        
        # Add tool outputs
        for tool_name, output in tool_outputs.items():
            if output.output_file:
                raw_outputs[f"{tool_name}_output"] = output.output_file
        
        # Save scan results
        self._save_scan_results(scan_result, raw_outputs)
        job.raw_outputs = raw_outputs
        
        # Generate report
        job.stage = "generating-report"
        job.progress = 90
        report_path = self._generate_report(job, scan_result)
        job.report_path = report_path
    
    def _run_enhanced_scan(self, job: ScanJob, scan_engine, job_dir: str):
        """Run enhanced scan profile"""
        # For now, use fast scan as base
        # TODO: Implement enhanced scan with more tools
        self._run_fast_scan(job, scan_engine, job_dir)
    
    def _run_deep_scan(self, job: ScanJob, scan_engine, job_dir: str):
        """Run deep scan profile"""
        # For now, use fast scan as base
        # TODO: Implement deep scan with aggressive tools
        self._run_fast_scan(job, scan_engine, job_dir)
    
    def _save_scan_results(self, scan_result, raw_outputs: Dict[str, str]):
        """Save scan results to files"""
        try:
            # Save HTTP response
            with open(raw_outputs["http_response"], 'w', encoding='utf-8') as f:
                json.dump(scan_result.http_response, f, indent=2, default=str)
            
            # Save headers analysis
            with open(raw_outputs["headers_analysis"], 'w', encoding='utf-8') as f:
                json.dump(scan_result.headers_analysis, f, indent=2, default=str)
            
            # Save body analysis
            with open(raw_outputs["body_analysis"], 'w', encoding='utf-8') as f:
                json.dump(scan_result.body_analysis, f, indent=2, default=str)
            
            # Save technology stack
            with open(raw_outputs["technology_stack"], 'w', encoding='utf-8') as f:
                json.dump(scan_result.technology_stack, f, indent=2, default=str)
            
            # Save discovered paths
            with open(raw_outputs["discovered_paths"], 'w', encoding='utf-8') as f:
                json.dump(scan_result.discovered_paths, f, indent=2, default=str)
            
            # Save findings
            findings_data = [self._convert_finding_to_dict(f) for f in scan_result.findings]
            with open(raw_outputs["findings"], 'w', encoding='utf-8') as f:
                json.dump(findings_data, f, indent=2, default=str)
                
        except Exception as e:
            print(f"Error saving scan results: {e}")
    
    def _convert_finding_to_dict(self, finding) -> Dict[str, Any]:
        """Convert ScanFinding to dictionary"""
        return {
            "id": f"f-{hash(finding.path + finding.type) % 10000}",
            "type": finding.type,
            "severity": finding.severity,
            "path": finding.path,
            "parameter": finding.parameter,
            "evidence": finding.evidence,
            "description": finding.description,
            "cwe": finding.cwe,
            "confidence": finding.confidence,
            "tool": "enhanced_scan_engine",
            "cvss_v3": None,
            "safe_poc_steps": [],
            "remediation": [],
            "created_at": ""
        }
    
    def _convert_normalized_finding_to_dict(self, finding) -> Dict[str, Any]:
        """Convert NormalizedFinding to dictionary"""
        return {
            "id": finding.id,
            "type": finding.type,
            "severity": finding.severity,
            "path": finding.path,
            "parameter": finding.parameter,
            "evidence": finding.evidence_snippet,
            "description": finding.type,
            "cwe": None,
            "confidence": finding.confidence,
            "tool": finding.tool,
            "cvss_v3": finding.cvss_v3,
            "safe_poc_steps": finding.safe_poc_steps,
            "remediation": finding.remediation,
            "created_at": finding.created_at
        }
    
    def _convert_enriched_finding_to_dict(self, finding) -> Dict[str, Any]:
        """Convert EnrichedFinding to dictionary"""
        return {
            "id": finding.id,
            "type": finding.type,
            "severity": finding.severity,
            "path": "",  # Will be filled from original finding
            "parameter": None,  # Will be filled from original finding
            "evidence": finding.raw_evidence,
            "description": finding.short_summary,
            "cwe": None,
            "confidence": finding.confidence,
            "tool": "llm_enriched",
            "cvss_v3": finding.cvss_v3,
            "safe_poc_steps": finding.safe_poc_steps,
            "remediation": finding.remediation,
            "created_at": "",
            "justification": finding.justification,
            "references": finding.references,
            "rag_context": finding.rag_context
        }
    
    def _generate_report(self, job: ScanJob, scan_result) -> str:
        """Generate comprehensive report"""
        report_path = os.path.join(self.reports_dir, job.job_id, 'report.json')
        
        report_data = {
            "metadata": {
                "job_id": job.job_id,
                "user_id": job.user_id,
                "target_url": job.target_url,
                "profile": job.profile.value,
                "created_at": job.created_at.isoformat(),
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                "scan_duration": (job.finished_at - job.started_at).total_seconds() if job.finished_at and job.started_at else None
            },
            "http_summary": {
                "status_code": scan_result.http_response.get("status_code"),
                "server": scan_result.http_response.get("headers", {}).get("Server"),
                "content_type": scan_result.http_response.get("headers", {}).get("Content-Type"),
                "response_time": scan_result.http_response.get("elapsed"),
                "content_length": len(scan_result.http_response.get("content", ""))
            },
            "security_headers": scan_result.headers_analysis,
            "technology_stack": scan_result.technology_stack,
            "discovered_paths": scan_result.discovered_paths,
            "findings": [self._convert_finding_to_dict(f) for f in scan_result.findings],
            "security_score": scan_result.security_score,
            "raw_outputs": job.raw_outputs
        }
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
        except Exception as e:
            print(f"Error generating report: {e}")
        
        return report_path
    
    def list_jobs(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List jobs, optionally filtered by user"""
        jobs = []
        for job in self.jobs.values():
            if user_id is None or job.user_id == user_id:
                jobs.append({
                    "job_id": job.job_id,
                    "user_id": job.user_id,
                    "target_url": job.target_url,
                    "profile": job.profile.value,
                    "status": job.status.value,
                    "stage": job.stage,
                    "progress": job.progress,
                    "created_at": job.created_at.isoformat(),
                    "started_at": job.started_at.isoformat() if job.started_at else None,
                    "finished_at": job.finished_at.isoformat() if job.finished_at else None
                })
        
        return sorted(jobs, key=lambda x: x["created_at"], reverse=True)
    
    def cleanup_old_jobs(self, days: int = 7):
        """Clean up old completed jobs"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        jobs_to_remove = []
        for job_id, job in self.jobs.items():
            if (job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED] 
                and job.created_at < cutoff_date):
                jobs_to_remove.append(job_id)
        
        for job_id in jobs_to_remove:
            # Remove job directory
            job_dir = os.path.join(self.reports_dir, job_id)
            if os.path.exists(job_dir):
                import shutil
                try:
                    shutil.rmtree(job_dir)
                except Exception as e:
                    print(f"Error removing job directory {job_dir}: {e}")
            
            # Remove job from memory
            del self.jobs[job_id]
        
        return len(jobs_to_remove)
