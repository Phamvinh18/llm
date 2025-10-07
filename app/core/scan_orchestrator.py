"""
Scan Orchestrator - Quản lý pipeline scan chuyên nghiệp với tools thực tế
"""

import asyncio
import json
import time
import uuid
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import subprocess
import os
from urllib.parse import urlparse
import requests

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanStage(Enum):
    VALIDATION = "validation"
    RECON = "reconnaissance"
    CRAWL = "crawl"
    FUZZ = "fuzz"
    VULN_SCAN = "vulnerability_scan"
    AGGREGATION = "aggregation"
    LLM_ENRICHMENT = "llm_enrichment"
    COMPLETED = "completed"

@dataclass
class ScanJob:
    job_id: str
    target_url: str
    status: ScanStatus
    current_stage: ScanStage
    progress: int  # 0-100
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    findings: List[Dict[str, Any]] = None
    summary: Optional[str] = None
    report_url: Optional[str] = None
    raw_outputs: Dict[str, Any] = None

@dataclass
class ScanFinding:
    id: str
    type: str
    path: str
    param: Optional[str]
    evidence: str
    tool: str
    severity: str
    poc: str
    remediation: str
    confidence: float

class ScanOrchestrator:
    """Orchestrator quản lý pipeline scan chuyên nghiệp"""
    
    def __init__(self):
        self.active_jobs: Dict[str, ScanJob] = {}
        self.allowlist = self._load_allowlist()
        self.scan_tools = ScanTools()
        self.result_aggregator = ResultAggregator()
        self.llm_enricher = LLMEnricher()
        
    def _load_allowlist(self) -> List[str]:
        """Load allowlist từ file"""
        try:
            with open('app/data/whitelist.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('allowed_targets', [])
        except:
            return ['testphp.vulnweb.com', 'demo.testfire.net', 'localhost']
    
    async def start_scan(self, target_url: str, user_id: str = "default") -> Dict[str, Any]:
        """Bắt đầu scan job"""
        try:
            # 1. Validation
            validation_result = await self._validate_target(target_url)
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error': validation_result['error'],
                    'job_id': None
                }
            
            # 2. Tạo job
            job_id = f"job_{uuid.uuid4().hex[:8]}"
            job = ScanJob(
                job_id=job_id,
                target_url=target_url,
                status=ScanStatus.PENDING,
                current_stage=ScanStage.VALIDATION,
                progress=0,
                created_at=time.strftime('%Y-%m-%d %H:%M:%S'),
                findings=[],
                raw_outputs={}
            )
            
            self.active_jobs[job_id] = job
            
            # 3. Start scan pipeline (async)
            asyncio.create_task(self._run_scan_pipeline(job_id))
            
            return {
                'success': True,
                'job_id': job_id,
                'message': f"Scan job đã được tạo. Job ID: {job_id}",
                'estimated_time': "5-10 phút"
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Lỗi tạo scan job: {str(e)}",
                'job_id': None
            }
    
    async def _validate_target(self, target_url: str) -> Dict[str, Any]:
        """Validate target URL"""
        try:
            # Parse URL
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                return {'valid': False, 'error': 'URL không hợp lệ'}
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                return {'valid': False, 'error': 'Chỉ hỗ trợ HTTP/HTTPS'}
            
            # Check allowlist
            domain = parsed.netloc.lower()
            if not any(allowed in domain for allowed in self.allowlist):
                return {'valid': False, 'error': f'Domain {domain} không có trong allowlist'}
            
            # Check if target is reachable
            try:
                response = requests.head(target_url, timeout=10, allow_redirects=True)
                if response.status_code >= 400:
                    return {'valid': False, 'error': f'Target không thể truy cập (Status: {response.status_code})'}
            except:
                return {'valid': False, 'error': 'Target không thể truy cập'}
            
            return {'valid': True, 'error': None}
            
        except Exception as e:
            return {'valid': False, 'error': f'Lỗi validation: {str(e)}'}
    
    async def _run_scan_pipeline(self, job_id: str):
        """Chạy pipeline scan"""
        try:
            job = self.active_jobs[job_id]
            job.status = ScanStatus.RUNNING
            job.started_at = time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Stage 1: Reconnaissance
            await self._update_job_progress(job_id, ScanStage.RECON, 10)
            recon_results = await self.scan_tools.run_reconnaissance(job.target_url)
            job.raw_outputs['recon'] = recon_results
            
            # Stage 2: Crawl
            await self._update_job_progress(job_id, ScanStage.CRAWL, 25)
            crawl_results = await self.scan_tools.run_crawl(job.target_url)
            job.raw_outputs['crawl'] = crawl_results
            
            # Stage 3: Directory Fuzzing
            await self._update_job_progress(job_id, ScanStage.FUZZ, 40)
            fuzz_results = await self.scan_tools.run_directory_fuzzing(job.target_url)
            job.raw_outputs['fuzz'] = fuzz_results
            
            # Stage 4: Vulnerability Scanning
            await self._update_job_progress(job_id, ScanStage.VULN_SCAN, 60)
            vuln_results = await self.scan_tools.run_vulnerability_scan(job.target_url)
            job.raw_outputs['vulnerability_scan'] = vuln_results
            
            # Stage 5: Aggregation
            await self._update_job_progress(job_id, ScanStage.AGGREGATION, 80)
            findings = await self.result_aggregator.aggregate_results(job.raw_outputs, job.target_url)
            job.findings = findings
            
            # Stage 6: LLM Enrichment
            await self._update_job_progress(job_id, ScanStage.LLM_ENRICHMENT, 90)
            enriched_results = await self.llm_enricher.enrich_findings(findings, job.target_url)
            job.summary = enriched_results['summary']
            job.findings = enriched_results['findings']
            
            # Complete
            await self._update_job_progress(job_id, ScanStage.COMPLETED, 100)
            job.status = ScanStatus.COMPLETED
            job.completed_at = time.strftime('%Y-%m-%d %H:%M:%S')
            
        except Exception as e:
            job = self.active_jobs[job_id]
            job.status = ScanStatus.FAILED
            job.error_message = str(e)
            job.completed_at = time.strftime('%Y-%m-%d %H:%M:%S')
    
    async def _update_job_progress(self, job_id: str, stage: ScanStage, progress: int):
        """Update job progress"""
        if job_id in self.active_jobs:
            job = self.active_jobs[job_id]
            job.current_stage = stage
            job.progress = progress
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status"""
        if job_id not in self.active_jobs:
            return None
        
        job = self.active_jobs[job_id]
        return {
            'job_id': job.job_id,
            'target_url': job.target_url,
            'status': job.status.value,
            'current_stage': job.current_stage.value,
            'progress': job.progress,
            'created_at': job.created_at,
            'started_at': job.started_at,
            'completed_at': job.completed_at,
            'error_message': job.error_message,
            'summary': job.summary,
            'findings_count': len(job.findings) if job.findings else 0
        }
    
    def get_job_results(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get complete job results"""
        if job_id not in self.active_jobs:
            return None
        
        job = self.active_jobs[job_id]
        if job.status != ScanStatus.COMPLETED:
            return None
        
        return {
            'job_id': job.job_id,
            'target_url': job.target_url,
            'summary': job.summary,
            'findings': [asdict(finding) if hasattr(finding, '__dataclass_fields__') else finding for finding in job.findings],
            'raw_outputs': job.raw_outputs,
            'scan_duration': self._calculate_duration(job.started_at, job.completed_at),
            'report_url': job.report_url
        }
    
    def _calculate_duration(self, started: str, completed: str) -> str:
        """Calculate scan duration"""
        try:
            start_time = time.strptime(started, '%Y-%m-%d %H:%M:%S')
            end_time = time.strptime(completed, '%Y-%m-%d %H:%M:%S')
            duration = time.mktime(end_time) - time.mktime(start_time)
            return f"{int(duration // 60)}m {int(duration % 60)}s"
        except:
            return "Unknown"

class ScanTools:
    """Container cho các security tools"""
    
    def __init__(self):
        from app.core.security_tools import SecurityToolsManager
        self.tools_manager = SecurityToolsManager()
        self.tools_available = self.tools_manager.get_available_tools()
    
    async def run_reconnaissance(self, target_url: str) -> Dict[str, Any]:
        """Chạy reconnaissance"""
        return self.tools_manager.run_reconnaissance(target_url)
    
    async def run_crawl(self, target_url: str) -> Dict[str, Any]:
        """Chạy crawling"""
        return self.tools_manager.run_crawling(target_url)
    
    async def run_directory_fuzzing(self, target_url: str) -> Dict[str, Any]:
        """Chạy directory fuzzing"""
        return self.tools_manager.run_directory_fuzzing(target_url)
    
    async def run_vulnerability_scan(self, target_url: str) -> Dict[str, Any]:
        """Chạy vulnerability scanning"""
        return self.tools_manager.run_vulnerability_scanning(target_url)

class ResultAggregator:
    """Aggregate và normalize kết quả từ các tools"""
    
    def __init__(self):
        self.finding_id_counter = 1
    
    async def aggregate_results(self, raw_outputs: Dict[str, Any], target_url: str) -> List[ScanFinding]:
        """Aggregate results từ tất cả tools"""
        findings = []
        
        # Parse nuclei results
        if 'vulnerability_scan' in raw_outputs and 'nuclei' in raw_outputs['vulnerability_scan']:
            nuclei_results = raw_outputs['vulnerability_scan']['nuclei']
            if nuclei_results.get('success') and nuclei_results.get('findings'):
                for finding in nuclei_results['findings']:
                    findings.append(self._parse_nuclei_finding(finding))
        
        # Parse dalfox results
        if 'vulnerability_scan' in raw_outputs and 'dalfox' in raw_outputs['vulnerability_scan']:
            dalfox_results = raw_outputs['vulnerability_scan']['dalfox']
            if dalfox_results.get('success') and dalfox_results.get('findings'):
                for finding in dalfox_results['findings']:
                    findings.append(self._parse_dalfox_finding(finding))
        
        # Parse nikto results
        if 'vulnerability_scan' in raw_outputs and 'nikto' in raw_outputs['vulnerability_scan']:
            nikto_results = raw_outputs['vulnerability_scan']['nikto']
            if nikto_results.get('success') and nikto_results.get('output'):
                findings.extend(self._parse_nikto_results(nikto_results['output']))
        
        # Parse ffuf results
        if 'fuzz' in raw_outputs and 'ffuf' in raw_outputs['fuzz']:
            ffuf_results = raw_outputs['fuzz']['ffuf']
            if ffuf_results.get('success') and ffuf_results.get('results'):
                findings.extend(self._parse_ffuf_results(ffuf_results['results']))
        
        # Parse basic fuzz results
        if 'fuzz' in raw_outputs and 'basic_fuzz' in raw_outputs['fuzz']:
            basic_fuzz_results = raw_outputs['fuzz']['basic_fuzz']
            if basic_fuzz_results.get('success') and basic_fuzz_results.get('results'):
                findings.extend(self._parse_basic_fuzz_results(basic_fuzz_results['results']))
        
        return findings
    
    def _parse_nuclei_finding(self, finding: Dict[str, Any]) -> ScanFinding:
        """Parse nuclei finding"""
        self.finding_id_counter += 1
        return ScanFinding(
            id=f"f{self.finding_id_counter}",
            type=finding.get('info', {}).get('name', 'Unknown'),
            path=finding.get('matched-at', ''),
            param=None,
            evidence=finding.get('request', ''),
            tool='nuclei',
            severity=self._map_nuclei_severity(finding.get('info', {}).get('severity', 'info')),
            poc=f"1) Visit {finding.get('matched-at', '')}\n2) Tool: nuclei\n3) Template: {finding.get('template-id', '')}",
            remediation="Xem chi tiết trong nuclei template",
            confidence=0.8
        )
    
    def _parse_dalfox_finding(self, finding: Dict[str, Any]) -> ScanFinding:
        """Parse dalfox finding"""
        self.finding_id_counter += 1
        return ScanFinding(
            id=f"f{self.finding_id_counter}",
            type='XSS',
            path=finding.get('url', ''),
            param=finding.get('param', ''),
            evidence=finding.get('payload', ''),
            tool='dalfox',
            severity='High',
            poc=f"1) Visit {finding.get('url', '')}\n2) Parameter: {finding.get('param', '')}\n3) Payload: {finding.get('payload', '')}",
            remediation="Implement proper input validation and output encoding",
            confidence=0.9
        )
    
    def _parse_nikto_results(self, output: str) -> List[ScanFinding]:
        """Parse nikto results"""
        findings = []
        lines = output.split('\n')
        
        for line in lines:
            if 'OSVDB-' in line or 'CVE-' in line:
                self.finding_id_counter += 1
                findings.append(ScanFinding(
                    id=f"f{self.finding_id_counter}",
                    type='Information Disclosure',
                    path='',
                    param=None,
                    evidence=line.strip(),
                    tool='nikto',
                    severity='Medium',
                    poc=f"1) Run nikto scan\n2) Check output\n3) Tool: nikto",
                    remediation="Review and secure server configuration",
                    confidence=0.7
                ))
        
        return findings
    
    def _parse_ffuf_results(self, results: List[Dict[str, Any]]) -> List[ScanFinding]:
        """Parse ffuf results"""
        findings = []
        for result in results:
            if result.get('status') in [200, 301, 302, 403]:
                self.finding_id_counter += 1
                findings.append(ScanFinding(
                    id=f"f{self.finding_id_counter}",
                    type='Directory/File Discovery',
                    path=result.get('url', ''),
                    param=None,
                    evidence=f"Status: {result.get('status')}, Size: {result.get('length')}",
                    tool='ffuf',
                    severity='Low',
                    poc=f"1) Visit {result.get('url', '')}\n2) Check response\n3) Tool: ffuf",
                    remediation="Review discovered paths and remove unnecessary files",
                    confidence=0.9
                ))
        return findings
    
    def _parse_basic_fuzz_results(self, results: List[Dict[str, Any]]) -> List[ScanFinding]:
        """Parse basic fuzz results"""
        findings = []
        for result in results:
            if result.get('status') in [200, 301, 302, 403]:
                self.finding_id_counter += 1
                findings.append(ScanFinding(
                    id=f"f{self.finding_id_counter}",
                    type='Directory/File Discovery',
                    path=result.get('url', ''),
                    param=None,
                    evidence=f"Status: {result.get('status')}, Length: {result.get('length')}",
                    tool='basic_fuzz',
                    severity='Low',
                    poc=f"1) Visit {result.get('url', '')}\n2) Check response\n3) Tool: basic HTTP requests",
                    remediation="Review discovered paths and remove unnecessary files",
                    confidence=0.8
                ))
        return findings
    
    def _map_nuclei_severity(self, severity: str) -> str:
        """Map nuclei severity to standard severity"""
        mapping = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Info'
        }
        return mapping.get(severity.lower(), 'Medium')

class LLMEnricher:
    """LLM enrichment cho findings"""
    
    def __init__(self):
        from app.clients.gemini_client import GeminiClient
        self.llm_client = GeminiClient()
        self.rag_retriever = self._init_rag_retriever()
    
    def _init_rag_retriever(self):
        """Initialize RAG retriever"""
        try:
            from app.core.kb_retriever import AdvancedKBRetriever
            return AdvancedKBRetriever()
        except:
            return None
    
    async def enrich_findings(self, findings: List[ScanFinding], target_url: str) -> Dict[str, Any]:
        """Enrich findings với LLM và RAG"""
        try:
            # Prepare findings data
            findings_data = []
            for finding in findings:
                findings_data.append({
                    'id': finding.id,
                    'type': finding.type,
                    'path': finding.path,
                    'param': finding.param,
                    'evidence': finding.evidence,
                    'tool': finding.tool,
                    'severity': finding.severity,
                    'poc': finding.poc,
                    'remediation': finding.remediation,
                    'confidence': finding.confidence
                })
            
            # Get RAG context
            rag_context = ""
            if self.rag_retriever:
                try:
                    rag_docs = self.rag_retriever.retrieve("vulnerability remediation", k=5)
                    if rag_docs:
                        rag_context = "\n".join([doc.content for doc in rag_docs[:3]])
                except:
                    pass
            
            # Create LLM prompt
            prompt = f"""
            Bạn là chuyên gia bảo mật web. Hãy phân tích kết quả scan và tạo báo cáo chuyên nghiệp.
            
            Target: {target_url}
            Findings: {json.dumps(findings_data, ensure_ascii=False, indent=2)}
            
            RAG Context (Remediation Knowledge):
            {rag_context}
            
            Hãy tạo:
            1. Executive Summary (2-3 câu tóm tắt)
            2. Cải thiện severity assessment cho từng finding
            3. Tạo PoC chi tiết và an toàn
            4. Cải thiện remediation steps với code examples
            5. Top 5 actions cần thực hiện ngay
            
            Trả về JSON format:
            {{
                "summary": "Executive summary",
                "findings": [
                    {{
                        "id": "f1",
                        "type": "XSS",
                        "path": "/path",
                        "param": "param",
                        "evidence": "evidence",
                        "tool": "tool",
                        "severity": "High",
                        "poc": "Detailed PoC steps",
                        "remediation": "Detailed remediation with code examples",
                        "confidence": 0.9
                    }}
                ],
                "actions": [
                    "Action 1",
                    "Action 2"
                ]
            }}
            """
            
            # Get LLM response
            llm_response = self.llm_client.chat(prompt, max_output_tokens=2000)
            
            try:
                # Try to parse JSON response
                enriched_data = json.loads(llm_response)
                return enriched_data
            except:
                # Fallback if JSON parsing fails
                return {
                    'summary': llm_response[:500] + "..." if len(llm_response) > 500 else llm_response,
                    'findings': findings_data,
                    'actions': [
                        "Review all findings manually",
                        "Implement security headers",
                        "Fix input validation issues",
                        "Update server configuration",
                        "Conduct penetration testing"
                    ]
                }
                
        except Exception as e:
            return {
                'summary': f"Scan completed with {len(findings)} findings. LLM enrichment failed: {str(e)}",
                'findings': [asdict(finding) for finding in findings],
                'actions': [
                    "Review findings manually",
                    "Implement security best practices",
                    "Conduct additional testing"
                ]
            }
