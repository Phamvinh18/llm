"""
Scan Orchestrator - Quản lý scan jobs và tool execution pipeline
"""

import asyncio
import json
import os
import time
import uuid
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import subprocess
import requests
from pathlib import Path

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
    CONFIRMATION = "confirmation"
    RAG_ENRICHMENT = "rag_enrichment"
    COMPLETED = "completed"

@dataclass
class ScanJob:
    job_id: str
    target_url: str
    status: ScanStatus
    current_stage: ScanStage
    progress: int
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    findings: List[Dict[str, Any]] = None
    raw_outputs: Dict[str, str] = None
    evidence_dir: Optional[str] = None

@dataclass
class ToolResult:
    tool_name: str
    command: str
    output_file: str
    exit_code: int
    duration: float
    findings_count: int
    error_message: Optional[str] = None

class ScanOrchestrator:
    """Orchestrator quản lý scan pipeline với evidence storage"""
    
    def __init__(self):
        self.active_jobs: Dict[str, ScanJob] = {}
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        self.allowlist = self._load_allowlist()
        
    def _load_allowlist(self) -> List[str]:
        """Load allowlist for safe targets"""
        try:
            with open('app/data/whitelist.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('allowed_targets', [])
        except:
            return ['testphp.vulnweb.com', 'demo.testfire.net', 'localhost', 'httpbin.org']
    
    async def start_scan(self, target_url: str) -> Dict[str, Any]:
        """Start a new scan job"""
        try:
            # Validate target
            if not self._is_target_allowed(target_url):
                return {
                    "success": False,
                    "error": f"Target {target_url} not in allowlist"
                }
            
            # Create job
            job_id = f"job_{uuid.uuid4().hex[:8]}"
            evidence_dir = self.reports_dir / job_id / "raw"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            
            job = ScanJob(
                job_id=job_id,
                target_url=target_url,
                status=ScanStatus.PENDING,
                current_stage=ScanStage.VALIDATION,
                progress=0,
                created_at=time.strftime('%Y-%m-%d %H:%M:%S'),
                evidence_dir=str(evidence_dir),
                raw_outputs={},
                findings=[]
            )
            
            self.active_jobs[job_id] = job
            
            # Start scan pipeline in background
            asyncio.create_task(self._run_scan_pipeline(job))
            
            return {
                "success": True,
                "job_id": job_id,
                "message": f"Scan started for {target_url}",
                "estimated_time": "5-10 minutes",
                "evidence_dir": str(evidence_dir)
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _is_target_allowed(self, target_url: str) -> bool:
        """Check if target is in allowlist"""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target_url)
            domain = parsed.netloc.lower()
            return any(allowed in domain for allowed in self.allowlist)
        except:
            return False
    
    async def _run_scan_pipeline(self, job: ScanJob):
        """Run the complete scan pipeline"""
        try:
            job.status = ScanStatus.RUNNING
            job.started_at = time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Stage 1: Reconnaissance
            job.current_stage = ScanStage.RECON
            job.progress = 10
            recon_results = await self._run_reconnaissance(job)
            
            # Stage 2: Crawling
            job.current_stage = ScanStage.CRAWL
            job.progress = 30
            crawl_results = await self._run_crawling(job)
            
            # Stage 3: Fuzzing
            job.current_stage = ScanStage.FUZZ
            job.progress = 50
            fuzz_results = await self._run_fuzzing(job)
            
            # Stage 4: Vulnerability Scanning
            job.current_stage = ScanStage.VULN_SCAN
            job.progress = 70
            vuln_results = await self._run_vulnerability_scan(job)
            
            # Stage 5: Confirmatory Tests
            job.current_stage = ScanStage.CONFIRMATION
            job.progress = 85
            confirmation_results = await self._run_confirmatory_tests(job)
            
            # Stage 6: RAG Enrichment
            job.current_stage = ScanStage.RAG_ENRICHMENT
            job.progress = 95
            enriched_findings = await self._run_rag_enrichment(job)
            
            # Complete
            job.current_stage = ScanStage.COMPLETED
            job.progress = 100
            job.status = ScanStatus.COMPLETED
            job.completed_at = time.strftime('%Y-%m-%d %H:%M:%S')
            job.findings = enriched_findings
            
        except Exception as e:
            job.status = ScanStatus.FAILED
            job.error_message = str(e)
            print(f"Scan pipeline failed for {job.job_id}: {e}")
    
    async def _run_reconnaissance(self, job: ScanJob) -> Dict[str, Any]:
        """Run reconnaissance tools"""
        results = {}
        evidence_dir = Path(job.evidence_dir)
        
        # HTTPX - Basic HTTP analysis
        httpx_result = await self._run_tool(
            f"httpx -timeout 30 -silent -json -o {evidence_dir}/httpx.json {job.target_url}",
            "httpx",
            evidence_dir / "httpx.json"
        )
        results["httpx"] = httpx_result
        
        # WhatWeb - Technology detection
        whatweb_result = await self._run_tool(
            f"whatweb -a 3 {job.target_url} -o {evidence_dir}/whatweb.json",
            "whatweb",
            evidence_dir / "whatweb.json"
        )
        results["whatweb"] = whatweb_result
        
        return results
    
    async def _run_crawling(self, job: ScanJob) -> Dict[str, Any]:
        """Run crawling tools"""
        results = {}
        evidence_dir = Path(job.evidence_dir)
        
        # GoSpider - Fast crawling
        gospider_result = await self._run_tool(
            f"gospider -s {job.target_url} -o {evidence_dir}/gospider.json -t 10",
            "gospider",
            evidence_dir / "gospider.json"
        )
        results["gospider"] = gospider_result
        
        return results
    
    async def _run_fuzzing(self, job: ScanJob) -> Dict[str, Any]:
        """Run fuzzing tools"""
        results = {}
        evidence_dir = Path(job.evidence_dir)
        
        # FFUF - Directory fuzzing
        ffuf_result = await self._run_tool(
            f"ffuf -u {job.target_url}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o {evidence_dir}/ffuf.json -mc 200,301,302 -json",
            "ffuf",
            evidence_dir / "ffuf.json"
        )
        results["ffuf"] = ffuf_result
        
        return results
    
    async def _run_vulnerability_scan(self, job: ScanJob) -> Dict[str, Any]:
        """Run vulnerability scanning tools"""
        results = {}
        evidence_dir = Path(job.evidence_dir)
        
        # Nuclei - Template-based scanning
        nuclei_result = await self._run_tool(
            f"nuclei -u {job.target_url} -t /nuclei-templates/ -json -o {evidence_dir}/nuclei.json",
            "nuclei",
            evidence_dir / "nuclei.json"
        )
        results["nuclei"] = nuclei_result
        
        # Dalfox - XSS scanning
        dalfox_result = await self._run_tool(
            f"dalfox url {job.target_url} --basic-payloads -o {evidence_dir}/dalfox.json --format json",
            "dalfox",
            evidence_dir / "dalfox.json"
        )
        results["dalfox"] = dalfox_result
        
        # Nikto - Web server scanning
        nikto_result = await self._run_tool(
            f"nikto -h {job.target_url} -Format json -output {evidence_dir}/nikto.json",
            "nikto",
            evidence_dir / "nikto.json"
        )
        results["nikto"] = nikto_result
        
        return results
    
    async def _run_confirmatory_tests(self, job: ScanJob) -> Dict[str, Any]:
        """Run confirmatory tests to reduce false positives"""
        results = {}
        evidence_dir = Path(job.evidence_dir)
        
        # Run marker reflection tests for each finding
        findings = self._parse_all_findings(job)
        for finding in findings:
            if finding.get('type') == 'XSS':
                confirm_result = await self._test_marker_reflection(
                    job.target_url, 
                    finding.get('path', ''), 
                    finding.get('param', ''),
                    evidence_dir
                )
                finding['confirmatory_tests'] = confirm_result
        
        return results
    
    async def _run_rag_enrichment(self, job: ScanJob) -> List[Dict[str, Any]]:
        """Run RAG enrichment on findings"""
        try:
            from app.core.enhanced_rag_retriever import EnhancedRAGRetriever
            from app.clients.gemini_client import GeminiClient
            
            rag_retriever = EnhancedRAGRetriever()
            llm_client = GeminiClient()
            
            findings = self._parse_all_findings(job)
            enriched_findings = []
            
            for finding in findings:
                # Get RAG context
                rag_context = self._get_rag_context_for_finding(finding, rag_retriever)
                
                # Enrich with LLM
                enriched_finding = await self._enrich_finding_with_llm(
                    finding, rag_context, llm_client
                )
                
                enriched_findings.append(enriched_finding)
            
            return enriched_findings
            
        except Exception as e:
            print(f"RAG enrichment error: {e}")
            return self._parse_all_findings(job)
    
    async def _run_tool(self, command: str, tool_name: str, output_file: Path) -> ToolResult:
        """Run a security tool and capture results"""
        start_time = time.time()
        
        try:
            # Run command in subprocess
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            duration = time.time() - start_time
            
            # Save output
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(stdout.decode('utf-8', errors='ignore'))
            
            # Parse findings count
            findings_count = self._count_findings_in_output(stdout.decode('utf-8', errors='ignore'))
            
            return ToolResult(
                tool_name=tool_name,
                command=command,
                output_file=str(output_file),
                exit_code=process.returncode,
                duration=duration,
                findings_count=findings_count,
                error_message=stderr.decode('utf-8', errors='ignore') if stderr else None
            )
            
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                command=command,
                output_file=str(output_file),
                exit_code=-1,
                duration=time.time() - start_time,
                findings_count=0,
                error_message=str(e)
            )
    
    def _count_findings_in_output(self, output: str) -> int:
        """Count findings in tool output"""
        try:
            # Simple heuristic - count JSON objects or specific patterns
            if 'nuclei' in output.lower():
                return output.count('"info"')
            elif 'dalfox' in output.lower():
                return output.count('"payload"')
            elif 'nikto' in output.lower():
                return output.count('"vulnerability"')
            else:
                return output.count('"finding"') + output.count('"vulnerability"')
        except:
            return 0
    
    def _parse_all_findings(self, job: ScanJob) -> List[Dict[str, Any]]:
        """Parse findings from all tool outputs"""
        findings = []
        evidence_dir = Path(job.evidence_dir)
        
        # Parse each tool output
        for tool_file in evidence_dir.glob("*.json"):
            tool_findings = self._parse_tool_output(tool_file, job.target_url)
            findings.extend(tool_findings)
        
        return findings
    
    def _parse_tool_output(self, output_file: Path, target_url: str) -> List[Dict[str, Any]]:
        """Parse individual tool output"""
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tool_name = output_file.stem
            
            if tool_name == "nuclei":
                return self._parse_nuclei_output(content, target_url, str(output_file))
            elif tool_name == "dalfox":
                return self._parse_dalfox_output(content, target_url, str(output_file))
            elif tool_name == "nikto":
                return self._parse_nikto_output(content, target_url, str(output_file))
            else:
                return []
                
        except Exception as e:
            print(f"Error parsing {output_file}: {e}")
            return []
    
    def _parse_nuclei_output(self, content: str, target_url: str, output_file: str) -> List[Dict[str, Any]]:
        """Parse Nuclei output"""
        findings = []
        try:
            lines = content.strip().split('\n')
            for line in lines:
                if line.strip():
                    data = json.loads(line)
                    finding = {
                        "id": f"f-{len(findings)+1:03d}",
                        "job_id": "temp",
                        "target": target_url,
                        "type": data.get("info", {}).get("name", "Unknown"),
                        "path": data.get("matched-at", ""),
                        "param": "",
                        "tool": "nuclei",
                        "severity": None,
                        "confidence": None,
                        "cvss_v3": None,
                        "exploitability_score": None,
                        "evidence_snippet": data.get("request", "")[:500],
                        "raw_outputs": [output_file],
                        "request_response": "",
                        "screenshot": "",
                        "confirmatory_tests": [],
                        "related_domains": [],
                        "exploit_vectors": [],
                        "remediation_suggestions": [],
                        "created_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')
                    }
                    findings.append(finding)
        except Exception as e:
            print(f"Error parsing nuclei output: {e}")
        
        return findings
    
    def _parse_dalfox_output(self, content: str, target_url: str, output_file: str) -> List[Dict[str, Any]]:
        """Parse Dalfox output"""
        findings = []
        try:
            data = json.loads(content)
            for item in data:
                finding = {
                    "id": f"f-{len(findings)+1:03d}",
                    "job_id": "temp",
                    "target": target_url,
                    "type": "XSS-Reflected",
                    "path": item.get("url", ""),
                    "param": item.get("param", ""),
                    "tool": "dalfox",
                    "severity": None,
                    "confidence": None,
                    "cvss_v3": None,
                    "exploitability_score": None,
                    "evidence_snippet": item.get("payload", ""),
                    "raw_outputs": [output_file],
                    "request_response": "",
                    "screenshot": "",
                    "confirmatory_tests": [],
                    "related_domains": [],
                    "exploit_vectors": [],
                    "remediation_suggestions": [],
                    "created_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')
                }
                findings.append(finding)
        except Exception as e:
            print(f"Error parsing dalfox output: {e}")
        
        return findings
    
    def _parse_nikto_output(self, content: str, target_url: str, output_file: str) -> List[Dict[str, Any]]:
        """Parse Nikto output"""
        findings = []
        try:
            data = json.loads(content)
            for item in data.get("vulnerabilities", []):
                finding = {
                    "id": f"f-{len(findings)+1:03d}",
                    "job_id": "temp",
                    "target": target_url,
                    "type": "Security-Misconfiguration",
                    "path": item.get("url", ""),
                    "param": "",
                    "tool": "nikto",
                    "severity": None,
                    "confidence": None,
                    "cvss_v3": None,
                    "exploitability_score": None,
                    "evidence_snippet": item.get("description", ""),
                    "raw_outputs": [output_file],
                    "request_response": "",
                    "screenshot": "",
                    "confirmatory_tests": [],
                    "related_domains": [],
                    "exploit_vectors": [],
                    "remediation_suggestions": [],
                    "created_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')
                }
                findings.append(finding)
        except Exception as e:
            print(f"Error parsing nikto output: {e}")
        
        return findings
    
    async def _test_marker_reflection(self, target_url: str, path: str, param: str, evidence_dir: Path) -> List[Dict[str, Any]]:
        """Test marker reflection for XSS findings"""
        try:
            # Generate unique marker
            marker = f"VAWESEC_TEST_{uuid.uuid4().hex[:8]}"
            
            # Test URL
            test_url = f"{target_url}{path}?{param}={marker}"
            
            # Make request
            response = requests.get(test_url, timeout=10)
            
            # Check if marker is reflected
            is_reflected = marker in response.text
            
            # Save evidence
            evidence_file = evidence_dir / f"marker_test_{param}.txt"
            with open(evidence_file, 'w', encoding='utf-8') as f:
                f.write(f"Test URL: {test_url}\n")
                f.write(f"Marker: {marker}\n")
                f.write(f"Reflected: {is_reflected}\n")
                f.write(f"Response: {response.text[:1000]}\n")
            
            return [{
                "name": "marker-reflection",
                "result": "passed" if is_reflected else "failed",
                "output": str(evidence_file),
                "marker": marker,
                "reflected": is_reflected
            }]
            
        except Exception as e:
            return [{
                "name": "marker-reflection",
                "result": "error",
                "output": str(e),
                "marker": "",
                "reflected": False
            }]
    
    def _get_rag_context_for_finding(self, finding: Dict[str, Any], rag_retriever) -> str:
        """Get RAG context for a specific finding"""
        try:
            vuln_type = finding.get('type', '').lower()
            query = f"{vuln_type} vulnerability detection remediation evidence"
            
            docs = rag_retriever.retrieve(query, k=5)
            context_parts = []
            
            for doc in docs:
                content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                context_parts.append(f"Source: {getattr(doc, 'source', 'Unknown')}")
                context_parts.append(f"Content: {content[:300]}...")
                context_parts.append("---")
            
            return "\n".join(context_parts)
            
        except Exception as e:
            return f"RAG context error: {str(e)}"
    
    async def _enrich_finding_with_llm(self, finding: Dict[str, Any], rag_context: str, llm_client) -> Dict[str, Any]:
        """Enrich finding with LLM analysis"""
        try:
            prompt = f"""
            You are a senior web security engineer. Analyze this finding and provide enrichment.
            
            FINDING_JSON: {json.dumps(finding, indent=2)}
            EVIDENCE_SNIPPET: {finding.get('evidence_snippet', '')}
            RAG_CONTEXT: {rag_context}
            
            Task: Produce JSON with keys:
            - id, short_summary, severity (Low/Med/High/Critical), confidence (Low/Med/High), 
            - cvss_v3, exploitability_score (0-100), justification, safe_poc_steps, 
            - remediation, references
            
            Rules:
            1) Use ONLY the provided evidence and RAG context to justify severity and confidence.
            2) Do NOT invent facts. If insufficient evidence, set confidence to Low.
            3) Output strictly valid JSON.
            4) Include source references from RAG context.
            """
            
            llm_response = llm_client.chat(prompt)
            
            # Parse LLM response and merge with original finding
            try:
                enriched_data = json.loads(llm_response)
                finding.update(enriched_data)
            except:
                # Fallback if JSON parsing fails
                finding['llm_analysis'] = llm_response
                finding['severity'] = 'Unknown'
                finding['confidence'] = 'Low'
            
            return finding
            
        except Exception as e:
            print(f"LLM enrichment error: {e}")
            finding['severity'] = 'Unknown'
            finding['confidence'] = 'Low'
            finding['llm_error'] = str(e)
            return finding
    
    def get_scan_status(self, job_id: str) -> Optional[ScanJob]:
        """Get scan job status"""
        return self.active_jobs.get(job_id)
    
    def get_scan_results(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get scan results"""
        job = self.active_jobs.get(job_id)
        if not job:
            return None
        
        return {
            "job_id": job.job_id,
            "target_url": job.target_url,
            "status": job.status.value,
            "current_stage": job.current_stage.value,
            "progress": job.progress,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "findings": job.findings or [],
            "raw_outputs": job.raw_outputs or {},
            "evidence_dir": job.evidence_dir
        }
    
    def cancel_scan(self, job_id: str) -> bool:
        """Cancel a scan job"""
        job = self.active_jobs.get(job_id)
        if job and job.status == ScanStatus.RUNNING:
            job.status = ScanStatus.CANCELLED
            return True
        return False