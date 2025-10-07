"""
Scan Orchestrator - Quản lý pipeline scan chuyên nghiệp
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
    
    
    async def _check_robots_txt(self, target_url: str) -> Dict[str, Any]:
        """Check robots.txt"""
        try:
            import requests
            robots_url = f"{target_url.rstrip('/')}/robots.txt"
            response = requests.get(robots_url, timeout=10)
            
            if response.status_code == 200:
                return {
                    'available': True,
                    'status_code': response.status_code,
                    'content': response.text,
                    'disallowed_paths': self._parse_robots_txt(response.text)
                }
            else:
                return {'available': True, 'status_code': response.status_code}
        except Exception as e:
            return {'available': True, 'error': str(e)}
    
    async def _check_sitemap(self, target_url: str) -> Dict[str, Any]:
        """Check sitemap.xml"""
        try:
            import requests
            sitemap_url = f"{target_url.rstrip('/')}/sitemap.xml"
            response = requests.get(sitemap_url, timeout=10)
            
            if response.status_code == 200:
                return {
                    'available': True,
                    'status_code': response.status_code,
                    'content': response.text,
                    'urls': self._parse_sitemap_xml(response.text)
                }
            else:
                return {'available': True, 'status_code': response.status_code}
        except Exception as e:
            return {'available': True, 'error': str(e)}
    
    async def _check_security_headers(self, target_url: str) -> Dict[str, Any]:
        """Check security headers"""
        try:
            import requests
            response = requests.head(target_url, timeout=10, allow_redirects=True)
            
            security_headers = [
                'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
                'Strict-Transport-Security', 'Content-Security-Policy',
                'Referrer-Policy', 'Permissions-Policy'
            ]
            
            headers_analysis = {}
            for header in security_headers:
                headers_analysis[header] = {
                    'present': header in response.headers,
                    'value': response.headers.get(header, '')
                }
            
            return {
                'available': True,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'security_headers': headers_analysis
            }
        except Exception as e:
            return {'available': True, 'error': str(e)}
    
    async def _run_gospider(self, target_url: str) -> Dict[str, Any]:
        """Run gospider for crawling"""
        if not self.tools_available.get('gospider', False):
            return {'available': False, 'error': 'gospider not available'}
        
        try:
            cmd = ['gospider', '-s', target_url, '-o', 'gospider_output', '--json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            return {
                'available': True,
                'output': result.stdout,
                'error': result.stderr if result.stderr else None
            }
        except Exception as e:
            return {'available': True, 'error': str(e)}
    
    async def _run_waybackurls(self, target_url: str) -> Dict[str, Any]:
        """Run waybackurls for historical URLs"""
        if not self.tools_available.get('waybackurls', False):
            return {'available': False, 'error': 'waybackurls not available'}
        
        try:
            domain = urlparse(target_url).netloc
            cmd = ['waybackurls', domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            urls = result.stdout.strip().split('\n') if result.stdout.strip() else []
            return {
                'available': True,
                'urls': urls[:100],  # Limit to 100 URLs
                'total_count': len(urls)
            }
        except Exception as e:
            return {'available': True, 'error': str(e)}
    
    async def _run_ffuf(self, target_url: str) -> Dict[str, Any]:
        """Run ffuf for directory fuzzing"""
        if not self.tools_available.get('ffuf', False):
            return {'available': False, 'error': 'ffuf not available'}
        
        try:
            cmd = [
                'ffuf', '-u', f'{target_url}/FUZZ',
                '-w', '/usr/share/wordlists/dirb/common.txt',
                '-mc', '200,301,302,403',
                '-o', 'ffuf_output.json',
                '-of', 'json'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            # Try to read the output file
            try:
                with open('ffuf_output.json', 'r') as f:
                    ffuf_data = json.load(f)
                return {
                    'available': True,
                    'results': ffuf_data.get('results', []),
                    'total_requests': ffuf_data.get('config', {}).get('total_requests', 0)
                }
            except:
                return {
                    'available': True,
                    'output': result.stdout,
                    'error': result.stderr if result.stderr else None
                }
        except Exception as e:
            return {'available': True, 'error': str(e)}
    
    async def _run_gobuster(self, target_url: str) -> Dict[str, Any]:
        """Run gobuster for directory fuzzing"""
        if not self.tools_available.get('gobuster', False):
            return {'available': False, 'error': 'gobuster not available'}
        
        try:
            cmd = [
                'gobuster', 'dir', '-u', target_url,
                '-w', '/usr/share/wordlists/dirb/common.txt',
                '-o', 'gobuster_output.txt'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            return {
                'available': True,
                'output': result.stdout,
                'error': result.stderr if result.stderr else None
            }
        except Exception as e:
            return {'available': True, 'error': str(e)}
    
    async def _run_nuclei(self, target_url: str) -> Dict[str, Any]:
        """Run nuclei for vulnerability scanning"""
        if not self.tools_available.get('nuclei', False):
            return {'available': False, 'error': 'nuclei not available'}
        
        try:
            cmd = ['nuclei', '-u', target_url, '-json', '-silent']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0 and result.stdout:
                findings = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                        except:
                            continue
                return {
                    'available': True,
                    'findings': findings,
                    'total_findings': len(findings)
                }
            else:
                return {
                    'available': True,
                    'findings': [],
                    'total_findings': 0,
                    'error': result.stderr if result.stderr else 'No findings'
                }
        except Exception as e:
            return {'available': True, 'error': str(e)}
    
    async def _run_nikto(self, target_url: str) -> Dict[str, Any]:
        """Run nikto for vulnerability scanning"""
        if not self.tools_available.get('nikto', False):
            return {'available': False, 'error': 'nikto not available'}
        
        try:
            cmd = ['nikto', '-h', target_url, '-Format', 'json', '-output', 'nikto_output.json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Try to read the output file
            try:
                with open('nikto_output.json', 'r') as f:
                    nikto_data = json.load(f)
                return {
                    'available': True,
                    'results': nikto_data,
                    'error': result.stderr if result.stderr else None
                }
            except:
                return {
                    'available': True,
                    'output': result.stdout,
                    'error': result.stderr if result.stderr else None
                }
        except Exception as e:
            return {'available': True, 'error': str(e)}
    
    async def _run_sqlmap(self, target_url: str) -> Dict[str, Any]:
        """Run sqlmap for SQL injection testing"""
        if not self.tools_available.get('sqlmap', False):
            return {'available': False, 'error': 'sqlmap not available'}
        
        try:
            # Only run basic checks, not full exploitation
            cmd = [
                'sqlmap', '-u', target_url,
                '--batch', '--level=1', '--risk=1',
                '--output-dir=sqlmap_output'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            return {
                'available': True,
                'output': result.stdout,
                'error': result.stderr if result.stderr else None
            }
        except Exception as e:
            return {'available': True, 'error': str(e)}
    
    async def _run_dalfox(self, target_url: str) -> Dict[str, Any]:
        """Run dalfox for XSS testing"""
        if not self.tools_available.get('dalfox', False):
            return {'available': False, 'error': 'dalfox not available'}
        
        try:
            cmd = ['dalfox', 'url', target_url, '--format', 'json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0 and result.stdout:
                try:
                    findings = json.loads(result.stdout)
                    return {
                        'available': True,
                        'findings': findings,
                        'total_findings': len(findings) if isinstance(findings, list) else 1
                    }
                except:
                    return {
                        'available': True,
                        'output': result.stdout,
                        'error': result.stderr if result.stderr else None
                    }
            else:
                return {
                    'available': True,
                    'findings': [],
                    'total_findings': 0,
                    'error': result.stderr if result.stderr else 'No XSS findings'
                }
        except Exception as e:
            return {'available': True, 'error': str(e)}
    
    def _parse_robots_txt(self, content: str) -> List[str]:
        """Parse robots.txt to extract disallowed paths"""
        disallowed = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('Disallow:'):
                path = line.replace('Disallow:', '').strip()
                if path:
                    disallowed.append(path)
        return disallowed
    
    def _parse_sitemap_xml(self, content: str) -> List[str]:
        """Parse sitemap.xml to extract URLs"""
        import re
        url_pattern = r'<loc>(.*?)</loc>'
        matches = re.findall(url_pattern, content)
        return matches

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
            if nuclei_results.get('available') and nuclei_results.get('findings'):
                for finding in nuclei_results['findings']:
                    findings.append(self._parse_nuclei_finding(finding))
        
        # Parse dalfox results
        if 'vulnerability_scan' in raw_outputs and 'dalfox' in raw_outputs['vulnerability_scan']:
            dalfox_results = raw_outputs['vulnerability_scan']['dalfox']
            if dalfox_results.get('available') and dalfox_results.get('findings'):
                for finding in dalfox_results['findings']:
                    findings.append(self._parse_dalfox_finding(finding))
        
        # Parse nikto results
        if 'vulnerability_scan' in raw_outputs and 'nikto' in raw_outputs['vulnerability_scan']:
            nikto_results = raw_outputs['vulnerability_scan']['nikto']
            if nikto_results.get('available') and nikto_results.get('results'):
                findings.extend(self._parse_nikto_results(nikto_results['results']))
        
        # Parse ffuf results
        if 'fuzz' in raw_outputs and 'ffuf' in raw_outputs['fuzz']:
            ffuf_results = raw_outputs['fuzz']['ffuf']
            if ffuf_results.get('available') and ffuf_results.get('results'):
                findings.extend(self._parse_ffuf_results(ffuf_results['results']))
        
        return findings
    
    def _parse_nuclei_finding(self, finding: Dict[str, Any]) -> ScanFinding:
        """Parse nuclei finding"""
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
    
    def _parse_nikto_results(self, results: Dict[str, Any]) -> List[ScanFinding]:
        """Parse nikto results"""
        findings = []
        if 'vulnerabilities' in results:
            for vuln in results['vulnerabilities']:
                self.finding_id_counter += 1
                findings.append(ScanFinding(
                    id=f"f{self.finding_id_counter}",
                    type='Information Disclosure',
                    path=vuln.get('url', ''),
                    param=None,
                    evidence=vuln.get('description', ''),
                    tool='nikto',
                    severity='Medium',
                    poc=f"1) Visit {vuln.get('url', '')}\n2) Check response headers\n3) Tool: nikto",
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
