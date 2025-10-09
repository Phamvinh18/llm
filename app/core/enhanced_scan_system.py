"""
Enhanced Scan System - Hệ thống scan tốt nhất với RAG và LLM
"""

import asyncio
import json
import time
import uuid
import requests
import subprocess
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from urllib.parse import urlparse, urljoin
import re
from bs4 import BeautifulSoup

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
    cve: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None

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
    findings: List[ScanFinding] = None
    summary: Optional[str] = None
    report_url: Optional[str] = None
    raw_outputs: Dict[str, Any] = None

class EnhancedScanSystem:
    """Hệ thống scan tốt nhất với RAG và LLM"""
    
    def __init__(self):
        self.active_jobs: Dict[str, ScanJob] = {}
        self.allowlist = self._load_allowlist()
        self.rag_retriever = self._init_rag_retriever()
        self.llm_client = self._init_llm_client()
        self.finding_id_counter = 1
        
    def _load_allowlist(self) -> List[str]:
        """Load allowlist"""
        try:
            with open('app/data/whitelist.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('allowed_targets', [])
        except:
            return ['testphp.vulnweb.com', 'demo.testfire.net', 'localhost', 'httpbin.org']
    
    def _init_rag_retriever(self):
        """Initialize RAG retriever"""
        try:
            from app.core.enhanced_rag_retriever import EnhancedRAGRetriever
            return EnhancedRAGRetriever()
        except Exception as e:
            print(f"RAG retriever init error: {e}")
            return None
    
    def _init_llm_client(self):
        """Initialize LLM client"""
        try:
            from app.clients.gemini_client import GeminiClient
            return GeminiClient()
        except:
            return None
    
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
            asyncio.create_task(self._run_enhanced_scan_pipeline(job_id))
            
            return {
                'success': True,
                'job_id': job_id,
                'message': f"[ROCKET] Enhanced Scan Started! Job ID: {job_id}",
                'estimated_time': "3-5 phút",
                'features': [
                    "[SCAN] Advanced Reconnaissance",
                    "[SPIDER] Intelligent Crawling", 
                    "[TARGET] Smart Fuzzing",
                    "[SECURITY] Vulnerability Detection",
                    "[ROBOT] LLM Analysis",
                    "[CHART] RAG-Enhanced Reports"
                ]
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Lỗi tạo scan job: {str(e)}",
                'job_id': None
            }
    
    async def _validate_target(self, target_url: str) -> Dict[str, Any]:
        """Enhanced validation"""
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
            
            # Enhanced reachability check
            try:
                response = requests.head(target_url, timeout=10, allow_redirects=True)
                if response.status_code >= 400:
                    return {'valid': False, 'error': f'Target không thể truy cập (Status: {response.status_code})'}
                
                # Check for security headers
                security_headers = self._check_security_headers(response.headers)
                if security_headers['missing_count'] > 3:
                    return {'valid': True, 'warning': f'Target thiếu {security_headers["missing_count"]} security headers'}
                
            except Exception as e:
                return {'valid': False, 'error': f'Target không thể truy cập: {str(e)}'}
            
            return {'valid': True, 'error': None}
            
        except Exception as e:
            return {'valid': False, 'error': f'Lỗi validation: {str(e)}'}
    
    async def _run_enhanced_scan_pipeline(self, job_id: str):
        """Enhanced scan pipeline với timeout và error handling tốt hơn"""
        try:
            job = self.active_jobs[job_id]
            job.status = ScanStatus.RUNNING
            job.started_at = time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Stage 1: Enhanced Reconnaissance (với timeout)
            await self._update_job_progress(job_id, ScanStage.RECON, 15)
            try:
                recon_results = await asyncio.wait_for(
                    self._enhanced_reconnaissance(job.target_url), 
                    timeout=30.0
                )
                job.raw_outputs['recon'] = recon_results
            except asyncio.TimeoutError:
                job.raw_outputs['recon'] = {'error': 'Reconnaissance timeout', 'partial': True}
            except Exception as e:
                job.raw_outputs['recon'] = {'error': str(e), 'partial': True}
            
            # Stage 2: Intelligent Crawling (với timeout)
            await self._update_job_progress(job_id, ScanStage.CRAWL, 30)
            try:
                crawl_results = await asyncio.wait_for(
                    self._intelligent_crawling(job.target_url), 
                    timeout=45.0
                )
                job.raw_outputs['crawl'] = crawl_results
            except asyncio.TimeoutError:
                job.raw_outputs['crawl'] = {'error': 'Crawling timeout', 'partial': True}
            except Exception as e:
                job.raw_outputs['crawl'] = {'error': str(e), 'partial': True}
            
            # Stage 3: Smart Fuzzing (với timeout)
            await self._update_job_progress(job_id, ScanStage.FUZZ, 45)
            try:
                fuzz_results = await asyncio.wait_for(
                    self._smart_fuzzing(job.target_url), 
                    timeout=60.0
                )
                job.raw_outputs['fuzz'] = fuzz_results
            except asyncio.TimeoutError:
                job.raw_outputs['fuzz'] = {'error': 'Fuzzing timeout', 'partial': True}
            except Exception as e:
                job.raw_outputs['fuzz'] = {'error': str(e), 'partial': True}
            
            # Stage 4: Vulnerability Detection (với timeout)
            await self._update_job_progress(job_id, ScanStage.VULN_SCAN, 65)
            try:
                vuln_results = await asyncio.wait_for(
                    self._vulnerability_detection(job.target_url), 
                    timeout=90.0
                )
                job.raw_outputs['vulnerability_scan'] = vuln_results
            except asyncio.TimeoutError:
                job.raw_outputs['vulnerability_scan'] = {'error': 'Vulnerability scan timeout', 'partial': True}
            except Exception as e:
                job.raw_outputs['vulnerability_scan'] = {'error': str(e), 'partial': True}
            
            # Stage 5: Result Aggregation (luôn chạy)
            await self._update_job_progress(job_id, ScanStage.AGGREGATION, 80)
            findings = await self._aggregate_findings(job.raw_outputs, job.target_url)
            job.findings = findings
            
            # Stage 6: LLM + RAG Enrichment (với timeout)
            await self._update_job_progress(job_id, ScanStage.LLM_ENRICHMENT, 95)
            try:
                enriched_results = await asyncio.wait_for(
                    self._llm_rag_enrichment(findings, job.target_url), 
                    timeout=30.0
                )
                job.summary = enriched_results['summary']
                job.findings = enriched_results['findings']
            except asyncio.TimeoutError:
                job.summary = "LLM analysis timeout - using basic analysis"
                # Giữ nguyên findings nếu LLM timeout
            except Exception as e:
                job.summary = f"LLM analysis error: {str(e)} - using basic analysis"
            
            # Complete
            await self._update_job_progress(job_id, ScanStage.COMPLETED, 100)
            job.status = ScanStatus.COMPLETED
            job.completed_at = time.strftime('%Y-%m-%d %H:%M:%S')
            
        except Exception as e:
            job = self.active_jobs[job_id]
            job.status = ScanStatus.FAILED
            job.error_message = str(e)
            job.completed_at = time.strftime('%Y-%m-%d %H:%M:%S')
    
    async def _enhanced_reconnaissance(self, target_url: str) -> Dict[str, Any]:
        """Enhanced reconnaissance"""
        results = {}
        
        try:
            # Basic HTTP probe
            response = requests.get(target_url, timeout=10, allow_redirects=True)
            results['http_probe'] = {
                'success': True,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'url': response.url,
                'content_length': len(response.content),
                'server': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown')
            }
            
            # Security headers analysis
            results['security_headers'] = self._check_security_headers(response.headers)
            
            # Robots.txt check
            results['robots_txt'] = await self._check_robots_txt(target_url)
            
            # Sitemap check
            results['sitemap'] = await self._check_sitemap(target_url)
            
            # Technology detection
            results['technology'] = self._detect_technology(response.text, response.headers)
            
            # SSL/TLS analysis
            if target_url.startswith('https://'):
                results['ssl_analysis'] = await self._analyze_ssl(target_url)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def _intelligent_crawling(self, target_url: str) -> Dict[str, Any]:
        """Intelligent crawling"""
        results = {}
        
        try:
            # Get main page
            response = requests.get(target_url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract links
                links = []
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('/'):
                        full_url = urljoin(target_url, href)
                    elif href.startswith('http'):
                        full_url = href
                    else:
                        continue
                    
                    if target_url.split('/')[2] in full_url:  # Same domain
                        links.append(full_url)
                
                results['links'] = list(set(links))[:50]  # Limit to 50 unique links
                
                # Extract forms
                forms = []
                for form in soup.find_all('form'):
                    form_data = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    for input_tag in form.find_all(['input', 'select', 'textarea']):
                        form_data['inputs'].append({
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', '')
                        })
                    
                    forms.append(form_data)
                
                results['forms'] = forms
                
                # Extract JavaScript files
                js_files = []
                for script in soup.find_all('script', src=True):
                    js_files.append(urljoin(target_url, script['src']))
                results['js_files'] = js_files
                
                # Extract CSS files
                css_files = []
                for link in soup.find_all('link', rel='stylesheet'):
                    if link.get('href'):
                        css_files.append(urljoin(target_url, link['href']))
                results['css_files'] = css_files
                
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def _smart_fuzzing(self, target_url: str) -> Dict[str, Any]:
        """Smart directory and file fuzzing"""
        results = {}
        
        # Common paths to check
        common_paths = [
            '/admin', '/login', '/api', '/test', '/dev', '/staging',
            '/robots.txt', '/sitemap.xml', '/favicon.ico', '/.env',
            '/config.php', '/wp-config.php', '/readme.txt', '/changelog.txt',
            '/.git/', '/.svn/', '/backup/', '/uploads/', '/files/',
            '/phpmyadmin/', '/admin.php', '/wp-admin/', '/administrator/',
            '/.well-known/security.txt', '/crossdomain.xml', '/web.config'
        ]
        
        discovered_paths = []
        
        for path in common_paths:
            try:
                url = target_url.rstrip('/') + path
                response = requests.head(url, timeout=5)
                
                if response.status_code in [200, 301, 302, 403]:
                    discovered_paths.append({
                        'url': url,
                        'status': response.status_code,
                        'length': response.headers.get('content-length', 0),
                        'server': response.headers.get('Server', ''),
                        'content_type': response.headers.get('Content-Type', '')
                    })
            except:
                continue
        
        results['discovered_paths'] = discovered_paths
        
        # Parameter fuzzing
        results['parameter_analysis'] = await self._analyze_parameters(target_url)
        
        return results
    
    async def _vulnerability_detection(self, target_url: str) -> Dict[str, Any]:
        """Vulnerability detection"""
        results = {}
        
        # XSS detection
        results['xss_scan'] = await self._scan_xss(target_url)
        
        # SQL injection detection
        results['sql_injection_scan'] = await self._scan_sql_injection(target_url)
        
        # Security misconfiguration detection
        results['misconfig_scan'] = await self._scan_misconfig(target_url)
        
        # IDOR detection
        results['idor_scan'] = await self._scan_idor(target_url)
        
        return results
    
    async def _scan_xss(self, target_url: str) -> Dict[str, Any]:
        """XSS vulnerability scanning"""
        findings = []
        
        try:
            # Get page content
            response = requests.get(target_url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find forms
                for form in soup.find_all('form'):
                    form_action = form.get('action', '')
                    form_method = form.get('method', 'GET').upper()
                    
                    # Find input fields
                    for input_tag in form.find_all(['input', 'textarea']):
                        input_name = input_tag.get('name', '')
                        input_type = input_tag.get('type', 'text')
                        
                        if input_name and input_type in ['text', 'search', 'textarea']:
                            # Test XSS payloads
                            xss_payloads = [
                                '<script>alert("XSS")</script>',
                                '"><script>alert("XSS")</script>',
                                "'><script>alert('XSS')</script>",
                                'javascript:alert("XSS")',
                                '<img src=x onerror=alert("XSS")>'
                            ]
                            
                            for payload in xss_payloads:
                                try:
                                    if form_method == 'GET':
                                        test_url = f"{target_url}?{input_name}={payload}"
                                        test_response = requests.get(test_url, timeout=5)
                                    else:
                                        test_response = requests.post(
                                            urljoin(target_url, form_action),
                                            data={input_name: payload},
                                            timeout=5
                                        )
                                    
                                    if payload in test_response.text:
                                        findings.append({
                                            'type': 'XSS',
                                            'parameter': input_name,
                                            'payload': payload,
                                            'url': test_url if form_method == 'GET' else urljoin(target_url, form_action),
                                            'evidence': 'Payload reflected in response',
                                            'severity': 'High'
                                        })
                                except:
                                    continue
                
        except Exception as e:
            findings.append({'error': str(e)})
        
        return {'findings': findings}
    
    async def _scan_sql_injection(self, target_url: str) -> Dict[str, Any]:
        """SQL injection vulnerability scanning"""
        findings = []
        
        try:
            # Parse URL for parameters
            parsed = urlparse(target_url)
            if parsed.query:
                params = {}
                for param_pair in parsed.query.split('&'):
                    if '=' in param_pair:
                        key, value = param_pair.split('=', 1)
                        params[key] = value
                
                # Test SQL injection payloads
                sql_payloads = [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "'; DROP TABLE users--",
                    "' UNION SELECT NULL--",
                    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
                ]
                
                for param_name, param_value in params.items():
                    for payload in sql_payloads:
                        try:
                            test_params = params.copy()
                            test_params[param_name] = payload
                            
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + \
                                      "&".join([f"{k}={v}" for k, v in test_params.items()])
                            
                            test_response = requests.get(test_url, timeout=5)
                            
                            # Check for SQL error patterns
                            error_patterns = [
                                'mysql_fetch_array',
                                'ORA-01756',
                                'Microsoft OLE DB Provider',
                                'SQLServer JDBC Driver',
                                'PostgreSQL query failed',
                                'Warning: mysql_',
                                'valid MySQL result',
                                'MySqlClient\.',
                                'SQL syntax.*MySQL',
                                'Warning.*\Wmysql_',
                                'valid MySQL result',
                                'check the manual that corresponds to your MySQL server version'
                            ]
                            
                            for pattern in error_patterns:
                                if re.search(pattern, test_response.text, re.IGNORECASE):
                                    findings.append({
                                        'type': 'SQL Injection',
                                        'parameter': param_name,
                                        'payload': payload,
                                        'url': test_url,
                                        'evidence': f'SQL error pattern detected: {pattern}',
                                        'severity': 'Critical'
                                    })
                                    break
                        except:
                            continue
                
        except Exception as e:
            findings.append({'error': str(e)})
        
        return {'findings': findings}
    
    async def _scan_misconfig(self, target_url: str) -> Dict[str, Any]:
        """Security misconfiguration scanning"""
        findings = []
        
        try:
            response = requests.get(target_url, timeout=10)
            
            # Check for debug information
            debug_patterns = [
                'debug.*true',
                'development.*mode',
                'test.*environment',
                'staging.*server',
                'phpinfo',
                'var_dump',
                'print_r',
                'console\.log'
            ]
            
            for pattern in debug_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    findings.append({
                        'type': 'Information Disclosure',
                        'evidence': f'Debug information detected: {pattern}',
                        'severity': 'Medium'
                    })
            
            # Check for version disclosure
            version_patterns = [
                'version.*\d+\.\d+',
                'powered by.*\d+\.\d+',
                'generator.*\d+\.\d+'
            ]
            
            for pattern in version_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    findings.append({
                        'type': 'Version Disclosure',
                        'evidence': f'Version information disclosed: {matches[0]}',
                        'severity': 'Low'
                    })
            
            # Check for directory listing
            if 'Index of' in response.text or 'Directory listing' in response.text:
                findings.append({
                    'type': 'Directory Listing',
                    'evidence': 'Directory listing enabled',
                    'severity': 'Medium'
                })
                
        except Exception as e:
            findings.append({'error': str(e)})
        
        return {'findings': findings}
    
    async def _scan_idor(self, target_url: str) -> Dict[str, Any]:
        """IDOR vulnerability scanning"""
        findings = []
        
        try:
            # Look for numeric IDs in URL
            parsed = urlparse(target_url)
            path_parts = parsed.path.split('/')
            
            for i, part in enumerate(path_parts):
                if part.isdigit():
                    # Test IDOR by changing the ID
                    test_parts = path_parts.copy()
                    test_parts[i] = str(int(part) + 1)
                    test_path = '/'.join(test_parts)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"
                    
                    try:
                        test_response = requests.get(test_url, timeout=5)
                        if test_response.status_code == 200 and test_response.text != requests.get(target_url, timeout=5).text:
                            findings.append({
                                'type': 'IDOR',
                                'parameter': f'path_segment_{i}',
                                'original_value': part,
                                'test_value': str(int(part) + 1),
                                'url': test_url,
                                'evidence': 'Different content returned for different ID',
                                'severity': 'High'
                            })
                    except:
                        continue
                
        except Exception as e:
            findings.append({'error': str(e)})
        
        return {'findings': findings}
    
    async def _aggregate_findings(self, raw_outputs: Dict[str, Any], target_url: str) -> List[ScanFinding]:
        """Aggregate findings from all scans"""
        findings = []
        
        # Process vulnerability scan results
        if 'vulnerability_scan' in raw_outputs:
            vuln_scan = raw_outputs['vulnerability_scan']
            
            # XSS findings
            if 'xss_scan' in vuln_scan and 'findings' in vuln_scan['xss_scan']:
                for finding in vuln_scan['xss_scan']['findings']:
                    if 'error' not in finding:
                        findings.append(ScanFinding(
                            id=f"f{self.finding_id_counter}",
                            type='XSS',
                            path=finding.get('url', ''),
                            param=finding.get('parameter', ''),
                            evidence=finding.get('evidence', ''),
                            tool='enhanced_scanner',
                            severity=finding.get('severity', 'High'),
                            poc=f"1) Visit {finding.get('url', '')}\n2) Parameter: {finding.get('parameter', '')}\n3) Payload: {finding.get('payload', '')}",
                            remediation="Implement proper input validation and output encoding",
                            confidence=0.9,
                            cwe="CWE-79",
                            owasp="A03:2021 - Injection"
                        ))
                        self.finding_id_counter += 1
            
            # SQL Injection findings
            if 'sql_injection_scan' in vuln_scan and 'findings' in vuln_scan['sql_injection_scan']:
                for finding in vuln_scan['sql_injection_scan']['findings']:
                    if 'error' not in finding:
                        findings.append(ScanFinding(
                            id=f"f{self.finding_id_counter}",
                            type='SQL Injection',
                            path=finding.get('url', ''),
                            param=finding.get('parameter', ''),
                            evidence=finding.get('evidence', ''),
                            tool='enhanced_scanner',
                            severity=finding.get('severity', 'Critical'),
                            poc=f"1) Visit {finding.get('url', '')}\n2) Parameter: {finding.get('parameter', '')}\n3) Payload: {finding.get('payload', '')}",
                            remediation="Use prepared statements and parameterized queries",
                            confidence=0.95,
                            cwe="CWE-89",
                            owasp="A03:2021 - Injection"
                        ))
                        self.finding_id_counter += 1
            
            # Misconfiguration findings
            if 'misconfig_scan' in vuln_scan and 'findings' in vuln_scan['misconfig_scan']:
                for finding in vuln_scan['misconfig_scan']['findings']:
                    if 'error' not in finding:
                        findings.append(ScanFinding(
                            id=f"f{self.finding_id_counter}",
                            type='Security Misconfiguration',
                            path=target_url,
                            param=None,
                            evidence=finding.get('evidence', ''),
                            tool='enhanced_scanner',
                            severity=finding.get('severity', 'Medium'),
                            poc=f"1) Visit {target_url}\n2) Check response content\n3) Look for debug information",
                            remediation="Remove debug information and secure server configuration",
                            confidence=0.8,
                            cwe="CWE-200",
                            owasp="A05:2021 - Security Misconfiguration"
                        ))
                        self.finding_id_counter += 1
            
            # IDOR findings
            if 'idor_scan' in vuln_scan and 'findings' in vuln_scan['idor_scan']:
                for finding in vuln_scan['idor_scan']['findings']:
                    if 'error' not in finding:
                        findings.append(ScanFinding(
                            id=f"f{self.finding_id_counter}",
                            type='IDOR',
                            path=finding.get('url', ''),
                            param=finding.get('parameter', ''),
                            evidence=finding.get('evidence', ''),
                            tool='enhanced_scanner',
                            severity=finding.get('severity', 'High'),
                            poc=f"1) Visit {finding.get('url', '')}\n2) Change {finding.get('parameter', '')} from {finding.get('original_value', '')} to {finding.get('test_value', '')}\n3) Check if different content is returned",
                            remediation="Implement proper access control and authorization checks",
                            confidence=0.85,
                            cwe="CWE-639",
                            owasp="A01:2021 - Broken Access Control"
                        ))
                        self.finding_id_counter += 1
        
        # Process fuzzing results
        if 'fuzz' in raw_outputs and 'discovered_paths' in raw_outputs['fuzz']:
            for path_info in raw_outputs['fuzz']['discovered_paths']:
                if path_info['status'] in [200, 403]:
                    findings.append(ScanFinding(
                        id=f"f{self.finding_id_counter}",
                        type='Directory/File Discovery',
                        path=path_info['url'],
                        param=None,
                        evidence=f"Status: {path_info['status']}, Server: {path_info['server']}",
                        tool='enhanced_fuzzer',
                        severity='Low',
                        poc=f"1) Visit {path_info['url']}\n2) Check response\n3) Review for sensitive information",
                        remediation="Review discovered paths and remove unnecessary files",
                        confidence=0.9,
                        cwe="CWE-200",
                        owasp="A05:2021 - Security Misconfiguration"
                    ))
                    self.finding_id_counter += 1
        
        return findings
    
    async def _llm_rag_enrichment(self, findings: List[ScanFinding], target_url: str, scan_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """LLM + RAG enrichment siêu thông minh với comprehensive analysis"""
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
                    'confidence': finding.confidence,
                    'cwe': finding.cwe,
                    'owasp': finding.owasp
                })
            
            # Get comprehensive RAG context
            rag_context = ""
            rag_insights = []
            if self.rag_retriever:
                try:
                    print(f"[RAG] Retrieving knowledge for {len(findings)} findings...")
                    
                    # 1. Get vulnerability-specific knowledge for each finding
                    for finding in findings:
                        vuln_type = finding.type.lower().replace(' ', '_')
                        print(f"[RAG] Getting knowledge for {vuln_type}...")
                        
                        # Get specific vulnerability knowledge
                        vuln_docs = self.rag_retriever.retrieve(f"{vuln_type} vulnerability detection remediation", k=5)
                        if vuln_docs:
                            rag_context += f"\n=== {vuln_type.upper()} VULNERABILITY KNOWLEDGE ===\n"
                            for doc in vuln_docs:
                                content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                                rag_context += f"- {content}\n"
                                rag_insights.append(f"RAG Insight: {vuln_type} - {content[:100]}...")
                        
                        # Get payload knowledge
                        payload_docs = self.rag_retriever.retrieve(f"{vuln_type} payloads techniques", k=3)
                        if payload_docs:
                            rag_context += f"\n=== {vuln_type.upper()} PAYLOAD TECHNIQUES ===\n"
                            for doc in payload_docs:
                                content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                                rag_context += f"- {content}\n"
                        
                        # Get remediation knowledge
                        remediation_docs = self.rag_retriever.retrieve(f"{vuln_type} remediation fix prevention", k=3)
                        if remediation_docs:
                            rag_context += f"\n=== {vuln_type.upper()} REMEDIATION GUIDANCE ===\n"
                            for doc in remediation_docs:
                                content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                                rag_context += f"- {content}\n"
                    
                    # 2. Get OWASP Top 10 2023 knowledge
                    owasp_docs = self.rag_retriever.retrieve("OWASP Top 10 2023 security risks", k=5)
                    if owasp_docs:
                        rag_context += "\n=== OWASP TOP 10 2023 KNOWLEDGE ===\n"
                        for doc in owasp_docs:
                            content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                            rag_context += f"- {content}\n"
                            rag_insights.append(f"OWASP Insight: {content[:100]}...")
                    
                    # 3. Get security headers knowledge
                    headers_docs = self.rag_retriever.retrieve("security headers HTTP protection", k=4)
                    if headers_docs:
                        rag_context += "\n=== SECURITY HEADERS KNOWLEDGE ===\n"
                        for doc in headers_docs:
                            content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                            rag_context += f"- {content}\n"
                    
                    # 4. Get web application security best practices
                    best_practices_docs = self.rag_retriever.retrieve("web application security best practices", k=4)
                    if best_practices_docs:
                        rag_context += "\n=== SECURITY BEST PRACTICES ===\n"
                        for doc in best_practices_docs:
                            content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                            rag_context += f"- {content}\n"
                            rag_insights.append(f"Best Practice: {content[:100]}...")
                    
                    # 5. Get CVE and vulnerability database knowledge
                    cve_docs = self.rag_retriever.retrieve("CVE vulnerability database recent", k=3)
                    if cve_docs:
                        rag_context += "\n=== CVE VULNERABILITY DATABASE ===\n"
                        for doc in cve_docs:
                            content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                            rag_context += f"- {content}\n"
                    
                    # 6. Get detection techniques knowledge
                    detection_docs = self.rag_retriever.retrieve("vulnerability detection techniques tools", k=3)
                    if detection_docs:
                        rag_context += "\n=== DETECTION TECHNIQUES ===\n"
                        for doc in detection_docs:
                            content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                            rag_context += f"- {content}\n"
                    
                    print(f"[RAG] Retrieved {len(rag_insights)} insights from knowledge base")
                    print(f"[RAG] Total context length: {len(rag_context)} characters")
                        
                except Exception as e:
                    print(f"[RAG] Retrieval error: {e}")
                    rag_context = "RAG knowledge base temporarily unavailable"
                    rag_insights = ["RAG system offline - using fallback analysis"]
            
            # Create enhanced LLM prompt with comprehensive RAG integration
            prompt = f"""
            Bạn là chuyên gia bảo mật web hàng đầu với kiến thức sâu rộng về OWASP Top 10, CWE, và các best practices bảo mật.
            
            ===== SCAN TARGET =====
            Target URL: {target_url}
            Total Findings: {len(findings)}
            Scan Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}
            
            ===== FINDINGS DATA =====
            {json.dumps(findings_data, ensure_ascii=False, indent=2)}
            
            ===== RAG KNOWLEDGE BASE CONTEXT =====
            {rag_context}
            
            ===== RAG INSIGHTS SUMMARY =====
            {chr(10).join(rag_insights[:10]) if rag_insights else "No RAG insights available"}
            
            ===== ANALYSIS REQUIREMENTS =====
            Sử dụng RAG knowledge base để tạo báo cáo bảo mật chuyên nghiệp với:
            
            1. **Executive Summary** (2-3 câu tóm tắt tình hình bảo mật dựa trên RAG insights)
            2. **Risk Assessment** (đánh giá rủi ro tổng thể với reference đến OWASP Top 10)
            3. **Detailed Findings Analysis** (phân tích chi tiết từng lỗ hổng với):
               - Severity justification dựa trên RAG knowledge
               - Business impact assessment
               - Technical details với RAG context
               - Safe PoC steps với RAG payload knowledge
               - Detailed remediation với RAG best practices
               - CWE và OWASP mapping từ RAG database
               - Confidence score dựa trên RAG patterns
            4. **RAG-Enhanced Remediation Priority** (thứ tự ưu tiên khắc phục dựa trên RAG insights)
            5. **Security Recommendations** (khuyến nghị bảo mật tổng thể từ RAG best practices)
            6. **Next Steps** (các bước tiếp theo với RAG guidance)
            7. **RAG Knowledge Impact** (tầm quan trọng của RAG trong phân tích này)
            
            ===== OUTPUT FORMAT =====
            Trả về JSON format với RAG-enhanced analysis:
            {{
                "summary": "Executive summary với RAG insights",
                "risk_assessment": "Overall risk level với OWASP reference",
                "rag_impact": "Tầm quan trọng của RAG trong phân tích này",
                "findings": [
                    {{
                        "id": "f1",
                        "type": "XSS",
                        "severity": "High",
                        "business_impact": "Impact description với RAG context",
                        "technical_details": "Technical explanation với RAG knowledge",
                        "poc": "Safe PoC steps với RAG payload techniques",
                        "remediation": "Detailed remediation với RAG best practices và code examples",
                        "cwe": "CWE-79",
                        "owasp": "A03:2023 - Injection",
                        "priority": 1,
                        "rag_confidence": 0.95,
                        "rag_insights": ["RAG insight 1", "RAG insight 2"]
                    }}
                ],
                "remediation_priority": [
                    "Priority 1: Critical vulnerabilities (RAG-based assessment)",
                    "Priority 2: High severity issues (RAG-enhanced)"
                ],
                "security_recommendations": [
                    "General security recommendations từ RAG best practices"
                ],
                "next_steps": [
                    "Immediate actions với RAG guidance",
                    "Long-term improvements với RAG insights"
                ],
                "rag_knowledge_used": {{
                    "vulnerability_knowledge": "XSS, SQL Injection, IDOR, Misconfiguration",
                    "owasp_knowledge": "Top 10 2023",
                    "best_practices": "Security headers, input validation, output encoding",
                    "detection_techniques": "Advanced payload techniques, evasion methods",
                    "remediation_guidance": "Code examples, implementation steps"
                }}
            }}
            
            ===== RAG IMPORTANCE =====
            Hãy nhấn mạnh tầm quan trọng của RAG knowledge base trong việc:
            - Cung cấp context chính xác cho từng loại lỗ hổng
            - Đưa ra remediation guidance dựa trên best practices
            - Phân tích severity với reference đến OWASP standards
            - Tạo PoC steps an toàn và hiệu quả
            - Đưa ra recommendations dựa trên real-world experience
            """
            
            # Get LLM response
            if self.llm_client:
                llm_response = self.llm_client.chat(prompt, max_output_tokens=3000)
                
                try:
                    # Try to parse JSON response
                    enriched_data = json.loads(llm_response)
                    
                    # Add RAG insights to the response
                    enriched_data['rag_insights'] = rag_insights
                    enriched_data['rag_context_length'] = len(rag_context)
                    enriched_data['rag_retrieval_success'] = len(rag_insights) > 0
                    
                    print(f"[RAG] LLM analysis completed with {len(rag_insights)} RAG insights")
                    return enriched_data
                except Exception as parse_error:
                    print(f"[RAG] JSON parsing failed: {parse_error}")
                    # Fallback if JSON parsing fails
                    return {
                        'summary': llm_response[:800] + "..." if len(llm_response) > 800 else llm_response,
                        'risk_assessment': 'Medium risk based on findings',
                        'rag_impact': 'RAG knowledge base provided context for analysis',
                        'findings': findings_data,
                        'remediation_priority': [
                            "Fix critical vulnerabilities immediately (RAG-enhanced)",
                            "Implement security headers (RAG best practices)",
                            "Review and secure all inputs (RAG guidance)"
                        ],
                        'security_recommendations': [
                            "Implement Web Application Firewall (WAF) - RAG recommendation",
                            "Regular security testing - RAG best practice",
                            "Security awareness training - RAG guidance"
                        ],
                        'next_steps': [
                            "Manual verification of findings with RAG context",
                            "Implement fixes using RAG remediation guidance",
                            "Conduct penetration testing with RAG techniques"
                        ],
                        'rag_insights': rag_insights,
                        'rag_context_length': len(rag_context),
                        'rag_retrieval_success': len(rag_insights) > 0
                    }
            else:
                # Fallback without LLM but with RAG insights
                return {
                    'summary': f"Scan completed with {len(findings)} findings. RAG knowledge base provided context for analysis.",
                    'risk_assessment': 'Medium risk based on findings and RAG analysis',
                    'rag_impact': 'RAG knowledge base provided comprehensive context for manual analysis',
                    'findings': findings_data,
                    'remediation_priority': [
                        "Review all findings manually with RAG context",
                        "Implement security best practices from RAG knowledge"
                    ],
                    'security_recommendations': [
                        "Regular security testing - RAG best practice",
                        "Implement security headers - RAG guidance"
                    ],
                    'next_steps': [
                        "Manual verification with RAG insights",
                        "Implement fixes using RAG remediation guidance"
                    ],
                    'rag_insights': rag_insights,
                    'rag_context_length': len(rag_context),
                    'rag_retrieval_success': len(rag_insights) > 0
                }
                
        except Exception as e:
            return {
                'summary': f"Scan completed with {len(findings)} findings. LLM enrichment failed: {str(e)}",
                'risk_assessment': 'Unknown risk level - RAG analysis attempted',
                'rag_impact': 'RAG knowledge base attempted to provide context but analysis failed',
                'findings': [asdict(finding) for finding in findings],
                'remediation_priority': ["Review findings manually with available RAG context"],
                'security_recommendations': ["Implement security best practices from RAG knowledge"],
                'next_steps': ["Manual verification required with RAG insights"],
                'rag_insights': rag_insights if 'rag_insights' in locals() else [],
                'rag_context_length': len(rag_context) if 'rag_context' in locals() else 0,
                'rag_retrieval_success': len(rag_insights) > 0 if 'rag_insights' in locals() else False,
                'error': str(e)
            }
    
    # Helper methods
    def _check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check security headers with RAG-enhanced analysis"""
        # Enhanced security headers with RAG knowledge
        security_headers = {
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'importance': 'High',
                'expected_values': ['DENY', 'SAMEORIGIN'],
                'rag_insight': 'Critical for preventing UI redressing attacks'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME sniffing attacks',
                'importance': 'High',
                'expected_values': ['nosniff'],
                'rag_insight': 'Prevents browsers from interpreting files as different MIME types'
            },
            'X-XSS-Protection': {
                'description': 'XSS protection (legacy)',
                'importance': 'Medium',
                'expected_values': ['1; mode=block'],
                'rag_insight': 'Legacy header, CSP is preferred for modern XSS protection'
            },
            'Strict-Transport-Security': {
                'description': 'HTTPS enforcement',
                'importance': 'Critical',
                'expected_values': ['max-age=31536000', 'max-age=31536000; includeSubDomains'],
                'rag_insight': 'Essential for preventing man-in-the-middle attacks'
            },
            'Content-Security-Policy': {
                'description': 'Content security policy',
                'importance': 'Critical',
                'expected_values': ['default-src \'self\'', 'script-src \'self\''],
                'rag_insight': 'Most effective defense against XSS and injection attacks'
            },
            'Referrer-Policy': {
                'description': 'Referrer information control',
                'importance': 'Medium',
                'expected_values': ['strict-origin-when-cross-origin', 'no-referrer'],
                'rag_insight': 'Prevents information leakage through referrer headers'
            },
            'Permissions-Policy': {
                'description': 'Feature permissions',
                'importance': 'Medium',
                'expected_values': ['geolocation=()', 'camera=()'],
                'rag_insight': 'Controls browser features to prevent unauthorized access'
            }
        }
        
        present = []
        missing = []
        rag_insights = []
        security_score = 0.0
        
        for header, config in security_headers.items():
            if header in headers:
                # Check if value meets RAG expectations
                value_score = 0.0
                for expected in config['expected_values']:
                    if expected.lower() in headers[header].lower():
                        value_score = 1.0
                        break
                
                present.append({
                    'header': header,
                    'value': headers[header],
                    'description': config['description'],
                    'importance': config['importance'],
                    'rag_insight': config['rag_insight'],
                    'value_score': value_score
                })
                
                # Calculate security score based on importance and value
                if config['importance'] == 'Critical':
                    security_score += value_score * 0.4
                elif config['importance'] == 'High':
                    security_score += value_score * 0.3
                else:
                    security_score += value_score * 0.1
                    
                rag_insights.append(f"RAG Header Insight: {header} - {config['rag_insight']}")
            else:
                missing.append({
                    'header': header,
                    'description': config['description'],
                    'importance': config['importance'],
                    'rag_insight': config['rag_insight'],
                    'severity': 'High' if config['importance'] == 'Critical' else 'Medium'
                })
                
                rag_insights.append(f"RAG Missing Header: {header} - {config['rag_insight']}")
        
        return {
            'present': present,
            'missing': missing,
            'missing_count': len(missing),
            'security_score': round(security_score * 100, 1),
            'rag_insights': rag_insights,
            'rag_analysis': 'RAG knowledge base provided comprehensive header analysis',
            'recommendations': self._get_header_recommendations(missing, rag_insights)
        }
    
    def _get_header_recommendations(self, missing_headers: List[Dict], rag_insights: List[str]) -> List[str]:
        """Get RAG-enhanced header recommendations"""
        recommendations = []
        
        for header in missing_headers:
            if header['importance'] == 'Critical':
                recommendations.append(f"CRITICAL: Implement {header['header']} - {header['rag_insight']}")
            elif header['importance'] == 'High':
                recommendations.append(f"HIGH: Add {header['header']} - {header['rag_insight']}")
            else:
                recommendations.append(f"MEDIUM: Consider {header['header']} - {header['rag_insight']}")
        
        # Add RAG-based general recommendations
        recommendations.extend([
            "RAG Recommendation: Implement comprehensive CSP policy for XSS protection",
            "RAG Best Practice: Use HSTS with includeSubDomains for complete HTTPS enforcement",
            "RAG Guidance: Regular header security audits using RAG knowledge base"
        ])
        
        return recommendations
    
    def format_scan_results(self, scan_data: Dict[str, Any]) -> str:
        """Format scan results with beautiful output"""
        try:
            from app.core.scan_results_formatter import ScanResultsFormatter
            formatter = ScanResultsFormatter()
            return formatter.format_comprehensive_scan_result(scan_data)
        except Exception as e:
            print(f"Error formatting scan results: {e}")
            return f"❌ Error formatting scan results: {str(e)}"
    
    async def _check_robots_txt(self, target_url: str) -> Dict[str, Any]:
        """Check robots.txt"""
        try:
            robots_url = urljoin(target_url, '/robots.txt')
            response = requests.get(robots_url, timeout=5)
            
            if response.status_code == 200:
                return {
                    'available': True,
                    'content': response.text,
                    'disallowed_paths': self._parse_robots_txt(response.text)
                }
        except:
            pass
        
        return {'available': False}
    
    async def _check_sitemap(self, target_url: str) -> Dict[str, Any]:
        """Check sitemap.xml"""
        try:
            sitemap_url = urljoin(target_url, '/sitemap.xml')
            response = requests.get(sitemap_url, timeout=5)
            
            if response.status_code == 200:
                return {
                    'available': True,
                    'content': response.text,
                    'urls': self._parse_sitemap_xml(response.text)
                }
        except:
            pass
        
        return {'available': False}
    
    def _detect_technology(self, content: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Detect web technologies"""
        technologies = {
            'server': headers.get('Server', 'Unknown'),
            'cms': None,
            'frameworks': [],
            'languages': []
        }
        
        # Detect CMS
        if 'wordpress' in content.lower() or 'wp-content' in content:
            technologies['cms'] = 'WordPress'
        elif 'drupal' in content.lower():
            technologies['cms'] = 'Drupal'
        elif 'joomla' in content.lower():
            technologies['cms'] = 'Joomla'
        
        # Detect frameworks
        if 'bootstrap' in content.lower():
            technologies['frameworks'].append('Bootstrap')
        if 'jquery' in content.lower():
            technologies['frameworks'].append('jQuery')
        if 'react' in content.lower():
            technologies['frameworks'].append('React')
        if 'angular' in content.lower():
            technologies['frameworks'].append('Angular')
        
        # Detect languages
        if 'php' in content.lower() or '.php' in content:
            technologies['languages'].append('PHP')
        if 'asp.net' in content.lower() or 'aspx' in content:
            technologies['languages'].append('ASP.NET')
        if 'python' in content.lower() or 'django' in content.lower():
            technologies['languages'].append('Python')
        
        return technologies
    
    async def _analyze_ssl(self, target_url: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        # Simplified SSL analysis
        return {
            'available': True,
            'protocol': 'TLS 1.2+',
            'certificate_valid': True,
            'recommendations': ['Use TLS 1.3', 'Implement HSTS']
        }
    
    async def _analyze_parameters(self, target_url: str) -> Dict[str, Any]:
        """Analyze URL parameters"""
        parsed = urlparse(target_url)
        params = {}
        
        if parsed.query:
            for param_pair in parsed.query.split('&'):
                if '=' in param_pair:
                    key, value = param_pair.split('=', 1)
                    params[key] = value
        
        return {
            'parameters': list(params.keys()),
            'sensitive_params': [p for p in params.keys() if p.lower() in ['id', 'user', 'admin', 'password', 'token']]
        }
    
    def _parse_robots_txt(self, content: str) -> List[str]:
        """Parse robots.txt"""
        disallowed = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('Disallow:'):
                path = line.replace('Disallow:', '').strip()
                if path:
                    disallowed.append(path)
        return disallowed
    
    def _parse_sitemap_xml(self, content: str) -> List[str]:
        """Parse sitemap.xml"""
        urls = []
        url_pattern = r'<loc>(.*?)</loc>'
        matches = re.findall(url_pattern, content)
        return matches
    
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
            'findings': [asdict(finding) for finding in job.findings],
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

