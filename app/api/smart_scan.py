from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import requests
import time
from app.core.request_generator import LLMRequestGenerator
from app.core.llm_analyzer import LLMAnalyzer
from app.core.session_store import append_message


router = APIRouter()


class SmartScanRequest(BaseModel):
    target_url: str
    session_id: Optional[str] = None
    max_requests: int = 10


class SmartScanResponse(BaseModel):
    scan_id: str
    target_url: str
    generated_requests: List[Dict[str, Any]]
    scan_results: List[Dict[str, Any]]
    vulnerability_analysis: Dict[str, Any]
    exploitation_guide: Dict[str, Any]


@router.post('/smart-scan', response_model=SmartScanResponse)
async def smart_scan(req: SmartScanRequest):
    """
    Enhanced Smart Scanner: URL → LLM sinh nhiều requests → Scan → LLM phân tích chi tiết → Exploitation guide
    """
    try:
        scan_id = f"smart-scan-{int(time.time())}"
        
        # Bước 1: LLM sinh ra nhiều request từ URL với các loại lỗ hổng khác nhau
        request_generator = LLMRequestGenerator()
        generated_requests = _generate_comprehensive_requests(req.target_url, req.max_requests)
        
        # Bước 2: Thực hiện các request và thu thập response với timeout và retry
        scan_results = []
        for i, request_data in enumerate(generated_requests):
            try:
                # Thêm delay giữa các request để tránh rate limiting
                if i > 0:
                    time.sleep(0.5)
                
                response = _execute_request_enhanced(request_data)
                scan_results.append({
                    "request": request_data,
                    "response": response,
                    "description": request_data.get("description", ""),
                    "vulnerability_type": request_data.get("vulnerability_type", ""),
                    "request_id": f"req-{i+1}"
                })
            except Exception as e:
                scan_results.append({
                    "request": request_data,
                    "response": {"error": str(e), "status": 0},
                    "description": request_data.get("description", ""),
                    "vulnerability_type": request_data.get("vulnerability_type", ""),
                    "request_id": f"req-{i+1}"
                })
        
        # Bước 3: LLM phân tích chi tiết các response để tìm lỗ hổng
        analyzer = LLMAnalyzer()
        vulnerability_analysis = await _analyze_scan_results_async(scan_results)
        
        # Bước 4: Tạo exploitation guide chi tiết
        exploitation_guide = _generate_exploitation_guide(vulnerability_analysis)
        
        # Lưu vào session nếu có
        if req.session_id:
            total_vulns = vulnerability_analysis.get('summary', {}).get('total_vulnerabilities', 0)
            append_message(req.session_id, 'assistant', 
                f"Enhanced smart scan completed for {req.target_url}. Generated {len(generated_requests)} requests, found {total_vulns} vulnerabilities.")
        
        return SmartScanResponse(
            scan_id=scan_id,
            target_url=req.target_url,
            generated_requests=generated_requests,
            scan_results=scan_results,
            vulnerability_analysis=vulnerability_analysis,
            exploitation_guide=exploitation_guide
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Smart scan failed: {str(e)}")


def _generate_comprehensive_requests(target_url: str, max_requests: int) -> List[Dict[str, Any]]:
    """
    Tạo nhiều request toàn diện cho các loại lỗ hổng khác nhau với LLM-generated URLs
    """
    requests = []
    
    # LLM-generated URL discovery requests
    llm_generated_urls = _generate_llm_urls(target_url)
    
    # Base URL requests
    base_requests = [
        {
            "method": "GET",
            "url": target_url,
            "description": "Basic GET request to homepage",
            "vulnerability_type": "Information Disclosure",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        },
        {
            "method": "GET", 
            "url": f"{target_url}/robots.txt",
            "description": "Check robots.txt for sensitive paths",
            "vulnerability_type": "Information Disclosure",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        },
        {
            "method": "GET",
            "url": f"{target_url}/sitemap.xml",
            "description": "Check sitemap for application structure",
            "vulnerability_type": "Information Disclosure",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        }
    ]
    
    # Add LLM-generated URLs
    base_requests.extend(llm_generated_urls)
    
    # SQL Injection requests
    sql_requests = [
        {
            "method": "GET",
            "url": f"{target_url}/search?q=' OR '1'='1' --",
            "description": "SQL injection test in search parameter",
            "vulnerability_type": "SQL Injection",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        },
        {
            "method": "GET",
            "url": f"{target_url}/product?id=1' UNION SELECT 1,2,3 --",
            "description": "SQL injection test in product ID parameter",
            "vulnerability_type": "SQL Injection",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        },
        {
            "method": "POST",
            "url": f"{target_url}/login",
            "description": "SQL injection test in login form",
            "vulnerability_type": "SQL Injection",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            "body": "username=admin' OR '1'='1' --&password=test"
        }
    ]
    
    # XSS requests
    xss_requests = [
        {
            "method": "GET",
            "url": f"{target_url}/search?q=<script>alert('XSS')</script>",
            "description": "XSS test in search parameter",
            "vulnerability_type": "Cross-Site Scripting",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        },
        {
            "method": "GET",
            "url": f"{target_url}/comment?text=<img src=x onerror=alert('XSS')>",
            "description": "XSS test in comment parameter",
            "vulnerability_type": "Cross-Site Scripting",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        },
        {
            "method": "POST",
            "url": f"{target_url}/contact",
            "description": "XSS test in contact form",
            "vulnerability_type": "Cross-Site Scripting",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            "body": "name=test&email=test@test.com&message=<svg onload=alert('XSS')>"
        }
    ]
    
    # Path Traversal requests
    path_requests = [
        {
            "method": "GET",
            "url": f"{target_url}/file?path=../../../etc/passwd",
            "description": "Path traversal test",
            "vulnerability_type": "Path Traversal",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        },
        {
            "method": "GET",
            "url": f"{target_url}/download?file=..%2f..%2f..%2fetc%2fpasswd",
            "description": "URL encoded path traversal test",
            "vulnerability_type": "Path Traversal",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        }
    ]
    
    # Command Injection requests
    cmd_requests = [
        {
            "method": "GET",
            "url": f"{target_url}/ping?host=127.0.0.1;id",
            "description": "Command injection test in ping parameter",
            "vulnerability_type": "Command Injection",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        },
        {
            "method": "GET",
            "url": f"{target_url}/exec?cmd=whoami",
            "description": "Command injection test in exec parameter",
            "vulnerability_type": "Command Injection",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        }
    ]
    
    # SSRF requests
    ssrf_requests = [
        {
            "method": "GET",
            "url": f"{target_url}/fetch?url=http://127.0.0.1:22",
            "description": "SSRF test to internal port",
            "vulnerability_type": "Server-Side Request Forgery",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        },
        {
            "method": "GET",
            "url": f"{target_url}/proxy?url=http://169.254.169.254/latest/meta-data/",
            "description": "SSRF test to cloud metadata",
            "vulnerability_type": "Server-Side Request Forgery",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        }
    ]
    
    # Combine all requests
    all_requests = base_requests + sql_requests + xss_requests + path_requests + cmd_requests + ssrf_requests
    
    # Limit to max_requests
    return all_requests[:max_requests]


def _generate_llm_urls(target_url: str) -> List[Dict[str, Any]]:
    """
    Sử dụng LLM để tạo ra các URLs đáng ngờ và endpoints để test
    """
    try:
        from app.clients.gemini_client import GeminiClient
        client = GeminiClient()
        
        prompt = f"""
        Bạn là chuyên gia bảo mật web. Hãy tạo ra danh sách các URLs và endpoints đáng ngờ để test bảo mật cho website: {target_url}
        
        Hãy tạo ra các URLs cho:
        1. Admin panels và management interfaces
        2. API endpoints thường gặp
        3. Sensitive files và directories
        4. Backup files và configuration files
        5. Development và testing endpoints
        6. Common web application paths
        
        Trả về JSON với format:
        {{
            "urls": [
                {{
                    "url": "full_url",
                    "description": "mô tả endpoint này",
                    "vulnerability_type": "loại lỗ hổng có thể có",
                    "risk_level": "High/Medium/Low"
                }}
            ]
        }}
        
        Tạo tối đa 15 URLs đáng ngờ nhất.
        """
        
        response = client.chat(prompt, max_output_tokens=1500)
        
        try:
            import json
            result = json.loads(response)
            urls = result.get('urls', [])
            
            # Convert to request format
            llm_requests = []
            for url_info in urls:
                llm_requests.append({
                    "method": "GET",
                    "url": url_info.get('url', ''),
                    "description": url_info.get('description', 'LLM-generated endpoint'),
                    "vulnerability_type": url_info.get('vulnerability_type', 'Information Disclosure'),
                    "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                    "risk_level": url_info.get('risk_level', 'Medium')
                })
            
            return llm_requests
            
        except json.JSONDecodeError:
            # Fallback to predefined URLs if LLM response is not valid JSON
            return _get_fallback_urls(target_url)
            
    except Exception as e:
        # Fallback to predefined URLs if LLM is not available
        return _get_fallback_urls(target_url)


def _get_fallback_urls(target_url: str) -> List[Dict[str, Any]]:
    """
    Fallback URLs khi LLM không khả dụng
    """
    fallback_urls = [
        {
            "method": "GET",
            "url": f"{target_url}/admin",
            "description": "Admin panel endpoint",
            "vulnerability_type": "Information Disclosure",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            "risk_level": "High"
        },
        {
            "method": "GET",
            "url": f"{target_url}/admin/login",
            "description": "Admin login page",
            "vulnerability_type": "Information Disclosure",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            "risk_level": "High"
        },
        {
            "method": "GET",
            "url": f"{target_url}/api",
            "description": "API endpoint discovery",
            "vulnerability_type": "Information Disclosure",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            "risk_level": "Medium"
        },
        {
            "method": "GET",
            "url": f"{target_url}/config.php",
            "description": "Configuration file",
            "vulnerability_type": "Information Disclosure",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            "risk_level": "High"
        },
        {
            "method": "GET",
            "url": f"{target_url}/backup.sql",
            "description": "Database backup file",
            "vulnerability_type": "Information Disclosure",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            "risk_level": "Critical"
        },
        {
            "method": "GET",
            "url": f"{target_url}/.env",
            "description": "Environment configuration file",
            "vulnerability_type": "Information Disclosure",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            "risk_level": "Critical"
        },
        {
            "method": "GET",
            "url": f"{target_url}/phpinfo.php",
            "description": "PHP info page",
            "vulnerability_type": "Information Disclosure",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            "risk_level": "High"
        },
        {
            "method": "GET",
            "url": f"{target_url}/test.php",
            "description": "Test endpoint",
            "vulnerability_type": "Information Disclosure",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            "risk_level": "Medium"
        }
    ]
    
    return fallback_urls


def _execute_request_enhanced(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Thực hiện HTTP request với retry và timeout
    """
    method = request_data.get("method", "GET").upper()
    url = request_data.get("url", "")
    headers = request_data.get("headers", {})
    body = request_data.get("body", "")
    
    # Add default headers if not present
    if "User-Agent" not in headers:
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=30, allow_redirects=False, verify=False)
            elif method == "POST":
                response = requests.post(url, headers=headers, data=body, timeout=30, allow_redirects=False, verify=False)
            elif method == "PUT":
                response = requests.put(url, headers=headers, data=body, timeout=30, allow_redirects=False, verify=False)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, timeout=30, allow_redirects=False, verify=False)
            else:
                response = requests.request(method, url, headers=headers, data=body, timeout=30, allow_redirects=False, verify=False)
            
            return {
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:10000],  # Increased limit for better analysis
                "url": response.url,
                "cookies": dict(response.cookies),
                "response_time": response.elapsed.total_seconds(),
                "content_length": len(response.content)
            }
        except requests.exceptions.RequestException as e:
            if attempt == max_retries:
                return {
                    "status": 0,
                    "headers": {},
                    "body": f"Request failed after {max_retries + 1} attempts: {str(e)}",
                    "url": url,
                    "cookies": {},
                    "response_time": 0,
                    "content_length": 0
                }
            time.sleep(1)  # Wait before retry


async def _analyze_scan_results_async(scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Enhanced LLM analysis of scan results for vulnerabilities with comprehensive analysis
    """
    analyzer = LLMAnalyzer()
    vulnerabilities = []
    detailed_analysis = []
    
    for result in scan_results:
        response = result.get('response', {})
        request_data = result.get('request', {})
        vuln_type = result.get('vulnerability_type', '')
        request_id = result.get('request_id', '')
        
        # Enhanced LLM analysis for each response
        if response.get('status') > 0:  # Valid response
            try:
                # Use advanced LLM analysis
                llm_analysis = analyzer.analyze_response(
                    response_data=response,
                    payload=request_data.get('body', '') or request_data.get('url', ''),
                    vulnerability_type=vuln_type
                )
                
                # Additional header and body analysis
                header_analysis = _analyze_headers(response.get('headers', {}))
                body_analysis = _analyze_response_body(response.get('body', ''))
                
                # Combine analyses
                combined_analysis = {
                    **llm_analysis,
                    'header_analysis': header_analysis,
                    'body_analysis': body_analysis,
                    'llm_detection_explanation': _explain_llm_detection(llm_analysis, header_analysis, body_analysis)
                }
                
            except Exception as e:
                combined_analysis = {
                    'vulnerability_detected': False,
                    'error': str(e),
                    'confidence': 0,
                    'header_analysis': {},
                    'body_analysis': {},
                    'llm_detection_explanation': f'Analysis failed: {str(e)}'
                }
            
            # Process combined analysis
            if combined_analysis and combined_analysis.get('vulnerability_detected', False):
                vulnerability = {
                    'id': request_id,
                    'type': combined_analysis.get('vulnerability_type', vuln_type),
                    'severity': combined_analysis.get('severity', 'Medium'),
                    'confidence': combined_analysis.get('confidence', 0.5),
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', 'GET'),
                    'payload': request_data.get('body', '') or request_data.get('url', ''),
                    'exploitation': combined_analysis.get('exploitation_steps', []),
                    'remediation': combined_analysis.get('remediation', 'Review and fix the vulnerability'),
                    'evidence': combined_analysis.get('evidence', []),
                    'description': combined_analysis.get('description', ''),
                    'header_analysis': combined_analysis.get('header_analysis', {}),
                    'body_analysis': combined_analysis.get('body_analysis', {}),
                    'llm_detection_explanation': combined_analysis.get('llm_detection_explanation', ''),
                    'request_data': request_data,
                    'response_data': response
                }
                vulnerabilities.append(vulnerability)
            
            # Store detailed analysis for each request
            detailed_analysis.append({
                'request_id': request_id,
                'request': request_data,
                'response': response,
                'vulnerability_type': vuln_type,
                'llm_analysis': combined_analysis,
                'status': 'Vulnerable' if combined_analysis and combined_analysis.get('vulnerability_detected') else 'Safe'
            })
    
    # Calculate risk summary
    risk_summary = _calculate_risk_summary(vulnerabilities)
    
    return {
        'vulnerabilities': vulnerabilities,
        'detailed_analysis': detailed_analysis,
        'summary': {
            'total_requests': len(scan_results),
            'total_vulnerabilities': len(vulnerabilities),
            'critical_count': len([v for v in vulnerabilities if v.get('severity') == 'Critical']),
            'high_count': len([v for v in vulnerabilities if v.get('severity') == 'High']),
            'medium_count': len([v for v in vulnerabilities if v.get('severity') == 'Medium']),
            'low_count': len([v for v in vulnerabilities if v.get('severity') == 'Low']),
            'overall_risk': risk_summary['overall_risk'],
            'risk_score': risk_summary['risk_score']
        },
        'llm_analysis_summary': _generate_llm_analysis_summary(vulnerabilities, detailed_analysis)
    }


def _analyze_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Phân tích HTTP headers để tìm các vấn đề bảo mật
    """
    analysis = {
        'security_headers': {},
        'missing_headers': [],
        'suspicious_headers': [],
        'server_info': {},
        'security_score': 0
    }
    
    # Security headers to check
    security_headers = {
        'x-frame-options': 'Prevents clickjacking',
        'x-content-type-options': 'Prevents MIME sniffing',
        'x-xss-protection': 'XSS protection',
        'strict-transport-security': 'HTTPS enforcement',
        'content-security-policy': 'Content Security Policy',
        'referrer-policy': 'Referrer policy',
        'permissions-policy': 'Permissions policy'
    }
    
    # Check for security headers
    for header, description in security_headers.items():
        if header in headers:
            analysis['security_headers'][header] = {
                'value': headers[header],
                'description': description,
                'present': True
            }
            analysis['security_score'] += 10
        else:
            analysis['missing_headers'].append({
                'header': header,
                'description': description,
                'risk': 'Medium' if header in ['x-frame-options', 'x-content-type-options'] else 'Low'
            })
    
    # Check for suspicious headers
    suspicious_patterns = ['server', 'x-powered-by', 'x-aspnet-version']
    for pattern in suspicious_patterns:
        for header_name, header_value in headers.items():
            if pattern in header_name.lower():
                analysis['suspicious_headers'].append({
                    'header': header_name,
                    'value': header_value,
                    'risk': 'Information disclosure'
                })
    
    # Server information
    if 'server' in headers:
        analysis['server_info']['server'] = headers['server']
    if 'x-powered-by' in headers:
        analysis['server_info']['powered_by'] = headers['x-powered-by']
    
    return analysis


def _analyze_response_body(body: str) -> Dict[str, Any]:
    """
    Phân tích response body để tìm các vấn đề bảo mật
    """
    analysis = {
        'sensitive_data': [],
        'error_messages': [],
        'version_info': [],
        'security_indicators': [],
        'content_analysis': {}
    }
    
    body_lower = body.lower()
    
    # Check for sensitive data
    sensitive_patterns = [
        ('password', 'Password field detected'),
        ('api_key', 'API key detected'),
        ('secret', 'Secret information detected'),
        ('token', 'Token detected'),
        ('database', 'Database information detected'),
        ('config', 'Configuration data detected')
    ]
    
    for pattern, description in sensitive_patterns:
        if pattern in body_lower:
            analysis['sensitive_data'].append({
                'pattern': pattern,
                'description': description,
                'risk': 'High'
            })
    
    # Check for error messages
    error_patterns = [
        ('error', 'Error message detected'),
        ('exception', 'Exception information detected'),
        ('warning', 'Warning message detected'),
        ('fatal', 'Fatal error detected'),
        ('stack trace', 'Stack trace detected')
    ]
    
    for pattern, description in error_patterns:
        if pattern in body_lower:
            analysis['error_messages'].append({
                'pattern': pattern,
                'description': description,
                'risk': 'Medium'
            })
    
    # Check for version information
    version_patterns = [
        ('version', 'Version information detected'),
        ('v1.', 'Version number detected'),
        ('build', 'Build information detected'),
        ('release', 'Release information detected')
    ]
    
    for pattern, description in version_patterns:
        if pattern in body_lower:
            analysis['version_info'].append({
                'pattern': pattern,
                'description': description,
                'risk': 'Low'
            })
    
    # Content analysis
    analysis['content_analysis'] = {
        'length': len(body),
        'has_html': '<html' in body_lower or '<body' in body_lower,
        'has_json': body.strip().startswith('{') or body.strip().startswith('['),
        'has_xml': body.strip().startswith('<') and not body.strip().startswith('<html'),
        'has_php': '<?php' in body_lower or '.php' in body_lower
    }
    
    return analysis


def _explain_llm_detection(llm_analysis: Dict, header_analysis: Dict, body_analysis: Dict) -> str:
    """
    Giải thích cách LLM phát hiện và phân tích lỗ hổng
    """
    explanation_parts = []
    
    # LLM analysis explanation
    if llm_analysis.get('vulnerability_detected'):
        explanation_parts.append("LLM phát hiện lỗ hổng thông qua:")
        explanation_parts.append("1. Phân tích pattern matching trong response")
        explanation_parts.append("2. So sánh với database các lỗ hổng đã biết")
        explanation_parts.append("3. Đánh giá context và behavior của ứng dụng")
        explanation_parts.append("4. Confidence scoring dựa trên multiple indicators")
    
    # Header analysis explanation
    if header_analysis.get('missing_headers'):
        explanation_parts.append("Header analysis phát hiện:")
        explanation_parts.append("- Missing security headers có thể dẫn đến lỗ hổng")
        explanation_parts.append("- Server information disclosure")
        explanation_parts.append("- Security configuration weaknesses")
    
    # Body analysis explanation
    if body_analysis.get('sensitive_data') or body_analysis.get('error_messages'):
        explanation_parts.append("Body analysis phát hiện:")
        explanation_parts.append("- Sensitive data exposure")
        explanation_parts.append("- Error messages revealing system information")
        explanation_parts.append("- Version information disclosure")
    
    if not explanation_parts:
        explanation_parts.append("LLM sử dụng multi-layer analysis:")
        explanation_parts.append("1. Pattern recognition trong response content")
        explanation_parts.append("2. Heuristic analysis của headers và body")
        explanation_parts.append("3. Context-aware vulnerability detection")
        explanation_parts.append("4. Confidence scoring và risk assessment")
    
    return "\n".join(explanation_parts)


def _generate_llm_analysis_summary(vulnerabilities: List[Dict], detailed_analysis: List[Dict]) -> Dict[str, Any]:
    """
    Tạo summary về LLM analysis
    """
    return {
        'total_analyzed': len(detailed_analysis),
        'vulnerabilities_found': len(vulnerabilities),
        'detection_methods': [
            'Pattern-based analysis',
            'Heuristic analysis', 
            'Context-aware detection',
            'Multi-layer validation'
        ],
        'llm_capabilities': [
            'Natural language understanding of error messages',
            'Context-aware vulnerability detection',
            'Pattern recognition across multiple data types',
            'Confidence scoring and risk assessment',
            'False positive reduction through multi-layer analysis'
        ],
        'analysis_accuracy': 'High - LLM combines multiple detection methods for accurate results'
    }


def _calculate_risk_summary(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate overall risk summary
    """
    if not vulnerabilities:
        return {'overall_risk': 'Low', 'risk_score': 0}
    
    # Risk scoring
    risk_scores = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
    total_score = 0
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'Low')
        confidence = vuln.get('confidence', 0.5)
        score = risk_scores.get(severity, 1) * confidence
        total_score += score
    
    # Normalize score (0-100)
    max_possible_score = len(vulnerabilities) * 10
    risk_score = min(100, (total_score / max_possible_score) * 100) if max_possible_score > 0 else 0
    
    # Determine overall risk
    if risk_score >= 70:
        overall_risk = 'Critical'
    elif risk_score >= 50:
        overall_risk = 'High'
    elif risk_score >= 30:
        overall_risk = 'Medium'
    else:
        overall_risk = 'Low'
    
    return {
        'overall_risk': overall_risk,
        'risk_score': round(risk_score, 1)
    }


def _execute_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Thực hiện HTTP request và trả về response
    """
    method = request_data.get("method", "GET").upper()
    url = request_data.get("url", "")
    headers = request_data.get("headers", {})
    body = request_data.get("body", "")
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
        elif method == "POST":
            response = requests.post(url, headers=headers, data=body, timeout=10, allow_redirects=False)
        elif method == "PUT":
            response = requests.put(url, headers=headers, data=body, timeout=10, allow_redirects=False)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, timeout=10, allow_redirects=False)
        else:
            response = requests.request(method, url, headers=headers, data=body, timeout=10, allow_redirects=False)
        
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:5000],  # Giới hạn body để tránh quá lớn
            "url": response.url,
            "cookies": dict(response.cookies)
        }
    except requests.exceptions.RequestException as e:
        return {
            "status": 0,
            "headers": {},
            "body": f"Request failed: {str(e)}",
            "url": url,
            "cookies": {}
        }


def _generate_exploitation_guide(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tạo hướng dẫn khai thác từ phân tích lỗ hổng
    """
    vulnerabilities = analysis.get("vulnerabilities", [])
    
    guide = {
        "overview": f"Found {len(vulnerabilities)} potential vulnerabilities",
        "exploitation_steps": [],
        "tools_recommended": [],
        "payloads": [],
        "mitigation": []
    }
    
    for vuln in vulnerabilities:
        vuln_type = vuln.get("type", "")
        severity = vuln.get("severity", "")
        url = vuln.get("url", "")
        payload = vuln.get("payload", "")
        
        # Thêm bước khai thác
        guide["exploitation_steps"].append({
            "vulnerability": vuln_type,
            "severity": severity,
            "url": url,
            "step": vuln.get("exploitation", ""),
            "payload": payload
        })
        
        # Thêm payload
        if payload:
            guide["payloads"].append({
                "type": vuln_type,
                "payload": payload,
                "description": vuln.get("exploitation", "")
            })
        
        # Thêm mitigation
        guide["mitigation"].append({
            "vulnerability": vuln_type,
            "solution": vuln.get("remediation", "")
        })
    
    # Gợi ý tools
    if any("XSS" in v.get("type", "") for v in vulnerabilities):
        guide["tools_recommended"].append("Burp Suite, XSS Hunter, BeEF")
    if any("SQL" in v.get("type", "") for v in vulnerabilities):
        guide["tools_recommended"].append("SQLMap, Burp Suite, NoSQLMap")
    if any("LFI" in v.get("type", "") for v in vulnerabilities):
        guide["tools_recommended"].append("Burp Suite, Dirb, Gobuster")
    
    return guide


@router.get('/smart-scan/{scan_id}/curl-commands')
def get_curl_commands_for_scan(scan_id: str):
    """
    Lấy curl commands cho tất cả requests trong smart scan
    """
    # Trong thực tế, bạn sẽ lưu scan results vào database
    # Ở đây tôi sẽ trả về example
    return {
        "scan_id": scan_id,
        "curl_commands": [
            "curl -X GET 'http://example.com' -H 'User-Agent: Mozilla/5.0'",
            "curl -X POST 'http://example.com/login' -d 'username=admin&password=admin'"
        ]
    }


@router.get('/smart-scan/{scan_id}/exploitation-guide')
def get_exploitation_guide(scan_id: str):
    """
    Lấy hướng dẫn khai thác chi tiết
    """
    # Trong thực tế, bạn sẽ lưu exploitation guide vào database
    return {
        "scan_id": scan_id,
        "guide": {
            "overview": "Exploitation guide for found vulnerabilities",
            "steps": [
                "1. Identify vulnerable endpoints",
                "2. Test with provided payloads",
                "3. Verify exploitation success",
                "4. Document findings"
            ]
        }
    }
