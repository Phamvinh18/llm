"""
Enhanced Scan Engine - Comprehensive security scanning with AI analysis
"""

import os
import json
import time
import requests
import subprocess
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import ssl
import socket

class ScanProfile(Enum):
    FAST = "fast"
    ENHANCED = "enhanced" 
    DEEP = "deep"

@dataclass
class ScanFinding:
    type: str
    severity: str
    path: str
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    description: str = ""
    cwe: Optional[str] = None
    confidence: float = 0.0

@dataclass
class ScanResult:
    target_url: str
    profile: str
    start_time: float
    end_time: float
    findings: List[ScanFinding]
    http_response: Dict[str, Any]
    headers_analysis: Dict[str, Any]
    body_analysis: Dict[str, Any]
    technology_stack: Dict[str, Any]
    discovered_paths: List[Dict[str, Any]]
    security_score: float
    llm_analysis: Optional[str] = None

class EnhancedScanEngine:
    def __init__(self):
        self.data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
        self.rag_data = self._load_enhanced_rag()
        
    def _load_enhanced_rag(self) -> Dict[str, Any]:
        """Load enhanced RAG data"""
        try:
            rag_file = os.path.join(self.data_dir, 'enhanced_master_rag.json')
            with open(rag_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load enhanced RAG: {e}")
            return {}
    
    def _run_command(self, command: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Run shell command safely"""
        try:
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                cwd=os.getcwd()
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Command timed out",
                "returncode": -1
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": -1
            }
    
    def _perform_http_request(self, url: str, method: str = "GET", **kwargs) -> Dict[str, Any]:
        """Perform HTTP request with error handling"""
        try:
            response = requests.request(
                method=method,
                url=url,
                timeout=15,
                allow_redirects=True,
                verify=False,
                **kwargs
            )
            
            return {
                "success": True,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": response.text,
                "url": response.url,
                "history": [r.url for r in response.history],
                "elapsed": response.elapsed.total_seconds()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "status_code": None,
                "headers": {},
                "content": "",
                "url": url,
                "history": [],
                "elapsed": 0
            }
    
    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze HTTP headers for security issues with enhanced scoring"""
        security_headers = {
            "Content-Security-Policy": {"present": False, "value": "", "score": 0, "weight": 3},
            "X-Frame-Options": {"present": False, "value": "", "score": 0, "weight": 2},
            "X-Content-Type-Options": {"present": False, "value": "", "score": 0, "weight": 2},
            "Strict-Transport-Security": {"present": False, "value": "", "score": 0, "weight": 3},
            "X-XSS-Protection": {"present": False, "value": "", "score": 0, "weight": 1},
            "Referrer-Policy": {"present": False, "value": "", "score": 0, "weight": 1},
            "Permissions-Policy": {"present": False, "value": "", "score": 0, "weight": 2},
            "Cross-Origin-Embedder-Policy": {"present": False, "value": "", "score": 0, "weight": 1},
            "Cross-Origin-Opener-Policy": {"present": False, "value": "", "score": 0, "weight": 1},
            "Cross-Origin-Resource-Policy": {"present": False, "value": "", "score": 0, "weight": 1}
        }
        
        # Check for security headers with enhanced analysis
        for header_name in security_headers:
            if header_name in headers:
                security_headers[header_name]["present"] = True
                security_headers[header_name]["value"] = headers[header_name]
                
                # Enhanced scoring based on header quality
                header_value = headers[header_name].lower()
                base_score = security_headers[header_name]["weight"]
                
                # CSP quality check
                if header_name == "Content-Security-Policy":
                    if "default-src 'self'" in header_value and "script-src" in header_value:
                        security_headers[header_name]["score"] = base_score
                    elif "default-src" in header_value:
                        security_headers[header_name]["score"] = base_score * 0.7
                    else:
                        security_headers[header_name]["score"] = base_score * 0.3
                
                # HSTS quality check
                elif header_name == "Strict-Transport-Security":
                    if "max-age=31536000" in header_value and "includesubdomains" in header_value:
                        security_headers[header_name]["score"] = base_score
                    elif "max-age=31536000" in header_value:
                        security_headers[header_name]["score"] = base_score * 0.8
                    else:
                        security_headers[header_name]["score"] = base_score * 0.5
                
                # X-Frame-Options quality check
                elif header_name == "X-Frame-Options":
                    if header_value in ["deny", "sameorigin"]:
                        security_headers[header_name]["score"] = base_score
                    else:
                        security_headers[header_name]["score"] = base_score * 0.5
                
                else:
                    security_headers[header_name]["score"] = base_score
        
        # Calculate weighted security score
        total_weight = sum(h["weight"] for h in security_headers.values())
        weighted_score = sum(h["score"] for h in security_headers.values())
        security_score = (weighted_score / total_weight) * 100 if total_weight > 0 else 0
        
        # Enhanced suspicious headers detection
        suspicious_headers = []
        
        # Server version disclosure
        server_header = headers.get("Server", "")
        if server_header:
            # Check for version numbers
            if re.search(r'\d+\.\d+', server_header):
                suspicious_headers.append({
                    "header": "Server",
                    "value": server_header,
                    "issue": "Version disclosure - reveals server version",
                    "severity": "Medium"
                })
        
        # X-Powered-By disclosure
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            suspicious_headers.append({
                "header": "X-Powered-By",
                "value": powered_by,
                "issue": "Technology disclosure - reveals backend technology",
                "severity": "Low"
            })
        
        # Missing security headers analysis
        missing_headers = []
        for header_name, header_info in security_headers.items():
            if not header_info["present"]:
                missing_headers.append({
                    "header": header_name,
                    "description": self._get_header_description(header_name),
                    "severity": "High" if header_info["weight"] >= 3 else "Medium" if header_info["weight"] >= 2 else "Low"
                })
        
        return {
            "security_headers": security_headers,
            "security_score": round(security_score, 1),
            "suspicious_headers": suspicious_headers,
            "missing_headers": missing_headers,
            "total_headers": len(headers),
            "recommendations": self._get_security_recommendations(security_headers, missing_headers)
        }
    
    def _get_header_description(self, header_name: str) -> str:
        """Get description for security header"""
        descriptions = {
            "Content-Security-Policy": "Prevents XSS attacks by controlling resource loading",
            "X-Frame-Options": "Prevents clickjacking attacks",
            "X-Content-Type-Options": "Prevents MIME type sniffing attacks",
            "Strict-Transport-Security": "Enforces HTTPS connections",
            "X-XSS-Protection": "Enables browser XSS filtering",
            "Referrer-Policy": "Controls referrer information sent with requests",
            "Permissions-Policy": "Controls browser features and APIs",
            "Cross-Origin-Embedder-Policy": "Controls cross-origin embedding",
            "Cross-Origin-Opener-Policy": "Controls cross-origin window access",
            "Cross-Origin-Resource-Policy": "Controls cross-origin resource access"
        }
        return descriptions.get(header_name, "Security header")
    
    def _get_security_recommendations(self, security_headers: Dict, missing_headers: List) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if missing_headers:
            high_priority = [h for h in missing_headers if h["severity"] == "High"]
            if high_priority:
                recommendations.append(f"CRITICAL: Implement {len(high_priority)} high-priority security headers")
            
            medium_priority = [h for h in missing_headers if h["severity"] == "Medium"]
            if medium_priority:
                recommendations.append(f"IMPORTANT: Add {len(medium_priority)} medium-priority security headers")
        
        # Check for weak CSP
        csp = security_headers.get("Content-Security-Policy", {})
        if csp.get("present") and csp.get("score", 0) < csp.get("weight", 0) * 0.7:
            recommendations.append("IMPROVE: Strengthen Content-Security-Policy configuration")
        
        # Check for weak HSTS
        hsts = security_headers.get("Strict-Transport-Security", {})
        if hsts.get("present") and hsts.get("score", 0) < hsts.get("weight", 0) * 0.8:
            recommendations.append("IMPROVE: Enhance HSTS configuration with longer max-age")
        
        return recommendations
    
    def _analyze_response_body(self, content: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze response body for security issues"""
        analysis = {
            "content_type": headers.get("Content-Type", ""),
            "content_length": len(content),
            "has_forms": False,
            "has_javascript": False,
            "sensitive_info": [],
            "error_messages": [],
            "version_info": [],
            "debug_info": []
        }
        
        # Check for forms
        if "<form" in content.lower():
            analysis["has_forms"] = True
        
        # Check for JavaScript
        if "<script" in content.lower() or "javascript:" in content.lower():
            analysis["has_javascript"] = True
        
        # Check for sensitive information
        sensitive_patterns = [
            r"password\s*[:=]\s*['\"][^'\"]*['\"]",
            r"api[_-]?key\s*[:=]\s*['\"][^'\"]*['\"]",
            r"secret\s*[:=]\s*['\"][^'\"]*['\"]",
            r"token\s*[:=]\s*['\"][^'\"]*['\"]"
        ]
        
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            analysis["sensitive_info"].extend(matches)
        
        # Check for error messages
        error_patterns = [
            r"error\s*[:=]\s*['\"][^'\"]*['\"]",
            r"exception\s*[:=]\s*['\"][^'\"]*['\"]",
            r"warning\s*[:=]\s*['\"][^'\"]*['\"]"
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            analysis["error_messages"].extend(matches)
        
        # Check for version information
        version_patterns = [
            r"version\s*[:=]\s*['\"][^'\"]*['\"]",
            r"v\d+\.\d+",
            r"build\s*[:=]\s*['\"][^'\"]*['\"]"
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            analysis["version_info"].extend(matches)
        
        return analysis
    
    def _detect_technology(self, content: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Detect technology stack"""
        tech_stack = {
            "web_server": "Unknown",
            "cms": [],
            "frameworks": [],
            "languages": []
        }
        
        # Detect web server from headers
        server_header = headers.get("Server", "").lower()
        if "nginx" in server_header:
            tech_stack["web_server"] = "Nginx"
        elif "apache" in server_header:
            tech_stack["web_server"] = "Apache"
        elif "iis" in server_header:
            tech_stack["web_server"] = "IIS"
        
        # Detect CMS
        if "wp-content" in content or "wordpress" in content.lower():
            tech_stack["cms"].append("WordPress")
        if "drupal" in content.lower():
            tech_stack["cms"].append("Drupal")
        if "joomla" in content.lower():
            tech_stack["cms"].append("Joomla")
        
        # Detect frameworks
        if "bootstrap" in content.lower():
            tech_stack["frameworks"].append("Bootstrap")
        if "jquery" in content.lower():
            tech_stack["frameworks"].append("jQuery")
        if "react" in content.lower():
            tech_stack["frameworks"].append("React")
        if "angular" in content.lower():
            tech_stack["frameworks"].append("Angular")
        
        # Detect programming languages
        if "<?php" in content:
            tech_stack["languages"].append("PHP")
        if "asp.net" in content.lower():
            tech_stack["languages"].append("ASP.NET")
        if "python" in content.lower():
            tech_stack["languages"].append("Python")
        
        return tech_stack
    
    def _discover_paths(self, base_url: str) -> List[Dict[str, Any]]:
        """Enhanced path discovery with comprehensive wordlist"""
        # Comprehensive wordlist for path discovery
        common_paths = [
            # Admin panels
            "/admin", "/administrator", "/admin.php", "/admin/", "/admin/login",
            "/wp-admin", "/wp-login.php", "/wp-admin/admin.php", "/wp-admin/install.php",
            "/user", "/users", "/login", "/signin", "/auth", "/authentication",
            "/dashboard", "/panel", "/control", "/manage", "/management",
            
            # API endpoints
            "/api", "/api/", "/api/v1", "/api/v2", "/rest", "/rest/",
            "/graphql", "/graphql/", "/swagger", "/swagger-ui", "/docs", "/documentation",
            "/openapi.json", "/api-docs", "/api.json", "/api.yaml",
            
            # Development & Testing
            "/test", "/testing", "/dev", "/development", "/staging", "/stage",
            "/debug", "/debug.php", "/phpinfo.php", "/info.php", "/test.php",
            "/demo", "/sample", "/example", "/sandbox", "/playground",
            
            # Configuration files
            "/.env", "/.env.local", "/.env.production", "/.env.development",
            "/config.php", "/configuration.php", "/wp-config.php", "/settings.php",
            "/database.yml", "/database.yaml", "/database.json", "/database.sql",
            "/app.config", "/web.config", "/application.properties",
            
            # Backup files
            "/backup", "/backup/", "/backup.sql", "/backup.zip", "/backup.tar.gz",
            "/backups", "/backups/", "/db_backup", "/database_backup",
            "/old", "/old/", "/archive", "/archives", "/temp_backup",
            
            # Version control
            "/.git/", "/.git/config", "/.git/HEAD", "/.git/index",
            "/.svn/", "/.svn/entries", "/.hg/", "/.bzr/",
            "/.gitignore", "/.svnignore", "/.hgignore",
            
            # Common files
            "/robots.txt", "/sitemap.xml", "/sitemap.txt", "/.htaccess",
            "/crossdomain.xml", "/clientaccesspolicy.xml", "/favicon.ico",
            "/humans.txt", "/security.txt", "/.well-known/security.txt",
            
            # Database management
            "/phpmyadmin/", "/phpmyadmin/index.php", "/phpmyadmin/setup/",
            "/adminer.php", "/adminer/", "/pma/", "/mysql/", "/db/",
            "/database/", "/dbadmin/", "/sql/", "/sqladmin/",
            
            # File uploads & media
            "/uploads/", "/upload/", "/files/", "/file/", "/media/",
            "/images/", "/img/", "/pictures/", "/photos/", "/assets/",
            "/static/", "/public/", "/www/", "/web/", "/htdocs/",
            
            # Logs & temporary files
            "/logs/", "/log/", "/error.log", "/access.log", "/error_log",
            "/access_log", "/debug.log", "/application.log", "/system.log",
            "/tmp/", "/temp/", "/temporary/", "/cache/", "/cached/",
            
            # Web shells & malicious files
            "/shell.php", "/webshell.php", "/c99.php", "/r57.php",
            "/b374k.php", "/wso.php", "/indoxploit.php", "/admin.php",
            "/cmd.php", "/eval.php", "/exec.php", "/system.php",
            
            # CMS specific
            "/wp-content/", "/wp-includes/", "/wp-json/", "/xmlrpc.php",
            "/drupal/", "/joomla/", "/magento/", "/prestashop/",
            "/opencart/", "/zencart/", "/oscommerce/",
            
            # Framework specific
            "/laravel/", "/symfony/", "/yii/", "/codeigniter/",
            "/cakephp/", "/zend/", "/phalcon/", "/fuel/",
            
            # Server information
            "/server-status", "/server-info", "/status", "/info",
            "/health", "/ping", "/monitor", "/metrics", "/stats",
            
            # Search & discovery
            "/search", "/find", "/lookup", "/query", "/browse",
            "/directory", "/dir", "/list", "/index", "/contents",
            
            # Authentication bypass
            "/login.php", "/login.html", "/signin.php", "/auth.php",
            "/authenticate.php", "/user.php", "/account.php", "/profile.php",
            
            # Error pages
            "/404", "/500", "/error", "/errors", "/notfound",
            "/forbidden", "/unauthorized", "/maintenance", "/offline"
        ]
        
        discovered = []
        print(f"[FOLDER] Scanning {len(common_paths)} common paths...")
        
        for i, path in enumerate(common_paths):
            if i % 20 == 0:  # Progress indicator
                print(f"[FOLDER] Progress: {i}/{len(common_paths)} paths checked")
            
            full_url = urljoin(base_url, path)
            response = self._perform_http_request(full_url)
            
            if response["success"] and response["status_code"] in [200, 301, 302, 403, 401]:
                # Enhanced analysis for discovered paths
                path_info = {
                    "path": path,
                    "url": full_url,
                    "status_code": response["status_code"],
                    "content_length": len(response["content"]),
                    "content_type": response["headers"].get("Content-Type", ""),
                    "server": response["headers"].get("Server", ""),
                    "title": self._extract_title(response["content"]),
                    "sensitive": self._is_sensitive_path(path),
                    "risk_level": self._assess_path_risk(path, response["status_code"])
                }
                
                # Add additional info for interesting paths
                if response["status_code"] == 200 and len(response["content"]) > 0:
                    path_info["has_forms"] = "<form" in response["content"].lower()
                    path_info["has_login"] = any(keyword in response["content"].lower() for keyword in ["login", "password", "username", "sign in"])
                    path_info["has_admin"] = any(keyword in response["content"].lower() for keyword in ["admin", "administrator", "dashboard", "control panel"])
                
                discovered.append(path_info)
        
        # Sort by risk level and sensitivity
        discovered.sort(key=lambda x: (x["risk_level"], x["sensitive"]), reverse=True)
        
        print(f"[FOLDER] Discovered {len(discovered)} accessible paths")
        return discovered
    
    def _extract_title(self, content: str) -> str:
        """Extract page title from HTML content"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                return title_tag.get_text().strip()[:100]
        except:
            pass
        return ""
    
    def _is_sensitive_path(self, path: str) -> bool:
        """Check if path is sensitive"""
        sensitive_keywords = [
            "admin", "login", "config", "backup", "database", "git", "svn",
            "phpmyadmin", "shell", "webshell", "upload", "tmp", "log",
            "env", "secret", "key", "password", "token", "api"
        ]
        path_lower = path.lower()
        return any(keyword in path_lower for keyword in sensitive_keywords)
    
    def _assess_path_risk(self, path: str, status_code: int) -> str:
        """Assess risk level of discovered path"""
        if status_code == 403:
            return "Medium"  # Forbidden but exists
        elif status_code == 401:
            return "Medium"  # Unauthorized but exists
        elif status_code in [200, 301, 302]:
            if self._is_sensitive_path(path):
                return "High"  # Sensitive path accessible
            else:
                return "Low"  # Normal path accessible
        return "Unknown"
    
    def _scan_xss_vulnerabilities(self, target_url: str) -> List[ScanFinding]:
        """Enhanced XSS vulnerability scanning with comprehensive detection"""
        findings = []
        
        # Comprehensive XSS payloads with various encoding techniques
        xss_payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            
            # Event handlers
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input autofocus onfocus=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            
            # JavaScript protocol
            "javascript:alert('XSS')",
            "javascript:alert(1)",
            
            # Attribute injection
            "'><script>alert('XSS')</script>",
            ""><script>alert('XSS')</script>",
            "'><img src=x onerror=alert('XSS')>",
            ""><img src=x onerror=alert('XSS')>",
            
            # Filter bypass techniques
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>al\x65rt('XSS')</script>",
            "<script>alert\x28\x27XSS\x27\x29</script>",
            
            # URL encoding
            "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
            "%3Cimg%20src%3Dx%20onerror%3Dalert%28%27XSS%27%29%3E",
            
            # HTML entity encoding bypass
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            
            # CSS injection
            "<style>@import'javascript:alert("XSS")';</style>",
            "<link rel=stylesheet href=javascript:alert('XSS')>",
            
            # Advanced techniques
            "<iframe srcdoc='<script>alert("XSS")</script>'>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            
            # DOM-based XSS
            "#<script>alert('XSS')</script>",
            "?test=<script>alert('XSS')</script>",
            
            # Polyglot payloads
            "jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>",
            
            # Test for specific contexts
            "'onmouseover='alert(1)'",
            ""onmouseover=\"alert(1)\"",
            "onmouseover=alert(1)",
            "onclick=alert(1)",
            "onload=alert(1)",
            "onerror=alert(1)"
        ]
        
        # Enhanced parameter discovery
        test_params = [
            # Common search parameters
            "searchFor", "search", "q", "query", "keyword", "term", "find", "lookup",
            # User input parameters
            "name", "id", "user", "username", "artist", "author", "title", "text", "msg", "message",
            # Form parameters
            "comment", "description", "content", "body", "subject", "email", "phone",
            # URL parameters
            "url", "link", "href", "src", "action", "redirect", "return", "next",
            # File parameters
            "file", "filename", "path", "dir", "folder", "upload", "image", "photo",
            # Admin parameters
            "admin", "userid", "catid", "page", "limit", "offset", "sort", "order",
            # API parameters
            "api_key", "token", "key", "secret", "auth", "session", "cookie"
        ]
        
        # Discover actual parameters from the site
        discovered_params = self._discover_parameters(target_url)
        all_test_params = list(set(test_params + discovered_params))
        
        print(f"[ALERT] Testing {len(all_test_params)} parameters with {len(xss_payloads)} XSS payloads")
        
        for param in all_test_params:
            print(f"[ALERT] Testing parameter: {param}")
            
            for i, payload in enumerate(xss_payloads):
                if i % 10 == 0:  # Progress indicator
                    print(f"[ALERT] XSS payload progress: {i}/{len(xss_payloads)}")
                
                # Test with GET parameter
                test_url = f"{target_url}?{param}={payload}"
                response = self._perform_http_request(test_url)
                
                if response["success"]:
                    content = response["content"]
                    
                    # Enhanced XSS detection
                    xss_detected = False
                    confidence = 0.0
                    evidence = ""
                    
                    # Check for direct payload reflection
                    if payload in content:
                        if self._is_dangerous_xss_context(content, payload):
                            xss_detected = True
                            confidence = 0.95
                            evidence = f"Direct payload reflection: {payload}"
                    
                    # Check for partial reflection
                    elif any(indicator in content.lower() for indicator in ['<script', 'onerror', 'onload', 'javascript:', 'onclick', 'onmouseover']):
                        xss_detected = True
                        confidence = 0.7
                        evidence = f"Partial payload reflection detected" 
                    
                    # Check for encoded payload reflection
                    elif self._check_encoded_reflection(content, payload):
                        xss_detected = True
                        confidence = 0.8
                        evidence = f"Encoded payload reflection detected"
                    
                    # Check for context-specific XSS
                    elif self._check_context_xss(content, param, payload):
                        xss_detected = True
                        confidence = 0.6
                        evidence = f"Context-specific XSS vulnerability"
                    
                    if xss_detected:
                        # Determine severity based on context and confidence
                        severity = "Critical" if confidence >= 0.9 else "High" if confidence >= 0.7 else "Medium"
                        
                        findings.append(ScanFinding(
                            type="XSS-Reflected",
                            severity=severity,
                            path=f"?{param}=",
                            parameter=param,
                            evidence=evidence,
                            description=f"XSS vulnerability in parameter '{param}'. {evidence}. Test URL: {test_url}",
                            cwe="CWE-79",
                            confidence=confidence
                        ))
                        
                        # Add test URL for manual verification
                        print(f"[ALERT] XSS found in {param}: {test_url}")
                        break  # Found XSS, move to next parameter
        
        print(f"[ALERT] XSS scan completed. Found {len(findings)} vulnerabilities")
        return findings
    
    def _check_encoded_reflection(self, content: str, payload: str) -> bool:
        """Check for encoded payload reflection"""
        import urllib.parse
        
        # Check URL encoding
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in content:
            return True
        
        # Check HTML entity encoding
        html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')
        if html_encoded in content:
            return True
        
        # Check hex encoding
        hex_encoded = ''.join([f'%{ord(c):02x}' for c in payload])
        if hex_encoded in content:
            return True
        
        return False
    
    def _check_context_xss(self, content: str, param: str, payload: str) -> bool:
        """Check for context-specific XSS vulnerabilities"""
        # Check if parameter value appears in dangerous contexts
        dangerous_patterns = [
            f'name="{param}" value="[^"]*{re.escape(payload)}[^"]*"',
            f'id="{param}"[^>]*>[^<]*{re.escape(payload)}[^<]*<',
            f'<input[^>]*name="{param}"[^>]*value="[^"]*{re.escape(payload)}[^"]*"',
            f'<textarea[^>]*name="{param}"[^>]*>[^<]*{re.escape(payload)}[^<]*</textarea>',
            f'<select[^>]*name="{param}"[^>]*>[^<]*{re.escape(payload)}[^<]*</select>'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _discover_parameters(self, target_url: str) -> List[str]:
        """Discover parameters from forms and URLs"""
        params = []
        try:
            response = self._perform_http_request(target_url)
            if response["success"]:
                soup = BeautifulSoup(response["content"], 'html.parser')
                
                # Find all form inputs
                for form in soup.find_all('form'):
                    for input_field in form.find_all(['input', 'textarea', 'select']):
                        param_name = input_field.get('name')
                        if param_name:
                            params.append(param_name)
                
                # Find parameters in links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if '?' in href:
                        query_part = href.split('?')[1]
                        for param_pair in query_part.split('&'):
                            if '=' in param_pair:
                                param_name = param_pair.split('=')[0]
                                params.append(param_name)
        except Exception as e:
            print(f"Error discovering parameters: {e}")
        
        return list(set(params))
    
    def _is_dangerous_xss_context(self, html_content: str, payload: str) -> bool:
        """Check if payload is in a dangerous XSS context"""
        # Check if payload appears outside of HTML encoding
        dangerous_contexts = [
            f'>{payload}<',  # Between tags
            f'"{payload}"',  # In attribute value
            f"'{payload}'",  # In single-quoted attribute
            f'={payload}',   # Direct attribute value
            f'<script>{payload}',  # In script tag
            f'javascript:{payload}',  # In javascript protocol
        ]
        
        for context in dangerous_contexts:
            if context in html_content:
                return True
        
        return False
    
    def _scan_sql_injection_vulnerabilities(self, target_url: str) -> List[ScanFinding]:
        """Scan for SQL injection vulnerabilities with enhanced detection"""
        findings = []
        
        # Enhanced SQL injection payloads with various techniques
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or ('1'='1--",
            "') or ('1'='1#",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1' AND '1'='1",
            "1' AND '1'='2"
        ]
        
        # Comprehensive SQL error patterns
        error_patterns = [
            # MySQL errors
            r"You have an error in your SQL syntax",
            r"mysql_fetch_array\(\)",
            r"mysql_query\(\)",
            r"mysql_num_rows\(\)",
            r"mysqli::query\(\)",
            r"Warning: mysql",
            r"MySQL server version",
            r"supplied argument is not a valid MySQL",
            
            # PostgreSQL errors
            r"PostgreSQL query failed",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"PostgreSQL.*ERROR",
            r"Warning: pg_",
            r"valid PostgreSQL result",
            
            # MSSQL errors
            r"Microsoft OLE DB Provider",
            r"SQLServer JDBC Driver",
            r"System.Data.SqlClient.SqlException",
            r"Unclosed quotation mark",
            r"Microsoft SQL Native Client error",
            r"\[SQL Server\]",
            
            # Oracle errors
            r"ORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning: oci_",
            
            # SQLite errors
            r"SQLite error",
            r"sqlite3.OperationalError",
            r"SQLite3::SQLException",
            
            # Generic SQL errors
            r"SQL syntax.*error",
            r"syntax error.*SQL",
            r"invalid query",
            r"SQL command not properly ended",
            r"quoted string not properly terminated"
        ]
        
        # Discover actual parameters from the site
        discovered_params = self._discover_parameters(target_url)
        common_params = ["id", "user", "name", "search", "q", "category", "artist", "art", "userid", "catid"]
        all_test_params = list(set(common_params + discovered_params))
        
        for param in all_test_params:
            # First, get baseline response
            baseline_url = f"{target_url}?{param}=1"
            baseline_response = self._perform_http_request(baseline_url)
            
            if not baseline_response["success"]:
                continue
            
            baseline_length = len(baseline_response["content"])
            
            for payload in sql_payloads:
                test_url = f"{target_url}?{param}={payload}"
                response = self._perform_http_request(test_url)
                
                if response["success"]:
                    content = response["content"]
                    response_length = len(content)
                    
                    # Check for SQL error patterns
                    for pattern in error_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            # Extract error snippet
                            match = re.search(pattern, content, re.IGNORECASE)
                            error_snippet = content[max(0, match.start()-50):min(len(content), match.end()+50)]
                            
                            findings.append(ScanFinding(
                                type="SQL Injection",
                                severity="Critical",
                                path=f"?{param}=",
                                parameter=param,
                                evidence=f"Payload: {payload}\nError: {error_snippet}",
                                description=f"SQL injection vulnerability confirmed in parameter '{param}'. Database error message leaked: {pattern}",
                                cwe="CWE-89",
                                confidence=0.95
                            ))
                            return findings  # High confidence, stop testing
                    
                    # Check for boolean-based blind SQL injection
                    true_payload = "1' OR '1'='1"
                    false_payload = "1' AND '1'='2"
                    
                    true_url = f"{target_url}?{param}={true_payload}"
                    false_url = f"{target_url}?{param}={false_payload}"
                    
                    true_response = self._perform_http_request(true_url)
                    false_response = self._perform_http_request(false_url)
                    
                    if true_response["success"] and false_response["success"]:
                        true_length = len(true_response["content"])
                        false_length = len(false_response["content"])
                        
                        # Significant difference in response length indicates SQL injection
                        if abs(true_length - false_length) > 100:
                            findings.append(ScanFinding(
                                type="SQL Injection (Boolean-Based Blind)",
                                severity="High",
                                path=f"?{param}=",
                                parameter=param,
                                evidence=f"True condition length: {true_length}, False condition length: {false_length}",
                                description=f"Boolean-based blind SQL injection detected in parameter '{param}'. Response length varies with true/false conditions.",
                                cwe="CWE-89",
                                confidence=0.85
                            ))
                            break
        
        return findings
    
    def _scan_misconfig_vulnerabilities(self, target_url: str) -> List[ScanFinding]:
        """Scan for security misconfigurations"""
        findings = []
        
        # Check for common misconfigurations
        misconfig_checks = [
            ("/phpinfo.php", "PHP Info Disclosure"),
            ("/server-status", "Apache Server Status"),
            ("/server-info", "Apache Server Info"),
            ("/.git/", "Git Repository Exposure"),
            ("/.svn/", "SVN Repository Exposure"),
            ("/backup.sql", "Database Backup File"),
            ("/database.sql", "Database Backup File"),
            ("/wp-config.php", "WordPress Config File"),
            ("/config.php", "Config File Exposure")
        ]
        
        for path, description in misconfig_checks:
            test_url = urljoin(target_url, path)
            response = self._perform_http_request(test_url)
            
            if response["success"] and response["status_code"] == 200:
                findings.append(ScanFinding(
                    type="Information Disclosure",
                    severity="Medium",
                    path=test_url,
                    evidence=f"Status: {response['status_code']}",
                    description=description,
                    cwe="CWE-200",
                    confidence=0.7
                ))
        
        return findings
    
    def start_scan(self, target_url: str, profile: ScanProfile = ScanProfile.FAST) -> ScanResult:
        """Start comprehensive security scan"""
        start_time = time.time()
        
        print(f"[SCAN] Starting {profile.value} scan of {target_url}")
        
        # Perform initial HTTP request
        print("[HTTP] Performing initial HTTP request...")
        http_response = self._perform_http_request(target_url)
        
        if not http_response["success"]:
            return ScanResult(
                target_url=target_url,
                profile=profile.value,
                start_time=start_time,
                end_time=time.time(),
                findings=[],
                http_response=http_response,
                headers_analysis={},
                body_analysis={},
                technology_stack={},
                discovered_paths=[],
                security_score=0.0
            )
        
        # Analyze headers
        print("[SECURITY] Analyzing security headers...")
        headers_analysis = self._analyze_headers(http_response["headers"])
        
        # Analyze response body
        print("[DOCUMENT] Analyzing response body...")
        body_analysis = self._analyze_response_body(http_response["content"], http_response["headers"])
        
        # Detect technology stack
        print("[TOOL] Detecting technology stack...")
        technology_stack = self._detect_technology(http_response["content"], http_response["headers"])
        
        # Discover paths
        print("[FOLDER] Discovering paths and files...")
        discovered_paths = self._discover_paths(target_url)
        
        # Vulnerability scanning
        print("[ALERT] Scanning for vulnerabilities...")
        findings = []
        
        # XSS scanning
        print("  [SCAN] Scanning for XSS...")
        findings.extend(self._scan_xss_vulnerabilities(target_url))
        
        # SQL injection scanning
        print("  [SCAN] Scanning for SQL injection...")
        findings.extend(self._scan_sql_injection_vulnerabilities(target_url))
        
        # Misconfiguration scanning
        print("  [SCAN] Scanning for misconfigurations...")
        findings.extend(self._scan_misconfig_vulnerabilities(target_url))
        
        # Calculate security score
        security_score = headers_analysis.get("security_score", 0)
        if findings:
            # Reduce score based on findings
            high_severity = sum(1 for f in findings if f.severity == "High")
            medium_severity = sum(1 for f in findings if f.severity == "Medium")
            security_score = max(0, security_score - (high_severity * 20) - (medium_severity * 10))
        
        end_time = time.time()
        
        print(f"[OK] Scan completed in {end_time - start_time:.2f} seconds")
        print(f"[CHART] Found {len(findings)} vulnerabilities")
        
        return ScanResult(
            target_url=target_url,
            profile=profile.value,
            start_time=start_time,
            end_time=end_time,
            findings=findings,
            http_response=http_response,
            headers_analysis=headers_analysis,
            body_analysis=body_analysis,
            technology_stack=technology_stack,
            discovered_paths=discovered_paths,
            security_score=security_score
        )

