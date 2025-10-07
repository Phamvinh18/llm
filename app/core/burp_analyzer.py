from typing import Dict, List, Any
from app.core.llm_analyzer import LLMAnalyzer
# from app.core.curl_generator import generate_test_curl_commands, generate_curl_for_verification


class BurpFindingAnalyzer:
    def __init__(self, llm_client=None):
        self.llm_analyzer = LLMAnalyzer(llm_client)
    
    def analyze_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive analysis of a Burp finding using LLM
        """
        # Extract request/response data
        request = finding.get('request', {})
        response = finding.get('response', {})
        
        # Build analysis payload
        analysis_payload = {
            'request': request,
            'response': response,
            'heuristics': self._extract_heuristics(finding),
            'history': []
        }
        
        # Get LLM analysis
        llm_result = self.llm_analyzer.analyze(analysis_payload)
        
        # Generate curl commands for testing
        # curl_commands = generate_test_curl_commands(finding)
        curl_commands = []
        
        # Create comprehensive analysis result
        analysis = {
            'finding_id': finding.get('id'),
            'title': finding.get('title'),
            'risk_level': finding.get('risk'),
            'owasp_ref': finding.get('owasp_ref'),
            'url': finding.get('url'),
            'parameter': finding.get('parameter'),
            'evidence': finding.get('evidence', []),
            'recommendation': finding.get('recommendation'),
            
            # LLM Analysis
            'llm_analysis': llm_result,
            
            # Verification commands
            'curl_commands': curl_commands,
            # 'verification_curl': generate_curl_for_verification(finding, 'basic'),
            'verification_curl': '',
            
            # Additional analysis
            'exploitation_steps': self._generate_exploitation_steps(finding, llm_result),
            'fix_implementation': self._generate_fix_implementation(finding, llm_result),
            'false_positive_indicators': self._check_false_positive_indicators(finding),
            'severity_justification': self._justify_severity(finding, llm_result)
        }
        
        return analysis
    
    def _extract_heuristics(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract heuristic information from finding
        """
        heuristics = []
        
        # Check response status
        response = finding.get('response', {})
        status = response.get('status')
        if status and status >= 400:
            heuristics.append({
                'type': 'error_status',
                'status': status,
                'message': f'HTTP {status} error response'
            })
        
        # Check for error messages in body
        body = response.get('body', '')
        if 'error' in body.lower() or 'exception' in body.lower():
            heuristics.append({
                'type': 'error_message',
                'message': 'Error message detected in response body'
            })
        
        # Check headers
        headers = response.get('headers', {})
        missing_headers = []
        security_headers = ['content-security-policy', 'x-frame-options', 'strict-transport-security']
        for header in security_headers:
            if header not in [h.lower() for h in headers.keys()]:
                missing_headers.append(header)
        
        if missing_headers:
            heuristics.append({
                'type': 'missing_security_headers',
                'headers': missing_headers,
                'message': f'Missing security headers: {", ".join(missing_headers)}'
            })
        
        # Check for reflected input
        request = finding.get('request', {})
        request_body = request.get('body', '')
        request_url = request.get('url', '')
        
        # Simple reflection check
        if request_body and request_body in body:
            heuristics.append({
                'type': 'reflected_input',
                'message': 'Request body appears to be reflected in response'
            })
        
        if '?' in request_url:
            params = request_url.split('?')[1]
            if params in body:
                heuristics.append({
                    'type': 'reflected_parameters',
                    'message': 'URL parameters appear to be reflected in response'
                })
        
        return heuristics
    
    def _generate_exploitation_steps(self, finding: Dict[str, Any], llm_result: Dict[str, Any]) -> List[str]:
        """
        Generate step-by-step exploitation instructions
        """
        steps = []
        vulnerability = finding.get('title', '').lower()
        
        if 'xss' in vulnerability:
            steps = [
                "1. Identify the vulnerable parameter",
                "2. Test with basic XSS payload: <script>alert('XSS')</script>",
                "3. If blocked, try encoding: %3Cscript%3Ealert('XSS')%3C/script%3E",
                "4. Test different contexts: <img src=x onerror=alert('XSS')>",
                "5. Verify the payload executes in the browser",
                "6. Document the exact payload and context"
            ]
        elif 'sql' in vulnerability or 'injection' in vulnerability:
            steps = [
                "1. Identify the vulnerable parameter",
                "2. Test with basic SQL injection: ' OR '1'='1' --",
                "3. If successful, try UNION-based injection",
                "4. Determine the number of columns",
                "5. Extract database information",
                "6. Document the injection point and technique"
            ]
        elif 'header' in vulnerability:
            steps = [
                "1. Send request without security headers",
                "2. Verify missing headers using browser dev tools",
                "3. Test if application is vulnerable to clickjacking",
                "4. Check for mixed content issues",
                "5. Document the security implications"
            ]
        else:
            # Use LLM-generated exploitation if available
            llm_exploitation = llm_result.get('exploitation', '')
            if llm_exploitation:
                steps = [f"1. {llm_exploitation}"]
            else:
                steps = ["1. Follow standard testing methodology for this vulnerability type"]
        
        return steps
    
    def _generate_fix_implementation(self, finding: Dict[str, Any], llm_result: Dict[str, Any]) -> List[str]:
        """
        Generate specific fix implementation steps
        """
        fixes = []
        vulnerability = finding.get('title', '').lower()
        
        if 'xss' in vulnerability:
            fixes = [
                "1. Implement proper output encoding based on context (HTML, JavaScript, CSS, URL)",
                "2. Use Content Security Policy (CSP) to prevent script execution",
                "3. Validate and sanitize all user input",
                "4. Use parameterized templates or safe templating engines",
                "5. Set appropriate Content-Type headers"
            ]
        elif 'sql' in vulnerability or 'injection' in vulnerability:
            fixes = [
                "1. Use parameterized queries or prepared statements",
                "2. Implement input validation and sanitization",
                "3. Use least privilege database accounts",
                "4. Enable database query logging for monitoring",
                "5. Consider using an ORM with built-in protection"
            ]
        elif 'header' in vulnerability:
            fixes = [
                "1. Add Content-Security-Policy header",
                "2. Set X-Frame-Options to DENY or SAMEORIGIN",
                "3. Enable Strict-Transport-Security for HTTPS",
                "4. Set X-Content-Type-Options: nosniff",
                "5. Configure Referrer-Policy appropriately"
            ]
        else:
            # Use LLM-generated fixes if available
            llm_fixes = llm_result.get('fix', [])
            if llm_fixes:
                fixes = [f"{i+1}. {fix}" for i, fix in enumerate(llm_fixes)]
            else:
                fixes = ["1. Review and implement security best practices for this vulnerability type"]
        
        return fixes
    
    def _check_false_positive_indicators(self, finding: Dict[str, Any]) -> List[str]:
        """
        Check for indicators that this might be a false positive
        """
        indicators = []
        
        # Check if it's a static file or known safe endpoint
        url = finding.get('url', '')
        if any(ext in url.lower() for ext in ['.css', '.js', '.png', '.jpg', '.gif', '.ico']):
            indicators.append("Static file endpoint - may not be exploitable")
        
        # Check if error is expected (like 404 for non-existent resources)
        response = finding.get('response', {})
        status = response.get('status')
        if status == 404:
            indicators.append("404 Not Found - may be expected behavior")
        
        # Check if it's a development/staging environment
        if any(env in url.lower() for env in ['dev', 'test', 'staging', 'localhost']):
            indicators.append("Development environment - may not reflect production security")
        
        # Check if evidence is weak
        evidence = finding.get('evidence', [])
        if not evidence or len(evidence) == 0:
            indicators.append("No clear evidence provided")
        
        return indicators
    
    def _justify_severity(self, finding: Dict[str, Any], llm_result: Dict[str, Any] = None) -> str:
        """
        Provide justification for the severity rating
        """
        risk = finding.get('risk', 'Unknown')
        vulnerability = finding.get('title', '').lower()
        
        if risk == 'Critical':
            if 'sql' in vulnerability or 'injection' in vulnerability:
                return "Critical: SQL injection can lead to complete database compromise, data theft, and system takeover"
            elif 'remote code execution' in vulnerability or 'rce' in vulnerability:
                return "Critical: Remote code execution allows complete system compromise"
            else:
                return "Critical: High impact vulnerability that could lead to system compromise"
        
        elif risk == 'High':
            if 'xss' in vulnerability:
                return "High: XSS can lead to session hijacking, credential theft, and client-side attacks"
            elif 'authentication' in vulnerability or 'auth' in vulnerability:
                return "High: Authentication bypass can lead to unauthorized access to sensitive data"
            else:
                return "High: Significant security impact that could lead to data exposure or system compromise"
        
        elif risk == 'Medium':
            if 'header' in vulnerability or 'misconfiguration' in vulnerability:
                return "Medium: Security misconfiguration can facilitate other attacks but may not be directly exploitable"
            elif 'information disclosure' in vulnerability:
                return "Medium: Information disclosure can aid attackers but may not directly compromise the system"
            else:
                return "Medium: Moderate security impact that should be addressed"
        
        else:
            return "Low: Minor security issue with limited impact"
    
    def analyze_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze all findings from a scan
        """
        issues = scan_results.get('issues', [])
        analyzed_findings = []
        
        for issue in issues:
            analysis = self.analyze_finding(issue)
            analyzed_findings.append(analysis)
        
        # Generate summary
        summary = {
            'total_findings': len(issues),
            'critical_count': len([f for f in analyzed_findings if f['risk_level'] == 'Critical']),
            'high_count': len([f for f in analyzed_findings if f['risk_level'] == 'High']),
            'medium_count': len([f for f in analyzed_findings if f['risk_level'] == 'Medium']),
            'low_count': len([f for f in analyzed_findings if f['risk_level'] == 'Low']),
            'false_positive_candidates': len([f for f in analyzed_findings if f['false_positive_indicators']])
        }
        
        return {
            'scan_id': scan_results.get('scan_id'),
            'target': scan_results.get('target'),
            'summary': summary,
            'findings': analyzed_findings
        }
