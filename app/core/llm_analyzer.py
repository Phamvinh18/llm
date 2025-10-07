import json
import re
import hashlib
from typing import Dict, Any, Optional, List, Tuple
# from app.core.security_schema import validate_finding
from app.clients.gemini_client import GeminiClient
# from app.core.llm_vulnerability_analyzer import LLMVulnerabilityAnalyzer


SYSTEM_PROMPT = (
    "Bạn là chuyên gia AppSec. Phân tích cặp HTTP request–response. "
    "Chỉ kết luận dựa trên bằng chứng trong dữ liệu. Gán CWE, OWASP Top 10, "
    "mức rủi ro, POC, fix. Trả về JSON đúng schema."
)

RESPONSE_ANALYSIS_PROMPT = (
    "Bạn là chuyên gia bảo mật ứng dụng web. Phân tích HTTP response để tìm lỗ hổng bảo mật. "
    "Dựa trên payload được gửi và response nhận được, xác định xem có lỗ hổng nào không. "
    "Trả về JSON với các trường: vulnerability_type, severity, confidence, evidence, "
    "exploitation_steps, remediation, false_positive_indicators, risk_score, attack_vectors."
)

# Advanced vulnerability patterns
VULNERABILITY_PATTERNS = {
    'sql_injection': {
        'error_patterns': [
            r'mysql_fetch_array\(\)',
            r'ORA-\d+',
            r'Microsoft.*ODBC.*SQL Server',
            r'PostgreSQL.*ERROR',
            r'Warning.*mysql_.*',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'SQLServer JDBC Driver',
            r'SQLException',
            r'SQL syntax.*near'
        ],
        'success_patterns': [
            r'admin.*password',
            r'user.*pass',
            r'login.*success',
            r'authentication.*bypass'
        ],
        'time_based_patterns': [
            r'sleep\(\d+\)',
            r'waitfor delay',
            r'pg_sleep\(\d+\)'
        ]
    },
    'xss': {
        'reflected_patterns': [
            r'<script[^>]*>.*</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe[^>]*>',
            r'<img[^>]*onerror',
            r'<svg[^>]*onload'
        ],
        'stored_patterns': [
            r'alert\([^)]*\)',
            r'document\.cookie',
            r'window\.location',
            r'document\.write'
        ]
    },
    'path_traversal': {
        'patterns': [
            r'root:.*:0:0:',
            r'\[boot loader\]',
            r'\[fonts\]',
            r'\[extensions\]',
            r'\[drivers\]',
            r'\[mci\]',
            r'\[fonts\]',
            r'\[drivers\]',
            r'\[mci\]',
            r'\[fonts\]'
        ],
        'file_patterns': [
            r'/etc/passwd',
            r'/etc/shadow',
            r'/etc/hosts',
            r'C:\\windows\\system32',
            r'C:\\boot\.ini'
        ]
    },
    'command_injection': {
        'patterns': [
            r'uid=\d+.*gid=\d+',
            r'Volume Serial Number',
            r'Directory of',
            r'Microsoft Windows',
            r'Linux.*GNU',
            r'Darwin.*Darwin'
        ]
    }
}


class AdvancedLLMAnalyzer:
    """Advanced LLM Analyzer with multi-layer analysis and pattern recognition"""
    
    def __init__(self):
        self.client = GeminiClient()
        self.vulnerability_analyzer = LLMVulnerabilityAnalyzer()
        self.confidence_threshold = 0.7
        self.analysis_cache = {}
        self.pattern_database = VULNERABILITY_PATTERNS
    
    def analyze_response_advanced(self, response_data: Dict[str, Any], payload: str, vulnerability_type: str = None) -> Dict[str, Any]:
        """Advanced response analysis with multi-layer detection"""
        try:
            # Generate cache key
            cache_key = self._generate_cache_key(response_data, payload)
            if cache_key in self.analysis_cache:
                return self.analysis_cache[cache_key]
            
            # Layer 1: Pattern-based analysis
            pattern_analysis = self._pattern_based_analysis(response_data, payload, vulnerability_type)
            
            # Layer 2: Heuristic analysis
            heuristic_analysis = self._heuristic_analysis(response_data, payload)
            
            # Layer 3: LLM analysis
            llm_analysis = self._llm_analysis(response_data, payload, vulnerability_type)
            
            # Layer 4: Confidence scoring
            confidence_score = self._calculate_confidence(pattern_analysis, heuristic_analysis, llm_analysis)
            
            # Layer 5: Risk assessment
            risk_assessment = self._assess_risk(pattern_analysis, heuristic_analysis, llm_analysis, confidence_score)
            
            # Combine all analyses
            final_analysis = {
                'vulnerability_detected': pattern_analysis['detected'] or heuristic_analysis['detected'] or llm_analysis.get('vulnerability_detected', False),
                'vulnerability_type': self._determine_vulnerability_type(pattern_analysis, heuristic_analysis, llm_analysis),
                'severity': risk_assessment['severity'],
                'confidence': confidence_score,
                'evidence': self._combine_evidence(pattern_analysis, heuristic_analysis, llm_analysis),
                'pattern_analysis': pattern_analysis,
                'heuristic_analysis': heuristic_analysis,
                'llm_analysis': llm_analysis,
                'risk_assessment': risk_assessment,
                'false_positive_indicators': self._detect_false_positives(pattern_analysis, heuristic_analysis, llm_analysis),
                'exploitation_potential': self._assess_exploitation_potential(pattern_analysis, heuristic_analysis, llm_analysis),
                'recommendations': self._generate_recommendations(pattern_analysis, heuristic_analysis, llm_analysis)
            }
            
            # Cache result
            self.analysis_cache[cache_key] = final_analysis
            return final_analysis
            
        except Exception as e:
            return self._fallback_analysis(response_data, payload)
    
    def _pattern_based_analysis(self, response_data: Dict[str, Any], payload: str, vulnerability_type: str = None) -> Dict[str, Any]:
        """Pattern-based vulnerability detection"""
        response_body = response_data.get('body', '').lower()
        response_headers = {k.lower(): v.lower() for k, v in response_data.get('headers', {}).items()}
        status_code = response_data.get('status_code', 0)
        
        detected_vulnerabilities = []
        evidence = []
        confidence = 0.0
        
        # Check for SQL injection patterns
        if vulnerability_type in [None, 'sql_injection']:
            sql_analysis = self._detect_sql_injection(response_body, payload, status_code)
            if sql_analysis['detected']:
                detected_vulnerabilities.append('sql_injection')
                evidence.extend(sql_analysis['evidence'])
                confidence = max(confidence, sql_analysis['confidence'])
        
        # Check for XSS patterns
        if vulnerability_type in [None, 'xss']:
            xss_analysis = self._detect_xss(response_body, payload)
            if xss_analysis['detected']:
                detected_vulnerabilities.append('xss')
                evidence.extend(xss_analysis['evidence'])
                confidence = max(confidence, xss_analysis['confidence'])
        
        # Check for path traversal patterns
        if vulnerability_type in [None, 'path_traversal']:
            pt_analysis = self._detect_path_traversal(response_body, payload)
            if pt_analysis['detected']:
                detected_vulnerabilities.append('path_traversal')
                evidence.extend(pt_analysis['evidence'])
                confidence = max(confidence, pt_analysis['confidence'])
        
        # Check for command injection patterns
        if vulnerability_type in [None, 'command_injection']:
            ci_analysis = self._detect_command_injection(response_body, payload)
            if ci_analysis['detected']:
                detected_vulnerabilities.append('command_injection')
                evidence.extend(ci_analysis['evidence'])
                confidence = max(confidence, ci_analysis['confidence'])
        
        return {
            'detected': len(detected_vulnerabilities) > 0,
            'vulnerabilities': detected_vulnerabilities,
            'evidence': evidence,
            'confidence': confidence,
            'primary_vulnerability': detected_vulnerabilities[0] if detected_vulnerabilities else None
        }
    
    def _detect_sql_injection(self, response_body: str, payload: str, status_code: int) -> Dict[str, Any]:
        """Detect SQL injection vulnerabilities"""
        evidence = []
        confidence = 0.0
        
        # Check error patterns
        for pattern in self.pattern_database['sql_injection']['error_patterns']:
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence.append(f"SQL error pattern detected: {pattern}")
                confidence += 0.3
        
        # Check success patterns
        for pattern in self.pattern_database['sql_injection']['success_patterns']:
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence.append(f"SQL success pattern detected: {pattern}")
                confidence += 0.4
        
        # Check time-based patterns
        for pattern in self.pattern_database['sql_injection']['time_based_patterns']:
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence.append(f"Time-based SQL pattern detected: {pattern}")
                confidence += 0.2
        
        # Check for SQL keywords in payload
        sql_keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter']
        payload_lower = payload.lower()
        for keyword in sql_keywords:
            if keyword in payload_lower:
                confidence += 0.1
        
        # Status code analysis
        if status_code == 500:
            confidence += 0.2
        elif status_code == 200 and evidence:
            confidence += 0.1
        
        return {
            'detected': confidence > 0.3,
            'evidence': evidence,
            'confidence': min(confidence, 1.0)
        }
    
    def _detect_xss(self, response_body: str, payload: str) -> Dict[str, Any]:
        """Detect XSS vulnerabilities"""
        evidence = []
        confidence = 0.0
        
        # Check reflected patterns
        for pattern in self.pattern_database['xss']['reflected_patterns']:
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence.append(f"XSS reflected pattern detected: {pattern}")
                confidence += 0.4
        
        # Check stored patterns
        for pattern in self.pattern_database['xss']['stored_patterns']:
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence.append(f"XSS stored pattern detected: {pattern}")
                confidence += 0.3
        
        # Check if payload is reflected
        if payload in response_body:
            evidence.append("Payload reflected in response")
            confidence += 0.3
        
        # Check for script tags in payload
        if '<script' in payload.lower() or 'javascript:' in payload.lower():
            confidence += 0.2
        
        return {
            'detected': confidence > 0.3,
            'evidence': evidence,
            'confidence': min(confidence, 1.0)
        }
    
    def _detect_path_traversal(self, response_body: str, payload: str) -> Dict[str, Any]:
        """Detect path traversal vulnerabilities"""
        evidence = []
        confidence = 0.0
        
        # Check system file patterns
        for pattern in self.pattern_database['path_traversal']['patterns']:
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence.append(f"System file pattern detected: {pattern}")
                confidence += 0.5
        
        # Check file path patterns
        for pattern in self.pattern_database['path_traversal']['file_patterns']:
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence.append(f"File path pattern detected: {pattern}")
                confidence += 0.4
        
        # Check for traversal sequences in payload
        if '../' in payload or '..\\' in payload:
            evidence.append("Path traversal sequence in payload")
            confidence += 0.3
        
        return {
            'detected': confidence > 0.3,
            'evidence': evidence,
            'confidence': min(confidence, 1.0)
        }
    
    def _detect_command_injection(self, response_body: str, payload: str) -> Dict[str, Any]:
        """Detect command injection vulnerabilities"""
        evidence = []
        confidence = 0.0
        
        # Check command output patterns
        for pattern in self.pattern_database['command_injection']['patterns']:
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence.append(f"Command output pattern detected: {pattern}")
                confidence += 0.4
        
        # Check for command separators in payload
        command_separators = [';', '|', '&', '&&', '||', '`', '$(']
        for separator in command_separators:
            if separator in payload:
                evidence.append(f"Command separator detected: {separator}")
                confidence += 0.2
        
        return {
            'detected': confidence > 0.3,
            'evidence': evidence,
            'confidence': min(confidence, 1.0)
        }
    
    def _heuristic_analysis(self, response_data: Dict[str, Any], payload: str) -> Dict[str, Any]:
        """Heuristic-based analysis"""
        response_body = response_data.get('body', '')
        status_code = response_data.get('status_code', 0)
        response_time = response_data.get('execution_time', 0)
        
        suspicious_indicators = []
        confidence = 0.0
        
        # Response time analysis
        if response_time > 5.0:  # Suspiciously long response time
            suspicious_indicators.append("Unusually long response time")
            confidence += 0.1
        
        # Status code analysis
        if status_code == 500:
            suspicious_indicators.append("Internal server error")
            confidence += 0.2
        elif status_code == 403:
            suspicious_indicators.append("Forbidden access")
            confidence += 0.1
        
        # Content length analysis
        content_length = len(response_body)
        if content_length > 10000:  # Very large response
            suspicious_indicators.append("Unusually large response")
            confidence += 0.1
        
        # Error message analysis
        error_keywords = ['error', 'exception', 'warning', 'fatal', 'critical']
        for keyword in error_keywords:
            if keyword in response_body.lower():
                suspicious_indicators.append(f"Error keyword detected: {keyword}")
                confidence += 0.1
        
        return {
            'detected': confidence > 0.2,
            'indicators': suspicious_indicators,
            'confidence': min(confidence, 1.0)
        }
    
    def _llm_analysis(self, response_data: Dict[str, Any], payload: str, vulnerability_type: str = None) -> Dict[str, Any]:
        """LLM-based analysis"""
        try:
            prompt = f"""
            Analyze this HTTP response for security vulnerabilities:
            
            Payload: {payload}
            Status Code: {response_data.get('status_code', 'N/A')}
            Response Body: {response_data.get('body', '')[:2000]}
            Headers: {json.dumps(response_data.get('headers', {}), indent=2)}
            
            Focus on: {vulnerability_type if vulnerability_type else 'all vulnerability types'}
            
            Return JSON with: vulnerability_detected, vulnerability_type, severity, confidence, evidence, exploitation_steps, remediation
            """
            
            response = self.client.generate_content(prompt)
            if response and response.text:
                try:
                    return json.loads(response.text)
                except json.JSONDecodeError:
                    return {'vulnerability_detected': False, 'confidence': 0.0}
            else:
                return {'vulnerability_detected': False, 'confidence': 0.0}
                
        except Exception as e:
            return {'vulnerability_detected': False, 'confidence': 0.0, 'error': str(e)}
    
    def _calculate_confidence(self, pattern_analysis: Dict, heuristic_analysis: Dict, llm_analysis: Dict) -> float:
        """Calculate overall confidence score"""
        pattern_conf = pattern_analysis.get('confidence', 0.0)
        heuristic_conf = heuristic_analysis.get('confidence', 0.0)
        llm_conf = llm_analysis.get('confidence', 0.0)
        
        # Weighted average
        weights = [0.5, 0.2, 0.3]  # Pattern, Heuristic, LLM
        confidence = (pattern_conf * weights[0] + heuristic_conf * weights[1] + llm_conf * weights[2])
        
        return min(confidence, 1.0)
    
    def _assess_risk(self, pattern_analysis: Dict, heuristic_analysis: Dict, llm_analysis: Dict, confidence: float) -> Dict[str, Any]:
        """Assess overall risk level"""
        if confidence > 0.8:
            severity = 'Critical'
            risk_score = 90
        elif confidence > 0.6:
            severity = 'High'
            risk_score = 70
        elif confidence > 0.4:
            severity = 'Medium'
            risk_score = 50
        elif confidence > 0.2:
            severity = 'Low'
            risk_score = 30
        else:
            severity = 'Info'
            risk_score = 10
        
        return {
            'severity': severity,
            'risk_score': risk_score,
            'confidence': confidence
        }
    
    def _determine_vulnerability_type(self, pattern_analysis: Dict, heuristic_analysis: Dict, llm_analysis: Dict) -> str:
        """Determine primary vulnerability type"""
        if pattern_analysis.get('primary_vulnerability'):
            return pattern_analysis['primary_vulnerability']
        elif llm_analysis.get('vulnerability_type'):
            return llm_analysis['vulnerability_type']
        else:
            return 'unknown'
    
    def _combine_evidence(self, pattern_analysis: Dict, heuristic_analysis: Dict, llm_analysis: Dict) -> List[str]:
        """Combine evidence from all analysis layers"""
        evidence = []
        evidence.extend(pattern_analysis.get('evidence', []))
        evidence.extend(heuristic_analysis.get('indicators', []))
        evidence.extend(llm_analysis.get('evidence', []))
        return list(set(evidence))  # Remove duplicates
    
    def _detect_false_positives(self, pattern_analysis: Dict, heuristic_analysis: Dict, llm_analysis: Dict) -> List[str]:
        """Detect potential false positives"""
        false_positive_indicators = []
        
        # Check for common false positive patterns
        if pattern_analysis.get('confidence', 0) < 0.3:
            false_positive_indicators.append("Low pattern confidence")
        
        if heuristic_analysis.get('confidence', 0) < 0.2:
            false_positive_indicators.append("Low heuristic confidence")
        
        if llm_analysis.get('confidence', 0) < 0.3:
            false_positive_indicators.append("Low LLM confidence")
        
        return false_positive_indicators
    
    def _assess_exploitation_potential(self, pattern_analysis: Dict, heuristic_analysis: Dict, llm_analysis: Dict) -> str:
        """Assess exploitation potential"""
        total_confidence = (
            pattern_analysis.get('confidence', 0) + 
            heuristic_analysis.get('confidence', 0) + 
            llm_analysis.get('confidence', 0)
        ) / 3
        
        if total_confidence > 0.7:
            return 'High'
        elif total_confidence > 0.4:
            return 'Medium'
        else:
            return 'Low'
    
    def _generate_recommendations(self, pattern_analysis: Dict, heuristic_analysis: Dict, llm_analysis: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        vuln_type = self._determine_vulnerability_type(pattern_analysis, heuristic_analysis, llm_analysis)
        
        if vuln_type == 'sql_injection':
            recommendations.extend([
                'Use parameterized queries or prepared statements',
                'Implement input validation and sanitization',
                'Apply principle of least privilege to database accounts',
                'Enable SQL injection protection in WAF'
            ])
        elif vuln_type == 'xss':
            recommendations.extend([
                'Implement output encoding for all user input',
                'Use Content Security Policy (CSP) headers',
                'Validate and sanitize all user input',
                'Use HTTP-only cookies for session management'
            ])
        elif vuln_type == 'path_traversal':
            recommendations.extend([
                'Validate file paths and restrict access',
                'Use whitelist of allowed file extensions',
                'Implement proper access controls',
                'Avoid user input in file operations'
            ])
        elif vuln_type == 'command_injection':
            recommendations.extend([
                'Avoid executing system commands with user input',
                'Use safe APIs instead of system commands',
                'Implement strict input validation',
                'Apply principle of least privilege'
            ])
        
        return recommendations
    
    def _generate_cache_key(self, response_data: Dict[str, Any], payload: str) -> str:
        """Generate cache key for analysis results"""
        content = f"{payload}_{response_data.get('status_code', 0)}_{response_data.get('body', '')[:500]}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _fallback_analysis(self, response_data: Dict[str, Any], payload: str) -> Dict[str, Any]:
        """Fallback analysis when all else fails"""
        return {
            'vulnerability_detected': False,
            'vulnerability_type': 'unknown',
            'severity': 'Info',
            'confidence': 0.0,
            'evidence': [],
            'pattern_analysis': {'detected': False, 'confidence': 0.0},
            'heuristic_analysis': {'detected': False, 'confidence': 0.0},
            'llm_analysis': {'vulnerability_detected': False, 'confidence': 0.0},
            'risk_assessment': {'severity': 'Info', 'risk_score': 10},
            'false_positive_indicators': ['Analysis failed'],
            'exploitation_potential': 'Low',
            'recommendations': ['Manual review recommended']
        }


def _build_user_prompt(payload: dict):
    # Keep only relevant sections
    req = payload.get('request', {})
    resp = payload.get('response', {})
    heur = payload.get('heuristics', [])
    history = payload.get('history', [])
    condensed = {
        'request': {
            'method': req.get('method'),
            'url': req.get('url'),
            'headers': {k: v for k, v in (req.get('headers') or {}).items() if k.lower() in ('accept','content-type','cookie','authorization')},
            'body': (req.get('body') or '')[:2000],
        },
        'response': {
            'status': resp.get('status'),
            'headers': {k: v for k, v in (resp.get('headers') or {}).items() if k.lower() in ('content-type','server','set-cookie','location')},
            'body': (resp.get('body') or '')[:4000],
        },
        'heuristics': heur[:50],
        'history': history[-5:],
    }
    instruction = (
        "Hãy phân tích và nếu có lỗ hổng, điền JSON với các khóa: "
        "vulnerability, cwe, owasp, severity, evidence[], exploitation, fix[], confidence. "
        "Nếu không có lỗ hổng rõ ràng, trả về confidence≈0 và evidence rỗng."
    )
    return instruction + "\nINPUT:\n" + json.dumps(condensed, ensure_ascii=False)


class LLMAnalyzer:
    def __init__(self, client=None):
        if client is None:
            try:
                from app.clients import GeminiClient
                client = GeminiClient()
            except Exception:
                client = None
        self.client = client

    def analyze(self, payload: dict):
        prompt = _build_user_prompt(payload)
        if not self.client:
            # Fallback heuristic-only finding with low confidence
            finding = {
                'vulnerability': 'Heuristic finding',
                'cwe': 'CWE-200',
                'owasp': 'A01:2021',
                'severity': 'Low',
                'evidence': [str(payload.get('heuristics', [])[:3])],
                'exploitation': 'N/A',
                'fix': ['Kiểm tra và vá theo phát hiện heuristics'],
                'confidence': 0.3,
            }
            ok, err = validate_finding(finding)
            if not ok:
                finding['confidence'] = 0.0
            return finding
        resp_text = self.client.chat(SYSTEM_PROMPT + "\n\n" + prompt, max_output_tokens=800)
        try:
            parsed = json.loads(resp_text)
        except Exception:
            parsed = {
                'vulnerability': 'LLM summary',
                'cwe': 'CWE-200',
                'owasp': 'A01:2021',
                'severity': 'Low',
                'evidence': [],
                'exploitation': resp_text[:800],
                'fix': [],
                'confidence': 0.2,
            }
        ok, err = validate_finding(parsed)
        if not ok:
            parsed = {
                'vulnerability': 'Schema mismatch',
                'cwe': 'CWE-200',
                'owasp': 'A01:2021',
                'severity': 'Low',
                'evidence': [],
                'exploitation': resp_text[:800],
                'fix': [],
                'confidence': 0.2,
            }
        return parsed

    async def analyze_nikto_results(self, nikto_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Nikto scan results with advanced LLM analysis"""
        try:
            findings = nikto_results.get('findings', [])
            summary = nikto_results.get('summary', {})
            target = nikto_results.get('target', '')
            
            # Create comprehensive analysis prompt
            prompt = f"""
            Bạn là chuyên gia bảo mật web chuyên phân tích kết quả Nikto scan. Hãy phân tích chi tiết kết quả quét Nikto cho target: {target}
            
            Tổng quan kết quả:
            - Tổng số lỗ hổng: {summary.get('total_findings', 0)}
            - Critical: {summary.get('critical_count', 0)}
            - High: {summary.get('high_count', 0)}
            - Medium: {summary.get('medium_count', 0)}
            - Low: {summary.get('low_count', 0)}
            
            Chi tiết các lỗ hổng phát hiện:
            {json.dumps(findings, ensure_ascii=False, indent=2)}
            
            Hãy phân tích và đưa ra JSON với các trường sau:
            1. overall_assessment: Đánh giá tổng quan về mức độ bảo mật của server
            2. critical_vulnerabilities: Danh sách các lỗ hổng nghiêm trọng nhất cần ưu tiên sửa
            3. security_recommendations: Khuyến nghị cụ thể cho từng loại lỗ hổng
            4. risk_score: Điểm rủi ro từ 0-100
            5. exploitation_potential: Khả năng khai thác (High/Medium/Low)
            6. server_security_posture: Đánh giá tình trạng bảo mật server
            7. immediate_actions: Các hành động cần thực hiện ngay lập tức
            8. long_term_recommendations: Khuyến nghị dài hạn
            9. llm_detection_explanation: Giải thích cách LLM phát hiện và phân tích các lỗ hổng
            10. false_positive_analysis: Phân tích các kết quả có thể là false positive
            """
            
            # Get LLM analysis
            if self.client:
                analysis_text = self.client.chat(prompt, max_output_tokens=2000)
                try:
                    analysis = json.loads(analysis_text)
                except json.JSONDecodeError:
                    analysis = {
                        'overall_assessment': analysis_text[:500],
                        'critical_vulnerabilities': [f.get('title', '') for f in findings if f.get('severity') == 'Critical'],
                        'security_recommendations': ['Review all findings and implement security controls'],
                        'risk_score': self._calculate_nikto_risk_score(summary),
                        'exploitation_potential': 'Medium',
                        'server_security_posture': 'Needs improvement',
                        'immediate_actions': ['Address critical vulnerabilities'],
                        'long_term_recommendations': ['Implement comprehensive security program'],
                        'llm_detection_explanation': 'LLM analyzes patterns, error messages, and response characteristics to identify vulnerabilities',
                        'false_positive_analysis': 'Manual verification recommended for all findings'
                    }
            else:
                analysis = {
                    'overall_assessment': 'LLM analysis not available',
                    'critical_vulnerabilities': [f.get('title', '') for f in findings if f.get('severity') == 'Critical'],
                    'security_recommendations': self._generate_nikto_recommendations(findings),
                    'risk_score': self._calculate_nikto_risk_score(summary),
                    'exploitation_potential': 'Medium',
                    'server_security_posture': 'Needs improvement',
                    'immediate_actions': ['Address critical vulnerabilities'],
                    'long_term_recommendations': ['Implement comprehensive security program'],
                    'llm_detection_explanation': 'LLM not available - using heuristic analysis',
                    'false_positive_analysis': 'Manual verification recommended'
                }
            
            return {
                'overall_assessment': analysis.get('overall_assessment', 'Analysis completed'),
                'critical_vulnerabilities': analysis.get('critical_vulnerabilities', []),
                'security_recommendations': analysis.get('security_recommendations', []),
                'risk_score': analysis.get('risk_score', self._calculate_nikto_risk_score(summary)),
                'exploitation_potential': analysis.get('exploitation_potential', 'Medium'),
                'server_security_posture': analysis.get('server_security_posture', 'Needs improvement'),
                'immediate_actions': analysis.get('immediate_actions', []),
                'long_term_recommendations': analysis.get('long_term_recommendations', []),
                'llm_detection_explanation': analysis.get('llm_detection_explanation', 'LLM analysis completed'),
                'false_positive_analysis': analysis.get('false_positive_analysis', 'Manual verification recommended'),
                'priority_findings': [f for f in findings if f.get('severity') in ['Critical', 'High']],
                'next_steps': self._generate_nikto_next_steps(findings)
            }
            
        except Exception as e:
            return {
                'error': f"Failed to analyze Nikto results: {str(e)}",
                'overall_assessment': "Không thể phân tích kết quả quét Nikto",
                'critical_vulnerabilities': [],
                'security_recommendations': [],
                'risk_score': 0,
                'exploitation_potential': 'Unknown',
                'server_security_posture': 'Unknown',
                'immediate_actions': [],
                'long_term_recommendations': [],
                'llm_detection_explanation': 'Analysis failed due to error',
                'false_positive_analysis': 'Unable to analyze',
                'priority_findings': [],
                'next_steps': []
            }
    
    def _generate_nikto_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate recommendations based on Nikto findings"""
        recommendations = []
        
        for finding in findings:
            severity = finding.get('severity', '')
            category = finding.get('category', '')
            title = finding.get('title', '')
            
            if severity == 'Critical':
                recommendations.append(f"[ALERT] KHẨN CẤP: {title} - {finding.get('recommendation', '')}")
            elif severity == 'High':
                recommendations.append(f"[WARNING] CAO: {title} - {finding.get('recommendation', '')}")
            elif severity == 'Medium':
                recommendations.append(f"[LIST] TRUNG BÌNH: {title} - {finding.get('recommendation', '')}")
        
        return recommendations[:10]  # Top 10 recommendations
    
    def _calculate_nikto_risk_score(self, summary: Dict) -> int:
        """Calculate risk score based on Nikto summary"""
        critical = summary.get('critical_count', 0) * 10
        high = summary.get('high_count', 0) * 7
        medium = summary.get('medium_count', 0) * 4
        low = summary.get('low_count', 0) * 1
        
        total_score = critical + high + medium + low
        return min(total_score, 100)  # Cap at 100
    
    def _generate_nikto_next_steps(self, findings: List[Dict]) -> List[str]:
        """Generate next steps based on findings"""
        next_steps = []
        
        # Check for critical findings
        critical_findings = [f for f in findings if f.get('severity') == 'Critical']
        if critical_findings:
            next_steps.append("1. Khắc phục ngay các lỗ hổng Critical")
            next_steps.append("2. Thay đổi mật khẩu mặc định")
            next_steps.append("3. Cập nhật phần mềm lên phiên bản mới nhất")
        
        # Check for SQL injection
        sql_findings = [f for f in findings if 'sql' in f.get('title', '').lower()]
        if sql_findings:
            next_steps.append("4. Kiểm tra và sửa lỗi SQL Injection")
            next_steps.append("5. Sử dụng prepared statements")
        
        # Check for XSS
        xss_findings = [f for f in findings if 'xss' in f.get('title', '').lower()]
        if xss_findings:
            next_steps.append("6. Thêm output encoding cho XSS")
            next_steps.append("7. Implement Content Security Policy")
        
        return next_steps

    def analyze_response(self, response_data: Dict[str, Any], 
                        payload: str = '', 
                        vulnerability_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze HTTP response for potential vulnerabilities with RAG enhancement
        """
        try:
            # Use new vulnerability analyzer with RAG
            context = {
                'payload': payload,
                'vulnerability_type': vulnerability_type,
                'user_input': f"analyze response for {vulnerability_type or 'vulnerabilities'}"
            }
            
            # Analyze with RAG-enhanced vulnerability analyzer (sync version)
            import asyncio
            rag_result = asyncio.run(self.vulnerability_analyzer.analyze_response_with_rag(
                response_data, 
                context=context
            ))
            
            # Convert to expected format
            analysis_result = {
                'vulnerability_type': vulnerability_type or 'unknown',
                'severity': 'high' if rag_result.risk_score > 70 else 'medium' if rag_result.risk_score > 40 else 'low',
                'confidence': rag_result.analysis_confidence,
                'evidence': rag_result.overall_assessment,
                'exploitation_steps': [f"Step {i+1}: {step}" for i, step in enumerate(rag_result.recommendations[:3])],
                'remediation': rag_result.recommendations,
                'false_positive_indicators': [],
                'risk_score': rag_result.risk_score,
                'attack_vectors': [v.vulnerability_type.value for v in rag_result.vulnerabilities],
                'rag_enhancement': rag_result.rag_enhancement,
                'llm_analysis': rag_result.overall_assessment
            }
            
            return analysis_result
            
        except Exception as e:
            return self._fallback_response_analysis(response_data, payload, str(e))

    def _fallback_response_analysis(self, response_data: Dict[str, Any], 
                                  payload: str, error: str = None) -> Dict[str, Any]:
        """
        Fallback analysis when LLM is not available
        """
        analysis = {
            'vulnerability_type': 'Unknown',
            'severity': 'Low',
            'confidence': 0.2,
            'evidence': [],
            'exploitation_steps': ['Manual verification required'],
            'remediation': ['Review application security controls'],
            'false_positive_indicators': ['LLM analysis not available']
        }
        
        if error:
            analysis['false_positive_indicators'].append(f'Error: {error}')
        
        # Basic heuristic analysis
        status_code = response_data.get('status_code', 0)
        body = response_data.get('body', '').lower()
        headers = response_data.get('headers', {})
        
        # Check for error messages
        error_indicators = ['error', 'exception', 'warning', 'fatal', 'sql', 'database']
        found_errors = [indicator for indicator in error_indicators if indicator in body]
        
        if found_errors:
            analysis['evidence'].append(f'Error indicators found: {", ".join(found_errors)}')
            analysis['confidence'] = 0.4
        
        # Check for suspicious status codes
        if status_code in [500, 502, 503, 504]:
            analysis['evidence'].append(f'Server error status: {status_code}')
            analysis['confidence'] = 0.3
        
        # Check for missing security headers
        security_headers = ['x-frame-options', 'x-content-type-options', 'x-xss-protection']
        missing_headers = [header for header in security_headers if header not in headers]
        
        if missing_headers:
            analysis['evidence'].append(f'Missing security headers: {", ".join(missing_headers)}')
        
        return analysis

    def analyze_nikto_results(self, nikto_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze Nikto scan results for vulnerabilities with RAG enhancement
        """
        try:
            # Use new vulnerability analyzer with RAG
            context = {
                'scan_type': 'nikto',
                'target': nikto_data.get('target', 'Unknown'),
                'user_input': f"analyze nikto scan results for {nikto_data.get('target', 'target')}"
            }
            
            # Prepare response data for analysis
            response_data = {
                'content': json.dumps(nikto_data.get('findings', [])[:10], ensure_ascii=False),
                'status_code': 200,
                'headers': {'content-type': 'application/json'},
                'url': nikto_data.get('target', 'Unknown')
            }
            
            # Analyze with RAG-enhanced vulnerability analyzer (sync version)
            import asyncio
            rag_result = asyncio.run(self.vulnerability_analyzer.analyze_response_with_rag(
                response_data, 
                context=context
            ))
            
            # Convert to expected format
            analysis = {
                "overall_severity": "Critical" if rag_result.risk_score > 80 else "High" if rag_result.risk_score > 60 else "Medium" if rag_result.risk_score > 40 else "Low",
                "critical_issues": [v.vulnerability_type.value for v in rag_result.vulnerabilities if v.severity.value in ['critical', 'high']],
                "security_recommendations": rag_result.recommendations,
                "risk_assessment": rag_result.overall_assessment,
                "false_positives": [],
                "exploitation_potential": "High" if rag_result.risk_score > 70 else "Medium" if rag_result.risk_score > 40 else "Low",
                "rag_enhancement": rag_result.rag_enhancement,
                "llm_analysis": rag_result.overall_assessment
            }
            
            return analysis
            
        except Exception as e:
            return self._fallback_nikto_analysis(nikto_data, str(e))

    def _fallback_nikto_analysis(self, nikto_data: Dict[str, Any], error: str = None) -> Dict[str, Any]:
        """
        Fallback analysis for Nikto results when LLM is not available
        """
        findings = nikto_data.get('findings', [])
        
        # Count findings by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Determine overall severity
        if severity_counts.get('Critical', 0) > 0:
            overall_severity = 'Critical'
        elif severity_counts.get('High', 0) > 0:
            overall_severity = 'High'
        elif severity_counts.get('Medium', 0) > 0:
            overall_severity = 'Medium'
        else:
            overall_severity = 'Low'
        
        # Extract critical issues
        critical_issues = [f.get('title', '') for f in findings if f.get('severity') == 'Critical']
        
        # Generate recommendations
        recommendations = []
        if any('SQL' in f.get('title', '') for f in findings):
            recommendations.append('Implement parameterized queries to prevent SQL injection')
        if any('XSS' in f.get('title', '') for f in findings):
            recommendations.append('Implement output encoding to prevent XSS attacks')
        if any('Default' in f.get('title', '') for f in findings):
            recommendations.append('Change all default credentials immediately')
        if any('Missing' in f.get('title', '') for f in findings):
            recommendations.append('Add missing security headers')
        
        if not recommendations:
            recommendations.append('Review all findings and implement appropriate security controls')
        
        return {
            'overall_severity': overall_severity,
            'critical_issues': critical_issues,
            'security_recommendations': recommendations,
            'risk_assessment': f'Found {len(findings)} security issues with {overall_severity} overall risk level',
            'false_positives': [],
            'exploitation_potential': 'High' if overall_severity in ['Critical', 'High'] else 'Medium',
            'error': error
        }


