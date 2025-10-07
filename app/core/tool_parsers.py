"""
Tool Parsers - Parse and normalize security tool outputs into findings schema
"""

import os
import json
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from bs4 import BeautifulSoup

@dataclass
class NormalizedFinding:
    id: str
    job_id: str
    target: str
    type: str
    path: str
    parameter: Optional[str]
    tool: str
    severity: str
    confidence: str
    cvss_v3: Optional[str]
    evidence_snippet: str
    raw_outputs: List[str]
    safe_poc_steps: List[str]
    remediation: List[str]
    created_at: str

class ToolParsers:
    def __init__(self):
        self.severity_mapping = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Info'
        }
    
    def parse_nuclei_output(self, output_file: str, job_id: str, target: str) -> List[NormalizedFinding]:
        """Parse nuclei JSON output"""
        findings = []
        
        if not os.path.exists(output_file):
            return findings
        
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle both single object and array
            if isinstance(data, dict):
                data = [data]
            
            for item in data:
                finding = self._parse_nuclei_finding(item, job_id, target)
                if finding:
                    findings.append(finding)
                    
        except Exception as e:
            print(f"Error parsing nuclei output: {e}")
        
        return findings
    
    def _parse_nuclei_finding(self, item: Dict[str, Any], job_id: str, target: str) -> Optional[NormalizedFinding]:
        """Parse individual nuclei finding"""
        try:
            # Extract basic info
            template_id = item.get('template-id', 'unknown')
            info = item.get('info', {})
            severity = info.get('severity', 'info').lower()
            name = info.get('name', template_id)
            
            # Map severity
            severity = self.severity_mapping.get(severity, 'Info')
            
            # Extract URL and path
            matched_at = item.get('matched-at', '')
            path = self._extract_path_from_url(matched_at)
            
            # Extract evidence
            evidence = item.get('request', '') + '\n' + item.get('response', '')
            evidence_snippet = self._extract_evidence_snippet(evidence, 5)
            
            # Generate finding ID
            finding_id = f"f-{hash(template_id + matched_at) % 10000}"
            
            # Determine vulnerability type from template
            vuln_type = self._map_nuclei_template_to_type(template_id, name)
            
            return NormalizedFinding(
                id=finding_id,
                job_id=job_id,
                target=target,
                type=vuln_type,
                path=path,
                parameter=None,
                tool='nuclei',
                severity=severity,
                confidence='High',
                cvss_v3=info.get('classification', {}).get('cvss-score'),
                evidence_snippet=evidence_snippet,
                raw_outputs=[f"nuclei: {template_id}"],
                safe_poc_steps=self._generate_safe_poc_steps(vuln_type, matched_at),
                remediation=self._generate_remediation(vuln_type),
                created_at=item.get('timestamp', '')
            )
            
        except Exception as e:
            print(f"Error parsing nuclei finding: {e}")
            return None
    
    def parse_dalfox_output(self, output_file: str, job_id: str, target: str) -> List[NormalizedFinding]:
        """Parse dalfox JSON output"""
        findings = []
        
        if not os.path.exists(output_file):
            return findings
        
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle both single object and array
            if isinstance(data, dict):
                data = [data]
            
            for item in data:
                finding = self._parse_dalfox_finding(item, job_id, target)
                if finding:
                    findings.append(finding)
                    
        except Exception as e:
            print(f"Error parsing dalfox output: {e}")
        
        return findings
    
    def _parse_dalfox_finding(self, item: Dict[str, Any], job_id: str, target: str) -> Optional[NormalizedFinding]:
        """Parse individual dalfox finding"""
        try:
            # Extract basic info
            url = item.get('url', '')
            payload = item.get('payload', '')
            method = item.get('method', 'GET')
            
            # Extract path and parameter
            path = self._extract_path_from_url(url)
            parameter = self._extract_parameter_from_url(url)
            
            # Extract evidence
            evidence = item.get('evidence', '')
            evidence_snippet = self._extract_evidence_snippet(evidence, 5)
            
            # Generate finding ID
            finding_id = f"f-{hash(url + payload) % 10000}"
            
            return NormalizedFinding(
                id=finding_id,
                job_id=job_id,
                target=target,
                type='XSS-Reflected',
                path=path,
                parameter=parameter,
                tool='dalfox',
                severity='High',
                confidence='High',
                cvss_v3='6.1',
                evidence_snippet=evidence_snippet,
                raw_outputs=[f"dalfox: {url}"],
                safe_poc_steps=self._generate_xss_poc_steps(url, payload),
                remediation=self._generate_xss_remediation(),
                created_at=item.get('timestamp', '')
            )
            
        except Exception as e:
            print(f"Error parsing dalfox finding: {e}")
            return None
    
    def parse_ffuf_output(self, output_file: str, job_id: str, target: str) -> List[NormalizedFinding]:
        """Parse ffuf JSON output"""
        findings = []
        
        if not os.path.exists(output_file):
            return findings
        
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            results = data.get('results', [])
            
            for item in results:
                finding = self._parse_ffuf_finding(item, job_id, target)
                if finding:
                    findings.append(finding)
                    
        except Exception as e:
            print(f"Error parsing ffuf output: {e}")
        
        return findings
    
    def _parse_ffuf_finding(self, item: Dict[str, Any], job_id: str, target: str) -> Optional[NormalizedFinding]:
        """Parse individual ffuf finding"""
        try:
            url = item.get('url', '')
            status = item.get('status', 0)
            length = item.get('length', 0)
            
            # Only report interesting findings
            if status not in [200, 301, 302, 403]:
                return None
            
            # Extract path
            path = self._extract_path_from_url(url)
            
            # Determine severity based on path
            severity = self._determine_path_severity(path, status)
            
            # Generate finding ID
            finding_id = f"f-{hash(url) % 10000}"
            
            return NormalizedFinding(
                id=finding_id,
                job_id=job_id,
                target=target,
                type='Information Disclosure',
                path=path,
                parameter=None,
                tool='ffuf',
                severity=severity,
                confidence='Medium',
                cvss_v3='3.7' if severity == 'Medium' else '5.3',
                evidence_snippet=f"Status: {status}, Length: {length}",
                raw_outputs=[f"ffuf: {url}"],
                safe_poc_steps=[f"Access {url} to verify directory/file exists"],
                remediation=self._generate_path_remediation(path),
                created_at=''
            )
            
        except Exception as e:
            print(f"Error parsing ffuf finding: {e}")
            return None
    
    def parse_nikto_output(self, output_file: str, job_id: str, target: str) -> List[NormalizedFinding]:
        """Parse nikto text output"""
        findings = []
        
        if not os.path.exists(output_file):
            return findings
        
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse nikto output
            lines = content.split('\n')
            for line in lines:
                if '+ OSVDB-' in line or '+ CVE-' in line:
                    finding = self._parse_nikto_line(line, job_id, target)
                    if finding:
                        findings.append(finding)
                        
        except Exception as e:
            print(f"Error parsing nikto output: {e}")
        
        return findings
    
    def _parse_nikto_line(self, line: str, job_id: str, target: str) -> Optional[NormalizedFinding]:
        """Parse individual nikto line"""
        try:
            # Extract URL from line
            url_match = re.search(r'https?://[^\s]+', line)
            if not url_match:
                return None
            
            url = url_match.group()
            path = self._extract_path_from_url(url)
            
            # Extract vulnerability info
            vuln_info = line.split('+')[1].strip() if '+' in line else line.strip()
            
            # Determine severity
            severity = 'Medium'
            if 'OSVDB-' in line or 'CVE-' in line:
                severity = 'High'
            
            # Generate finding ID
            finding_id = f"f-{hash(line) % 10000}"
            
            return NormalizedFinding(
                id=finding_id,
                job_id=job_id,
                target=target,
                type='Server Vulnerability',
                path=path,
                parameter=None,
                tool='nikto',
                severity=severity,
                confidence='High',
                cvss_v3='6.5' if severity == 'High' else '4.3',
                evidence_snippet=vuln_info,
                raw_outputs=[f"nikto: {line.strip()}"],
                safe_poc_steps=[f"Verify vulnerability at {url}"],
                remediation=self._generate_server_remediation(),
                created_at=''
            )
            
        except Exception as e:
            print(f"Error parsing nikto line: {e}")
            return None
    
    def _extract_path_from_url(self, url: str) -> str:
        """Extract path from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.path or '/'
        except:
            return '/'
    
    def _extract_parameter_from_url(self, url: str) -> Optional[str]:
        """Extract parameter from URL"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            if query_params:
                return list(query_params.keys())[0]
        except:
            pass
        return None
    
    def _extract_evidence_snippet(self, evidence: str, context_lines: int = 5) -> str:
        """Extract evidence snippet with context"""
        if not evidence:
            return ""
        
        lines = evidence.split('\n')
        if len(lines) <= context_lines * 2:
            return evidence
        
        # Find interesting lines (containing payloads, errors, etc.)
        interesting_lines = []
        for i, line in enumerate(lines):
            if any(keyword in line.lower() for keyword in ['<script>', 'alert(', 'error', 'exception', 'vulnerable']):
                start = max(0, i - context_lines)
                end = min(len(lines), i + context_lines + 1)
                interesting_lines.extend(lines[start:end])
                break
        
        if interesting_lines:
            return '\n'.join(interesting_lines)
        
        # Fallback to first few lines
        return '\n'.join(lines[:context_lines * 2])
    
    def _map_nuclei_template_to_type(self, template_id: str, name: str) -> str:
        """Map nuclei template to vulnerability type"""
        template_lower = template_id.lower()
        name_lower = name.lower()
        
        if 'xss' in template_lower or 'xss' in name_lower:
            return 'XSS-Reflected'
        elif 'sqli' in template_lower or 'sql' in template_lower:
            return 'SQL Injection'
        elif 'lfi' in template_lower or 'local-file' in template_lower:
            return 'Local File Inclusion'
        elif 'rfi' in template_lower or 'remote-file' in template_lower:
            return 'Remote File Inclusion'
        elif 'ssrf' in template_lower:
            return 'Server-Side Request Forgery'
        elif 'csrf' in template_lower:
            return 'Cross-Site Request Forgery'
        elif 'rce' in template_lower or 'command' in template_lower:
            return 'Remote Code Execution'
        elif 'info' in template_lower or 'disclosure' in template_lower:
            return 'Information Disclosure'
        else:
            return 'Vulnerability'
    
    def _determine_path_severity(self, path: str, status: int) -> str:
        """Determine severity based on discovered path"""
        path_lower = path.lower()
        
        # High severity paths
        if any(keyword in path_lower for keyword in ['admin', 'config', 'backup', '.git', '.env', 'database']):
            return 'High'
        
        # Medium severity paths
        if any(keyword in path_lower for keyword in ['test', 'dev', 'staging', 'debug', 'phpinfo']):
            return 'Medium'
        
        # Low severity for other paths
        return 'Low'
    
    def _generate_safe_poc_steps(self, vuln_type: str, url: str) -> List[str]:
        """Generate safe PoC steps"""
        steps = {
            'XSS-Reflected': [
                f"1. Navigate to {url}",
                "2. Inject payload in parameter",
                "3. Observe reflected output",
                "4. Verify payload execution"
            ],
            'SQL Injection': [
                f"1. Navigate to {url}",
                "2. Inject SQL payload in parameter",
                "3. Observe error messages or behavior changes",
                "4. Verify database interaction"
            ],
            'Information Disclosure': [
                f"1. Access {url}",
                "2. Verify information is exposed",
                "3. Document sensitive data found",
                "4. Assess impact of disclosure"
            ]
        }
        
        return steps.get(vuln_type, [
            f"1. Access {url}",
            "2. Verify vulnerability",
            "3. Document findings",
            "4. Assess impact"
        ])
    
    def _generate_xss_poc_steps(self, url: str, payload: str) -> List[str]:
        """Generate XSS PoC steps"""
        return [
            f"1. Navigate to {url}",
            f"2. Inject payload: {payload}",
            "3. Observe reflected output",
            "4. Verify script execution in browser",
            "5. Document XSS context and impact"
        ]
    
    def _generate_remediation(self, vuln_type: str) -> List[str]:
        """Generate remediation steps"""
        remediation = {
            'XSS-Reflected': [
                "Implement proper input validation",
                "Use output encoding (HTML entity encoding)",
                "Implement Content Security Policy (CSP)",
                "Use parameterized queries"
            ],
            'SQL Injection': [
                "Use prepared statements",
                "Implement input validation",
                "Use parameterized queries",
                "Apply principle of least privilege"
            ],
            'Information Disclosure': [
                "Remove sensitive information from responses",
                "Implement proper error handling",
                "Use generic error messages",
                "Review and sanitize all output"
            ]
        }
        
        return remediation.get(vuln_type, [
            "Review and fix the vulnerability",
            "Implement proper security controls",
            "Test the fix thoroughly",
            "Monitor for similar issues"
        ])
    
    def _generate_xss_remediation(self) -> List[str]:
        """Generate XSS remediation"""
        return [
            "Implement proper input validation and sanitization",
            "Use output encoding (HTML entity encoding)",
            "Implement Content Security Policy (CSP)",
            "Use parameterized queries for database operations",
            "Regular security testing and code review"
        ]
    
    def _generate_path_remediation(self, path: str) -> List[str]:
        """Generate path remediation"""
        return [
            "Remove or secure sensitive directories",
            "Implement proper access controls",
            "Use authentication for sensitive areas",
            "Regular security audits of file structure"
        ]
    
    def _generate_server_remediation(self) -> List[str]:
        """Generate server vulnerability remediation"""
        return [
            "Update server software to latest version",
            "Apply security patches",
            "Implement proper server configuration",
            "Regular security monitoring and updates"
        ]
    
    def normalize_all_findings(self, tool_outputs: Dict[str, Any], job_id: str, target: str) -> List[NormalizedFinding]:
        """Normalize all tool outputs into findings"""
        all_findings = []
        
        # Parse each tool output
        for tool_name, output in tool_outputs.items():
            if not output.success or not output.output_file:
                continue
            
            try:
                if tool_name == 'nuclei':
                    findings = self.parse_nuclei_output(output.output_file, job_id, target)
                elif tool_name == 'dalfox':
                    findings = self.parse_dalfox_output(output.output_file, job_id, target)
                elif tool_name == 'ffuf':
                    findings = self.parse_ffuf_output(output.output_file, job_id, target)
                elif tool_name == 'nikto':
                    findings = self.parse_nikto_output(output.output_file, job_id, target)
                else:
                    continue
                
                all_findings.extend(findings)
                
            except Exception as e:
                print(f"Error parsing {tool_name} output: {e}")
        
        # Remove duplicates based on path and type
        unique_findings = []
        seen = set()
        
        for finding in all_findings:
            key = (finding.path, finding.type, finding.parameter)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings

