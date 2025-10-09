"""
Tool Parsers - Parse outputs từ các security tools và extract evidence
"""

import json
import re
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs

class ToolParser:
    """Base class cho tool parsers"""
    
    def __init__(self):
        self.tool_name = "unknown"
    
    def parse(self, content: str, target_url: str, output_file: str) -> List[Dict[str, Any]]:
        """Parse tool output và return findings"""
        raise NotImplementedError
    
    def extract_evidence_snippet(self, content: str, marker: str, context_lines: int = 5) -> str:
        """Extract evidence snippet around marker"""
        try:
            lines = content.split('\n')
            marker_line = -1
            
            # Find marker line
            for i, line in enumerate(lines):
                if marker in line:
                    marker_line = i
                    break
            
            if marker_line == -1:
                return "Marker not found in response"
            
            # Extract context around marker
            start = max(0, marker_line - context_lines)
            end = min(len(lines), marker_line + context_lines + 1)
            
            snippet_lines = lines[start:end]
            
            # Highlight marker line
            for i, line in enumerate(snippet_lines):
                if marker in line:
                    snippet_lines[i] = f">>> {line} <<<"
                    break
            
            return '\n'.join(snippet_lines)
            
        except Exception as e:
            return f"Error extracting snippet: {str(e)}"

class NucleiParser(ToolParser):
    """Parser cho Nuclei output"""
    
    def __init__(self):
        super().__init__()
        self.tool_name = "nuclei"
    
    def parse(self, content: str, target_url: str, output_file: str) -> List[Dict[str, Any]]:
        findings = []
        
        try:
            lines = content.strip().split('\n')
            for line_num, line in enumerate(lines, 1):
                if line.strip():
                    try:
                        data = json.loads(line)
                        finding = self._parse_nuclei_finding(data, target_url, output_file, line_num)
                if finding:
                    findings.append(finding)
                    except json.JSONDecodeError:
                        continue
                    
        except Exception as e:
            print(f"Error parsing nuclei output: {e}")
        
        return findings
    
    def _parse_nuclei_finding(self, data: Dict[str, Any], target_url: str, 
                            output_file: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse individual nuclei finding"""
        try:
            info = data.get("info", {})
            matched_at = data.get("matched-at", "")
            request = data.get("request", "")
            response = data.get("response", "")
            
            # Extract vulnerability type
            vuln_type = self._classify_vulnerability(info.get("name", ""), info.get("tags", []))
            
            # Extract path and parameters
            path, param = self._extract_path_and_param(matched_at)
            
            # Extract evidence snippet
            evidence_snippet = self._extract_nuclei_evidence(request, response, info.get("name", ""))
            
            finding = {
                "id": f"f-{len(findings)+1:03d}",
                "job_id": "temp",  # Will be updated later
                "target": target_url,
                "type": vuln_type,
                "path": path,
                "param": param,
                "tool": "nuclei",
                "severity": None,  # Will be enriched by LLM
                "confidence": None,
                "cvss_v3": None,
                "exploitability_score": None,
                "evidence_snippet": evidence_snippet,
                "raw_outputs": [output_file],
                "request_response": "",
                "screenshot": "",
                "confirmatory_tests": [],
                "related_domains": self._extract_related_domains(matched_at),
                "exploit_vectors": [],
                "remediation_suggestions": [],
                "created_at": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                "metadata": {
                    "template_id": info.get("template-id", ""),
                    "template_name": info.get("name", ""),
                    "severity_raw": info.get("severity", ""),
                    "tags": info.get("tags", []),
                    "reference": info.get("reference", []),
                    "line_number": line_num
                }
            }
            
            return finding
            
        except Exception as e:
            print(f"Error parsing nuclei finding: {e}")
            return None
    
    def _classify_vulnerability(self, name: str, tags: List[str]) -> str:
        """Classify vulnerability type from name and tags"""
        name_lower = name.lower()
        tags_lower = [tag.lower() for tag in tags]
        
        if any(keyword in name_lower for keyword in ['xss', 'cross-site', 'scripting']):
            return "XSS-Reflected"
        elif any(keyword in name_lower for keyword in ['sql', 'injection', 'sqli']):
            return "SQL-Injection"
        elif any(keyword in name_lower for keyword in ['lfi', 'local-file', 'file-inclusion']):
            return "LFI"
        elif any(keyword in name_lower for keyword in ['rfi', 'remote-file']):
            return "RFI"
        elif any(keyword in name_lower for keyword in ['ssrf', 'server-side']):
            return "SSRF"
        elif any(keyword in name_lower for keyword in ['csrf', 'cross-site-request']):
            return "CSRF"
        elif any(keyword in name_lower for keyword in ['idor', 'direct-object']):
            return "IDOR"
        elif any(keyword in name_lower for keyword in ['misconfig', 'configuration']):
            return "Security-Misconfiguration"
        elif any(keyword in name_lower for keyword in ['ssti', 'template-injection']):
            return "SSTI"
        elif any(keyword in name_lower for keyword in ['rce', 'remote-code', 'command-injection']):
            return "RCE"
        else:
            return "Unknown"
    
    def _extract_path_and_param(self, matched_at: str) -> tuple:
        """Extract path and parameter from matched URL"""
        try:
            parsed = urlparse(matched_at)
            path = parsed.path
            param = ""
            
            if parsed.query:
                params = parse_qs(parsed.query)
                # Get first parameter
                if params:
                    param = list(params.keys())[0]
            
            return path, param
            
        except Exception as e:
            return matched_at, ""
    
    def _extract_nuclei_evidence(self, request: str, response: str, template_name: str) -> str:
        """Extract evidence snippet from nuclei request/response"""
        try:
            # Look for common patterns in response
            if response:
                # Look for reflected payloads
                if '<script>' in response.lower():
                    return self.extract_evidence_snippet(response, '<script>')
                elif 'alert(' in response.lower():
                    return self.extract_evidence_snippet(response, 'alert(')
                elif 'javascript:' in response.lower():
                    return self.extract_evidence_snippet(response, 'javascript:')
                else:
                    # Return first 500 chars of response
                    return response[:500]
            else:
                return f"Nuclei template: {template_name}"
                
        except Exception as e:
            return f"Error extracting evidence: {str(e)}"
    
    def _extract_related_domains(self, matched_at: str) -> List[str]:
        """Extract related domains from matched URL"""
        try:
            parsed = urlparse(matched_at)
            domain = parsed.netloc
            return [domain] if domain else []
        except:
            return []

class DalfoxParser(ToolParser):
    """Parser cho Dalfox output"""
    
    def __init__(self):
        super().__init__()
        self.tool_name = "dalfox"
    
    def parse(self, content: str, target_url: str, output_file: str) -> List[Dict[str, Any]]:
        findings = []
        
        try:
            # Dalfox can output both JSON and text
            if content.strip().startswith('{'):
                # JSON format
                data = json.loads(content)
                if isinstance(data, list):
            for item in data:
                        finding = self._parse_dalfox_finding(item, target_url, output_file)
                        if finding:
                            findings.append(finding)
                else:
                    finding = self._parse_dalfox_finding(data, target_url, output_file)
                if finding:
                    findings.append(finding)
            else:
                # Text format - parse manually
                findings = self._parse_dalfox_text(content, target_url, output_file)
                    
        except Exception as e:
            print(f"Error parsing dalfox output: {e}")
        
        return findings
    
    def _parse_dalfox_finding(self, data: Dict[str, Any], target_url: str, 
                            output_file: str) -> Optional[Dict[str, Any]]:
        """Parse individual dalfox finding"""
        try:
            url = data.get("url", "")
            param = data.get("param", "")
            payload = data.get("payload", "")
            method = data.get("method", "GET")
            
            # Extract path
            parsed = urlparse(url)
            path = parsed.path
            
            # Extract evidence snippet
            evidence_snippet = self._extract_dalfox_evidence(payload, data.get("response", ""))
            
            finding = {
                "id": f"f-{len(findings)+1:03d}",
                "job_id": "temp",
                "target": target_url,
                "type": "XSS-Reflected",
                "path": path,
                "param": param,
                "tool": "dalfox",
                "severity": None,
                "confidence": None,
                "cvss_v3": None,
                "exploitability_score": None,
                "evidence_snippet": evidence_snippet,
                "raw_outputs": [output_file],
                "request_response": "",
                "screenshot": "",
                "confirmatory_tests": [],
                "related_domains": [parsed.netloc] if parsed.netloc else [],
                "exploit_vectors": [payload] if payload else [],
                "remediation_suggestions": [],
                "created_at": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                "metadata": {
                    "method": method,
                    "payload": payload,
                    "url": url,
                    "param": param
                }
            }
            
            return finding
            
        except Exception as e:
            print(f"Error parsing dalfox finding: {e}")
            return None
    
    def _parse_dalfox_text(self, content: str, target_url: str, output_file: str) -> List[Dict[str, Any]]:
        """Parse dalfox text output"""
        findings = []
        
        try:
            lines = content.split('\n')
            for line in lines:
                if '[POC]' in line or '[VULN]' in line:
                    # Extract URL and payload from line
                    # Format: [POC] http://target.com/page?param=<script>alert(1)</script>
                    match = re.search(r'\[(?:POC|VULN)\]\s+(https?://[^\s]+)', line)
                    if match:
                        url = match.group(1)
                        parsed = urlparse(url)
                        
                        # Extract parameter and payload
                        param = ""
                        payload = ""
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            for key, values in params.items():
                                if values and any(char in values[0] for char in ['<', '>', 'script', 'alert']):
                                    param = key
                                    payload = values[0]
                                    break
                        
                        finding = {
                            "id": f"f-{len(findings)+1:03d}",
                            "job_id": "temp",
                            "target": target_url,
                            "type": "XSS-Reflected",
                            "path": parsed.path,
                            "param": param,
                            "tool": "dalfox",
                            "severity": None,
                            "confidence": None,
                            "cvss_v3": None,
                            "exploitability_score": None,
                            "evidence_snippet": payload,
                            "raw_outputs": [output_file],
                            "request_response": "",
                            "screenshot": "",
                            "confirmatory_tests": [],
                            "related_domains": [parsed.netloc] if parsed.netloc else [],
                            "exploit_vectors": [payload] if payload else [],
                            "remediation_suggestions": [],
                            "created_at": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                            "metadata": {
                                "method": "GET",
                                "payload": payload,
                                "url": url,
                                "param": param,
                                "source_line": line
                            }
                        }
                        
                    findings.append(finding)
                    
        except Exception as e:
            print(f"Error parsing dalfox text: {e}")
        
        return findings
    
    def _extract_dalfox_evidence(self, payload: str, response: str) -> str:
        """Extract evidence snippet from dalfox payload and response"""
        try:
            if response and payload in response:
                return self.extract_evidence_snippet(response, payload)
            else:
                return f"Payload: {payload}"
        except:
            return payload

class NiktoParser(ToolParser):
    """Parser cho Nikto output"""
    
    def __init__(self):
        super().__init__()
        self.tool_name = "nikto"
    
    def parse(self, content: str, target_url: str, output_file: str) -> List[Dict[str, Any]]:
        findings = []
        
        try:
            data = json.loads(content)
            vulnerabilities = data.get("vulnerabilities", [])
            
            for vuln in vulnerabilities:
                finding = self._parse_nikto_finding(vuln, target_url, output_file)
                    if finding:
                        findings.append(finding)
                        
        except Exception as e:
            print(f"Error parsing nikto output: {e}")
        
        return findings
    
    def _parse_nikto_finding(self, vuln: Dict[str, Any], target_url: str, 
                           output_file: str) -> Optional[Dict[str, Any]]:
        """Parse individual nikto finding"""
        try:
            url = vuln.get("url", "")
            description = vuln.get("description", "")
            method = vuln.get("method", "GET")
            
            # Extract path
            parsed = urlparse(url)
            path = parsed.path
            
            # Classify vulnerability type
            vuln_type = self._classify_nikto_vulnerability(description)
            
            finding = {
                "id": f"f-{len(findings)+1:03d}",
                "job_id": "temp",
                "target": target_url,
                "type": vuln_type,
                "path": path,
                "param": "",
                "tool": "nikto",
                "severity": None,
                "confidence": None,
                "cvss_v3": None,
                "exploitability_score": None,
                "evidence_snippet": description,
                "raw_outputs": [output_file],
                "request_response": "",
                "screenshot": "",
                "confirmatory_tests": [],
                "related_domains": [parsed.netloc] if parsed.netloc else [],
                "exploit_vectors": [],
                "remediation_suggestions": [],
                "created_at": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                "metadata": {
                    "method": method,
                    "description": description,
                    "url": url,
                    "cve": vuln.get("cve", ""),
                    "osvdb": vuln.get("osvdb", "")
                }
            }
            
            return finding
            
        except Exception as e:
            print(f"Error parsing nikto finding: {e}")
            return None
    
    def _classify_nikto_vulnerability(self, description: str) -> str:
        """Classify nikto vulnerability type"""
        desc_lower = description.lower()
        
        if any(keyword in desc_lower for keyword in ['xss', 'cross-site', 'scripting']):
            return "XSS-Reflected"
        elif any(keyword in desc_lower for keyword in ['sql', 'injection']):
            return "SQL-Injection"
        elif any(keyword in desc_lower for keyword in ['directory', 'listing', 'browsing']):
            return "Directory-Listing"
        elif any(keyword in desc_lower for keyword in ['server', 'version', 'disclosure']):
            return "Information-Disclosure"
        elif any(keyword in desc_lower for keyword in ['ssl', 'tls', 'certificate']):
            return "SSL-TLS-Issue"
        elif any(keyword in desc_lower for keyword in ['backup', 'old', 'temp']):
            return "Sensitive-File-Exposure"
        else:
            return "Security-Misconfiguration"

class FFUFParser(ToolParser):
    """Parser cho FFUF output"""
    
    def __init__(self):
        super().__init__()
        self.tool_name = "ffuf"
    
    def parse(self, content: str, target_url: str, output_file: str) -> List[Dict[str, Any]]:
        findings = []
        
        try:
            data = json.loads(content)
            results = data.get("results", [])
            
            for result in results:
                finding = self._parse_ffuf_result(result, target_url, output_file)
                if finding:
                    findings.append(finding)
                    
        except Exception as e:
            print(f"Error parsing ffuf output: {e}")
        
        return findings
    
    def _parse_ffuf_result(self, result: Dict[str, Any], target_url: str, 
                          output_file: str) -> Optional[Dict[str, Any]]:
        """Parse individual ffuf result"""
        try:
            url = result.get("url", "")
            status = result.get("status", 0)
            length = result.get("length", 0)
            words = result.get("words", 0)
            
            # Extract path
            parsed = urlparse(url)
            path = parsed.path
            
            # Only report interesting findings
            if status in [200, 301, 302, 403] and length > 0:
                finding = {
                    "id": f"f-{len(findings)+1:03d}",
                    "job_id": "temp",
                    "target": target_url,
                    "type": "Directory-Found",
                    "path": path,
                    "param": "",
                    "tool": "ffuf",
                    "severity": None,
                    "confidence": None,
                    "cvss_v3": None,
                    "exploitability_score": None,
                    "evidence_snippet": f"Status: {status}, Length: {length}, Words: {words}",
                    "raw_outputs": [output_file],
                    "request_response": "",
                    "screenshot": "",
                    "confirmatory_tests": [],
                    "related_domains": [parsed.netloc] if parsed.netloc else [],
                    "exploit_vectors": [],
                    "remediation_suggestions": [],
                    "created_at": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                    "metadata": {
                        "status": status,
                        "length": length,
                        "words": words,
                        "url": url
                    }
                }
                
                return finding
                
            except Exception as e:
            print(f"Error parsing ffuf result: {e}")
        
        return None

class ToolParserFactory:
    """Factory để tạo appropriate parser cho từng tool"""
    
    _parsers = {
        "nuclei": NucleiParser,
        "dalfox": DalfoxParser,
        "nikto": NiktoParser,
        "ffuf": FFUFParser
    }
    
    @classmethod
    def get_parser(cls, tool_name: str) -> ToolParser:
        """Get parser for specific tool"""
        parser_class = cls._parsers.get(tool_name.lower())
        if parser_class:
            return parser_class()
        else:
            return ToolParser()  # Default parser
    
    @classmethod
    def parse_tool_output(cls, tool_name: str, content: str, target_url: str, 
                         output_file: str) -> List[Dict[str, Any]]:
        """Parse tool output using appropriate parser"""
        parser = cls.get_parser(tool_name)
        return parser.parse(content, target_url, output_file)