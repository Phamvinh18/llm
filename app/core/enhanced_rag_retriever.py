"""
Enhanced RAG Retriever - Advanced knowledge retrieval system
"""

import os
import json
from typing import Dict, List, Any, Optional

class EnhancedRAGRetriever:
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
    
    def get_vulnerability_info(self, vuln_type: str) -> Dict[str, Any]:
        """Get detailed information about a vulnerability type"""
        vulnerabilities = self.rag_data.get("vulnerability_knowledge", {})
        return vulnerabilities.get(vuln_type.lower(), {})
    
    def get_payloads(self, vuln_type: str, category: str = "basic") -> List[str]:
        """Get payloads for a vulnerability type"""
        payloads = self.rag_data.get("payload_generation", {})
        vuln_payloads = payloads.get(vuln_type.lower(), {})
        return vuln_payloads.get(category, [])
    
    def get_wordlist(self, wordlist_type: str, size: str = "medium") -> List[str]:
        """Get wordlists for scanning"""
        wordlists = self.rag_data.get("wordlists", {})
        return wordlists.get(wordlist_type, {}).get(size, [])
    
    def get_scan_profile_config(self, profile: str) -> Dict[str, Any]:
        """Get scan profile configuration"""
        profiles = self.rag_data.get("scan_profiles", {})
        return profiles.get(profile, {})
    
    def get_security_header_info(self, header_name: str) -> Dict[str, Any]:
        """Get information about a security header"""
        headers = self.rag_data.get("security_headers", {})
        return headers.get(header_name, {})
    
    def get_error_patterns(self, db_type: str = "all") -> List[str]:
        """Get SQL error patterns"""
        patterns = self.rag_data.get("error_patterns", {})
        if db_type == "all":
            all_patterns = []
            for db_patterns in patterns.values():
                all_patterns.extend(db_patterns)
            return all_patterns
        return patterns.get(db_type, [])
    
    def get_enhanced_analysis_prompt(self, scan_results: Dict[str, Any]) -> str:
        """Generate enhanced LLM analysis prompt"""
        target_url = scan_results.get("target_url", "")
        findings = scan_results.get("findings", [])
        http_response = scan_results.get("http_response", {})
        headers_analysis = scan_results.get("headers_analysis", {})
        body_analysis = scan_results.get("body_analysis", {})
        technology_stack = scan_results.get("technology_stack", {})
        discovered_paths = scan_results.get("discovered_paths", [])
        security_score = scan_results.get("security_score", 0)
        
        # Get RAG context
        rag_context = self._get_rag_context_for_analysis(findings)
        
        prompt = f"""
Bạn là một chuyên gia bảo mật web hàng đầu. Hãy phân tích kết quả scan bảo mật sau đây một cách chi tiết và chuyên nghiệp.

[TARGET] **THÔNG TIN MỤC TIÊU:**
- URL: {target_url}
- Điểm bảo mật: {security_score}/100

[CHART] **KẾT QUẢ HTTP RESPONSE:**
- Status Code: {http_response.get('status_code', 'N/A')}
- Response Size: {len(http_response.get('content', ''))} bytes
- Response Time: {http_response.get('elapsed', 0):.2f}s
- Content Type: {http_response.get('headers', {}).get('Content-Type', 'N/A')}
- Final URL: {http_response.get('url', 'N/A')}

[SECURITY] **PHÂN TÍCH SECURITY HEADERS:**
- Điểm bảo mật: {headers_analysis.get('security_score', 0)}/100
- Headers có sẵn: {sum(1 for h in headers_analysis.get('security_headers', {}).values() if h.get('present', False))}/{len(headers_analysis.get('security_headers', {}))}
- Headers thiếu: {[name for name, info in headers_analysis.get('security_headers', {}).items() if not info.get('present', False)]}

[TOOL] **TECHNOLOGY STACK:**
- Web Server: {technology_stack.get('web_server', 'Unknown')}
- CMS: {', '.join(technology_stack.get('cms', [])) or 'None detected'}
- Frameworks: {', '.join(technology_stack.get('frameworks', [])) or 'None detected'}
- Languages: {', '.join(technology_stack.get('languages', [])) or 'None detected'}

[FOLDER] **DISCOVERED PATHS:**
- Tổng số paths: {len(discovered_paths)}
- Paths quan trọng: {[p['path'] for p in discovered_paths[:10]]}

[ALERT] **VULNERABILITIES FOUND:**
- Tổng số: {len(findings)}
- High: {sum(1 for f in findings if f.get('severity') == 'High')}
- Medium: {sum(1 for f in findings if f.get('severity') == 'Medium')}
- Low: {sum(1 for f in findings if f.get('severity') == 'Low')}

[LIST] **CHI TIẾT VULNERABILITIES:**
"""
        
        for i, finding in enumerate(findings[:10], 1):  # Show first 10 findings
            prompt += f"""
{i}. **{finding.get('type', 'Unknown')}** - {finding.get('severity', 'Unknown')}
   - Path: {finding.get('path', 'N/A')}
   - Parameter: {finding.get('parameter', 'N/A')}
   - Evidence: {finding.get('evidence', 'N/A')}
   - Description: {finding.get('description', 'N/A')}
   - CWE: {finding.get('cwe', 'N/A')}
   - Confidence: {finding.get('confidence', 0):.1f}
"""
        
        prompt += f"""

🧠 **RAG CONTEXT:**
{rag_context}

[NOTE] **YÊU CẦU PHÂN TÍCH:**

Hãy cung cấp phân tích chi tiết theo format sau:

## [SCAN] **TỔNG QUAN BẢO MẬT**
- Đánh giá tổng thể về tình trạng bảo mật
- Điểm số bảo mật và giải thích
- Những điểm mạnh và yếu chính

## [ALERT] **PHÂN TÍCH VULNERABILITIES**
- Phân tích từng loại lỗ hổng được phát hiện
- Mức độ nghiêm trọng và tác động
- Khả năng khai thác và proof-of-concept

## [SECURITY] **PHÂN TÍCH SECURITY HEADERS**
- Headers thiếu và tác động
- Khuyến nghị cấu hình headers
- Best practices cho từng header

## [TOOL] **PHÂN TÍCH TECHNOLOGY STACK**
- Rủi ro bảo mật của từng technology
- Version disclosure và tác động
- Khuyến nghị cập nhật và hardening

## [FOLDER] **PHÂN TÍCH DISCOVERED PATHS**
- Paths nguy hiểm và tác động
- Information disclosure risks
- Khuyến nghị bảo mật

## [TARGET] **KHUYẾN NGHỊ ƯU TIÊN**
- Top 5 hành động cần thực hiện ngay
- Timeline và mức độ ưu tiên
- Resources và tools cần thiết

## [BOOK] **REFERENCES & RESOURCES**
- OWASP guidelines liên quan
- CVE references nếu có
- Tools và techniques để test thêm

Hãy phân tích một cách chuyên nghiệp, chi tiết và cung cấp khuyến nghị thực tế có thể áp dụng ngay.
"""
        
        return prompt
    
    def _get_rag_context_for_analysis(self, findings: List[Dict[str, Any]]) -> str:
        """Get RAG context for vulnerability analysis"""
        context_parts = []
        
        # Get unique vulnerability types
        vuln_types = list(set(f.get('type', '').lower() for f in findings))
        
        for vuln_type in vuln_types:
            if vuln_type:
                vuln_info = self.get_vulnerability_info(vuln_type)
                if vuln_info:
                    context_parts.append(f"""
**{vuln_type.upper()} KNOWLEDGE:**
- Description: {vuln_info.get('description', 'N/A')}
- CVSS Score: {vuln_info.get('cvss_score', 'N/A')}
- CWE: {vuln_info.get('cwe', 'N/A')}
- OWASP Top 10: {vuln_info.get('owasp_top10', 'N/A')}
- Attack Complexity: {vuln_info.get('attack_complexity', 'N/A')}
- Impact: {vuln_info.get('impact', 'N/A')}
- Detection Methods: {', '.join(vuln_info.get('detection_methods', []))}
- Remediation: {vuln_info.get('remediation', 'N/A')}
""")
        
        # Add general security knowledge
        context_parts.append("""
**GENERAL SECURITY KNOWLEDGE:**
- Security headers are critical for web application protection
- Information disclosure can lead to further attacks
- Technology stack disclosure helps attackers target specific vulnerabilities
- Path discovery can reveal sensitive files and directories
- Regular security testing is essential for maintaining security posture
""")
        
        return "\n".join(context_parts)
    
    def get_scan_techniques(self, technique_type: str) -> List[Dict[str, Any]]:
        """Get scanning techniques"""
        techniques = self.rag_data.get("scanning_techniques", {})
        return techniques.get(technique_type, [])
    
    def get_remediation_guide(self, vuln_type: str) -> Dict[str, Any]:
        """Get remediation guide for vulnerability type"""
        guides = self.rag_data.get("remediation_guides", {})
        return guides.get(vuln_type.lower(), {})
    
    def get_confidence_scoring(self) -> Dict[str, Any]:
        """Get confidence scoring guidelines"""
        return self.rag_data.get("confidence_scoring", {})
    
    def get_test_sites(self) -> List[Dict[str, Any]]:
        """Get list of test sites"""
        return self.rag_data.get("test_sites", [])
    
    def get_scan_commands(self, tool: str) -> List[str]:
        """Get scan command templates"""
        commands = self.rag_data.get("scan_commands", {})
        return commands.get(tool, [])

