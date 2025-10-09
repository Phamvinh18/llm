"""
Simple Chat Assistant với scan functionality đúng
"""

import asyncio
import re
import json
import time
from typing import Dict, Any, List
from app.core.enhanced_rag_retriever import EnhancedRAGRetriever
from app.clients.gemini_client import GeminiClient
from app.core.real_tools_integration import RealToolsIntegration

class ChatCommand:
    """Chat commands enum"""
    PAYLOAD = "/payload"
    SCAN = "/scan"
    HELP = "/help"
    GREETING = "/greeting"
    UNKNOWN = "unknown"

class ChatResponse:
    """Chat response class"""
    def __init__(self, message: str, command: str, suggestions: List[str] = None, 
                 vulnerability_type: str = None, target_url: str = None, 
                 payloads: List[str] = None, scan_results: Dict = None, 
                 llm_analysis: str = None):
        self.message = message
        self.command = command
        self.suggestions = suggestions or []
        self.vulnerability_type = vulnerability_type
        self.target_url = target_url
        self.payloads = payloads
        self.scan_results = scan_results
        self.llm_analysis = llm_analysis

class ChatAssistantSimple:
    """Simple Chat Assistant với scan functionality đúng"""
    
    def __init__(self):
        self.llm_client = GeminiClient()
        self.kb_retriever = EnhancedRAGRetriever()
        
    async def process_message(self, user_message: str, user_id: str = "default") -> ChatResponse:
        """Process user message"""
        try:
            message = user_message.strip()
            command = self._detect_command(message)
            
            if command == ChatCommand.SCAN:
                return await self._handle_scan_command(message)
            elif command == ChatCommand.PAYLOAD:
                return await self._handle_payload_command(message)
            elif command == ChatCommand.HELP:
                return await self._handle_help_command()
            elif command == ChatCommand.GREETING:
                return await self._handle_greeting_command()
            else:
                return await self._handle_natural_conversation(message)
                
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi: {str(e)}",
                command=ChatCommand.UNKNOWN,
                suggestions=["Hãy thử lại", "Sử dụng /help để xem hướng dẫn"]
            )
    
    def _detect_command(self, message: str) -> ChatCommand:
        """Detect command từ message"""
        message_lower = message.lower()
        
        if message_lower.startswith('/scan'):
            return ChatCommand.SCAN
        elif message_lower.startswith('/payload'):
            return ChatCommand.PAYLOAD
        elif message_lower.startswith('/help'):
            return ChatCommand.HELP
        elif message_lower.startswith('/') or message_lower in ['hi', 'hello', 'chào', 'xin chào']:
            return ChatCommand.GREETING
        else:
            return ChatCommand.UNKNOWN
    
    async def _handle_scan_command(self, message: str) -> ChatResponse:
        """Handle /scan command - Thực sự chạy scan và trả về kết quả"""
        try:
            # Extract URL from message
            url_pattern = r'https?://[^\s]+'
            url_match = re.search(url_pattern, message)
            
            if not url_match:
                return ChatResponse(
                    message="[ERROR] Vui lòng cung cấp URL để scan. Ví dụ: /scan http://example.com",
                    command=ChatCommand.SCAN,
                    suggestions=[
                        "/scan http://testphp.vulnweb.com/",
                        "/scan http://example.com",
                        "/help"
                    ]
                )
            
            target_url = url_match.group()
            
            # Thực sự chạy scan với các tool thực tế
            print(f"[SCAN] Starting real scan for {target_url}")
            
            # Import working tools integration
            from app.core.working_tools_integration import WorkingToolsIntegration
            
            # Run all security tools
            tools_results = await WorkingToolsIntegration.run_all_tools(target_url)
            
            # Perform basic HTTP analysis
            http_analysis = await self._perform_http_analysis(target_url)
            
            # Get RAG context for analysis
            rag_context = self._get_scan_rag_context(target_url)
            
            # Combine results
            scan_results = {
                'target_url': target_url,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'tools_scan_time': tools_results.get('scan_time', 0),
                'http_analysis': http_analysis,
                'nikto_results': tools_results.get('nikto_results', []),
                'nuclei_results': tools_results.get('nuclei_results', []),
                'ffuf_results': tools_results.get('ffuf_results', []),
                'xss_results': tools_results.get('xss_results', []),
                'sql_results': tools_results.get('sql_results', []),
                'directory_traversal_results': tools_results.get('directory_traversal_results', []),
                'command_injection_results': tools_results.get('command_injection_results', []),
                'httpx_results': tools_results.get('httpx_results', {}),
                'rag_context': rag_context
            }
            
            # Analyze with LLM + RAG
            llm_analysis = self._analyze_scan_results_with_llm_rag(scan_results)
            
            # Format response
            response_message = self._format_scan_response(scan_results, llm_analysis)
            
            return ChatResponse(
                message=response_message,
                command=ChatCommand.SCAN,
                suggestions=[
                    f"/payload xss {target_url}",
                    f"/payload sql {target_url}",
                    "/help"
                ]
            )
                
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi scan: {str(e)}",
                command=ChatCommand.SCAN,
                suggestions=["Thử lại", "/help"]
            )
    
    async def _perform_http_analysis(self, target_url: str) -> Dict[str, Any]:
        """Perform comprehensive HTTP analysis including body analysis"""
        try:
            import requests
            import re
            from bs4 import BeautifulSoup
            
            response = requests.get(target_url, timeout=30, allow_redirects=True)
            
            # Basic HTTP info
            http_info = {
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'N/A'),
                'content_type': response.headers.get('Content-Type', 'N/A'),
                'content_length': len(response.content),
                'response_time': 'N/A',
                'headers': dict(response.headers),
                'security_headers': self._analyze_security_headers(response.headers)
            }
            
            # Body analysis
            body_analysis = self._analyze_response_body(response.text, target_url)
            http_info['body_analysis'] = body_analysis
            
            return http_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_response_body(self, html_content: str, target_url: str) -> Dict[str, Any]:
        """Analyze HTML body for forms, inputs, and potential vulnerabilities"""
        try:
            from bs4 import BeautifulSoup
            import re
            
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find forms
            forms = []
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET'),
                    'inputs': []
                }
                
                # Find inputs in form
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        'type': input_tag.get('type', 'text'),
                        'name': input_tag.get('name', ''),
                        'id': input_tag.get('id', ''),
                        'placeholder': input_tag.get('placeholder', '')
                    }
                    form_info['inputs'].append(input_info)
                
                forms.append(form_info)
            
            # Find JavaScript sinks (dangerous functions)
            js_sinks = []
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string:
                    # Look for dangerous JS functions
                    dangerous_patterns = [
                        r'eval\s*\(',
                        r'document\.write\s*\(',
                        r'innerHTML\s*=',
                        r'outerHTML\s*=',
                        r'setTimeout\s*\(',
                        r'setInterval\s*\(',
                        r'Function\s*\('
                    ]
                    
                    for pattern in dangerous_patterns:
                        matches = re.findall(pattern, script.string, re.IGNORECASE)
                        if matches:
                            js_sinks.append({
                                'pattern': pattern,
                                'matches': len(matches),
                                'context': script.string[:200] + '...' if len(script.string) > 200 else script.string
                            })
            
            # Find hidden comments
            comments = []
            for comment in soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--')):
                if 'debug' in comment.lower() or 'test' in comment.lower() or 'todo' in comment.lower():
                    comments.append(comment.strip())
            
            # Find potential XSS points
            xss_points = []
            for tag in soup.find_all(['a', 'img', 'iframe', 'object', 'embed']):
                for attr in ['href', 'src', 'data']:
                    if tag.get(attr):
                        value = tag.get(attr)
                        if 'javascript:' in value.lower() or 'data:' in value.lower():
                            xss_points.append({
                                'tag': tag.name,
                                'attribute': attr,
                                'value': value,
                                'type': 'javascript_url' if 'javascript:' in value.lower() else 'data_url'
                            })
            
            # Find potential SQL injection points
            sql_points = []
            for form in forms:
                for input_field in form['inputs']:
                    if any(keyword in input_field['name'].lower() for keyword in ['id', 'user', 'search', 'query', 'filter']):
                        sql_points.append({
                            'form_action': form['action'],
                            'input_name': input_field['name'],
                            'input_type': input_field['type'],
                            'risk_level': 'medium' if 'id' in input_field['name'].lower() else 'low'
                        })
            
            return {
                'forms_found': len(forms),
                'forms': forms[:5],  # Limit to first 5 forms
                'js_sinks_found': len(js_sinks),
                'js_sinks': js_sinks[:3],  # Limit to first 3
                'hidden_comments': comments[:3],
                'xss_points': xss_points[:3],
                'sql_injection_points': sql_points[:3],
                'total_forms': len(forms),
                'total_js_sinks': len(js_sinks),
                'total_xss_points': len(xss_points),
                'total_sql_points': len(sql_points)
            }
            
        except Exception as e:
            return {'error': f'Body analysis failed: {str(e)}'}
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security headers"""
        security_headers = {
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'X-XSS-Protection': 'XSS protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'XSS protection',
            'Referrer-Policy': 'Information leakage prevention'
        }
        
        present = []
        missing = []
        
        for header, description in security_headers.items():
            if header in headers:
                present.append({
                    'header': header,
                    'value': headers[header],
                    'description': description
                })
            else:
                missing.append({
                    'header': header,
                    'description': description
                })
        
        # Calculate security score
        security_score = (len(present) / len(security_headers)) * 100
        
        return {
            'present': present,
            'missing': missing,
            'security_score': security_score
        }
    
    def _get_scan_rag_context(self, target_url: str) -> str:
        """Get comprehensive RAG context for scan analysis"""
        try:
            context_parts = []
            
            # Get RAG knowledge for comprehensive scan
            if self.kb_retriever:
                # Get OWASP Top 10 2023 knowledge
                owasp_docs = self.kb_retriever.retrieve("OWASP Top 10 2023 security risks vulnerabilities", k=4)
                if owasp_docs:
                    context_parts.append("**OWASP Top 10 2023 Knowledge:**")
                    for doc in owasp_docs:
                        content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                        context_parts.append(f"- {content[:300]}...")
                    context_parts.append("")
                
                # Get vulnerability detection techniques
                detection_docs = self.kb_retriever.retrieve("vulnerability detection techniques XSS SQL injection", k=3)
                if detection_docs:
                    context_parts.append("**Advanced Detection Techniques:**")
                    for doc in detection_docs:
                        content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                        context_parts.append(f"- {content[:300]}...")
                    context_parts.append("")
                
                # Get security headers knowledge
                headers_docs = self.kb_retriever.retrieve("security headers HTTP protection CSP HSTS", k=3)
                if headers_docs:
                    context_parts.append("**Security Headers Best Practices:**")
                    for doc in headers_docs:
                        content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                        context_parts.append(f"- {content[:300]}...")
                    context_parts.append("")
                
                # Get payload techniques
                payload_docs = self.kb_retriever.retrieve("payload techniques XSS SQL injection bypass", k=3)
                if payload_docs:
                    context_parts.append("**Advanced Payload Techniques:**")
                    for doc in payload_docs:
                        content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                        context_parts.append(f"- {content[:300]}...")
                    context_parts.append("")
                
                # Get remediation knowledge
                remediation_docs = self.kb_retriever.retrieve("remediation fixes security vulnerabilities", k=2)
                if remediation_docs:
                    context_parts.append("**Security Remediation Guidelines:**")
                    for doc in remediation_docs:
                        content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                        context_parts.append(f"- {content[:300]}...")
                    context_parts.append("")
                
                # Get CVE and exploit knowledge
                cve_docs = self.kb_retriever.retrieve("CVE exploits vulnerabilities database", k=2)
                if cve_docs:
                    context_parts.append("**CVE Database Knowledge:**")
                    for doc in cve_docs:
                        content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                        context_parts.append(f"- {content[:300]}...")
                    context_parts.append("")
            
            # Add target-specific analysis context
            context_parts.append(f"**Target-Specific Analysis for {target_url}:**")
            context_parts.append("- Comprehensive vulnerability assessment with real tool results")
            context_parts.append("- RAG-guided detection patterns and techniques")
            context_parts.append("- Advanced payload generation and testing")
            context_parts.append("- Real-world attack scenarios and exploitation")
            context_parts.append("- Industry best practices and compliance standards")
            context_parts.append("- CVE correlation and exploit database matching")
            context_parts.append("- OWASP Top 10 2023 mapping and remediation")
            
            return "\n".join(context_parts)
            
        except Exception as e:
            return f"RAG context retrieval error: {str(e)}"
    
    def _analyze_scan_results_with_llm_rag(self, scan_results: Dict[str, Any]) -> str:
        """Analyze scan results with LLM + RAG"""
        try:
            target_url = scan_results['target_url']
            nikto_results = scan_results.get('nikto_results', [])
            nuclei_results = scan_results.get('nuclei_results', [])
            ffuf_results = scan_results.get('ffuf_results', [])
            xss_results = scan_results.get('xss_results', [])
            sql_results = scan_results.get('sql_results', [])
            traversal_results = scan_results.get('directory_traversal_results', [])
            cmd_results = scan_results.get('command_injection_results', [])
            httpx_results = scan_results.get('httpx_results', {})
            http_analysis = scan_results.get('http_analysis', {})
            rag_context = scan_results.get('rag_context', '')
            
            prompt = f"""
            Bạn là chuyên gia bảo mật web hàng đầu với kiến thức sâu rộng về OWASP, CVE, và các kỹ thuật tấn công thực tế. 
            Hãy phân tích chi tiết kết quả scan này từ các tool thực tế và đưa ra đánh giá chuyên nghiệp:
            
            ===== THÔNG TIN SCAN =====
            Target URL: {target_url}
            Scan Time: {scan_results.get('scan_time', 'N/A')}
            Tools Scan Time: {scan_results.get('tools_scan_time', 0):.2f}s
            Scan Type: Comprehensive Security Assessment
            
            ## [TOOL] **KẾT QUẢ TỪ CÁC TOOL THỰC TẾ**
            
            ### Nikto Scan Results: {len(nikto_results)} findings
            {json.dumps(nikto_results[:3], indent=2, ensure_ascii=False) if nikto_results else 'No Nikto findings'}
            
            ### Nuclei Scan Results: {len(nuclei_results)} findings  
            {json.dumps(nuclei_results[:3], indent=2, ensure_ascii=False) if nuclei_results else 'No Nuclei findings'}
            
            ### FFUF Directory Discovery: {len(ffuf_results)} paths
            {json.dumps(ffuf_results[:5], indent=2, ensure_ascii=False) if ffuf_results else 'No FFUF findings'}
            
            ### XSS Scanner (Advanced): {len(xss_results)} findings
            {json.dumps(xss_results[:3], indent=2, ensure_ascii=False) if xss_results else 'No XSS findings'}
            
            ### SQL Scanner (Advanced): {len(sql_results)} findings
            {json.dumps(sql_results[:3], indent=2, ensure_ascii=False) if sql_results else 'No SQL injection findings'}
            
            ### Directory Traversal Scanner: {len(traversal_results)} findings
            {json.dumps(traversal_results[:3], indent=2, ensure_ascii=False) if traversal_results else 'No directory traversal findings'}
            
            ### Command Injection Scanner: {len(cmd_results)} findings
            {json.dumps(cmd_results[:3], indent=2, ensure_ascii=False) if cmd_results else 'No command injection findings'}
            
            ### HTTPX Technology Detection:
            {json.dumps(httpx_results, indent=2, ensure_ascii=False) if httpx_results else 'No HTTPX results'}
            
            ## [HTTP] **HTTP RESPONSE ANALYSIS**
            - Status Code: {http_analysis.get('status_code', 'N/A')}
            - Server: {http_analysis.get('server', 'N/A')}
            - Content Type: {http_analysis.get('content_type', 'N/A')}
            - Security Score: {http_analysis.get('security_headers', {}).get('security_score', 0):.1f}%
            
            ## [RAG] **RAG KNOWLEDGE BASE CONTEXT**
            {rag_context}
            
            Hãy phân tích chi tiết theo format sau với thông tin từ các tool thực tế:
            
            ## [SCAN] **TỔNG QUAN BẢO MẬT**
            - Đánh giá tổng thể về bảo mật của website dựa trên kết quả từ Nikto, Nuclei, FFUF
            - Mức độ rủi ro chung và điểm số bảo mật
            - Thời gian scan và hiệu quả của các tool
            
            ## [ALERT] **LỖ HỔNG BẢO MẬT PHÁT HIỆN**
            ### Nikto Findings ({len(nikto_results)} findings)
            - Phân tích chi tiết từng lỗ hổng Nikto phát hiện
            - Mức độ nghiêm trọng và khả năng khai thác
            - CVE/OSVDB references nếu có
            
            ### Nuclei Findings ({len(nuclei_results)} findings)
            - Phân tích các template Nuclei đã match
            - Severity levels và classification
            - Request/Response evidence
            
            ### Path Discovery Analysis ({len(ffuf_results)} paths)
            - Các endpoint có thể khai thác từ FFUF
            - Admin panels và sensitive paths
            - Backup files và configuration files
            - Directory structure analysis
            
            ### SQL Injection Analysis ({len(sql_results)} findings)
            - SQLMap detection results
            - Database type và version information
            - Injection points và techniques
            
            ### XSS Analysis ({len(xss_results)} findings)
            - Dalfox XSS detection results
            - Reflected và stored XSS potential
            - Payload effectiveness và bypass techniques
            
            ## [WARNING] **MỨC ĐỘ NGHIÊM TRỌNG & PHÂN TÍCH RỦI RO**
            Hãy đánh giá mức độ nghiêm trọng dựa trên:
            - Critical: Lỗ hổng có thể dẫn đến compromise hoàn toàn, RCE, data breach
            - High: Lỗ hổng có thể dẫn đến data breach, privilege escalation
            - Medium: Lỗ hổng có thể dẫn đến information disclosure, limited access
            - Low: Lỗ hổng có thể dẫn đến reconnaissance, minor information leak
            
            ## [WRENCH] **KHUYẾN NGHỊ KHẮC PHỤC CHI TIẾT**
            Dựa trên RAG knowledge và tool findings, hãy đưa ra:
            - Specific technical steps để fix từng lỗ hổng
            - Code examples và configuration changes
            - Best practices từ OWASP và industry standards
            - Immediate actions cần thực hiện (priority order)
            - Long-term security improvements
            
            ## [EVIDENCE] **EVIDENCE MAPPING & CVE CORRELATION**
            - Map findings với CVE database và OWASP Top 10 2023
            - Provide specific CVE references nếu có
            - Explain exploit techniques và attack vectors
            - Reference payloads từ PayloadAllTheThings
            
            ## [BUSINESS] **BUSINESS IMPACT ASSESSMENT**
            - Đánh giá tác động kinh doanh của từng lỗ hổng
            - Compliance implications (GDPR, PCI-DSS, etc.)
            - Reputation và financial risks
            - Customer data protection concerns
            
            Hãy sử dụng thông tin từ RAG knowledge base và kết quả tool thực tế để đưa ra phân tích chính xác, 
            tránh ảo giác, và cung cấp actionable insights cho security team.
            """
            
            analysis = self.llm_client.chat(prompt, max_output_tokens=1500)
            return analysis
            
        except Exception as e:
            return f"LLM analysis error: {str(e)}"
    
    def _format_scan_response(self, scan_results: Dict[str, Any], llm_analysis: str) -> str:
        """Format comprehensive scan response for user"""
        target_url = scan_results['target_url']
        
        # Tool results counts
        nikto_count = len(scan_results.get('nikto_results', []))
        nuclei_count = len(scan_results.get('nuclei_results', []))
        ffuf_count = len(scan_results.get('ffuf_results', []))
        xss_count = len(scan_results.get('xss_results', []))
        sql_count = len(scan_results.get('sql_results', []))
        traversal_count = len(scan_results.get('directory_traversal_results', []))
        cmd_count = len(scan_results.get('command_injection_results', []))
        
        # HTTP analysis
        http_analysis = scan_results.get('http_analysis', {})
        security_score = http_analysis.get('security_headers', {}).get('security_score', 0)
        
        # Combine all discovered paths
        all_paths = []
        all_paths.extend(scan_results.get('ffuf_results', []))
        
        # Combine all vulnerabilities
        all_vulnerabilities = []
        all_vulnerabilities.extend(scan_results.get('nikto_results', []))
        all_vulnerabilities.extend(scan_results.get('nuclei_results', []))
        all_vulnerabilities.extend(scan_results.get('xss_results', []))
        all_vulnerabilities.extend(scan_results.get('sql_results', []))
        all_vulnerabilities.extend(scan_results.get('directory_traversal_results', []))
        all_vulnerabilities.extend(scan_results.get('command_injection_results', []))
        
        # Calculate safety score
        safety_score = self._calculate_safety_score(scan_results)
        
        response = f"""[SCAN] **Kết Quả Scan Toàn Diện với RAG + LLM**

[TARGET] **Target:** {target_url}
[TIME] **Thời gian scan:** {scan_results.get('scan_time', 'N/A')}
[TOOLS] **Tools scan time:** {scan_results.get('tools_scan_time', 0):.2f}s

🛰️ **1. RECONNAISSANCE (Thu thập thông tin)**
**Tools:** FFUF, HTTPX, Custom Scanners
**Paths discovered:** {len(all_paths)} total
- **FFUF:** {ffuf_count} paths

**Discovered Paths:**
{self._format_paths(all_paths[:10])}

**Technology Detection:**
{self._format_technology_detection(scan_results.get('httpx_results', {}))}

🧠 **2. HEADER ANALYSIS**
**Tools:** HTTPX, Custom Analysis
**Status Code:** {http_analysis.get('status_code', 'N/A')}
**Server:** {http_analysis.get('server', 'N/A')}
**Content Type:** {http_analysis.get('content_type', 'N/A')}
**Security Score:** {security_score:.1f}%

**Security Headers Analysis:**
{self._format_security_headers(http_analysis.get('security_headers', {}))}

🧱 **3. BODY ANALYSIS**
**Tools:** HTTPX, BeautifulSoup, Custom Analysis
**Content Length:** {http_analysis.get('content_length', 0):,} bytes
**Forms Found:** {http_analysis.get('body_analysis', {}).get('total_forms', 0)}
**JS Sinks:** {http_analysis.get('body_analysis', {}).get('total_js_sinks', 0)}
**XSS Points:** {http_analysis.get('body_analysis', {}).get('total_xss_points', 0)}
**SQL Points:** {http_analysis.get('body_analysis', {}).get('total_sql_points', 0)}

**Body Analysis Details:**
{self._format_body_analysis(http_analysis.get('body_analysis', {}))}

🧨 **4. VULNERABILITY FINDINGS**
**Total Vulnerabilities:** {len(all_vulnerabilities)}
- **Nikto:** {nikto_count} findings
- **Nuclei:** {nuclei_count} findings
- **XSS Scanner:** {xss_count} findings
- **SQL Scanner:** {sql_count} findings
- **Directory Traversal:** {traversal_count} findings
- **Command Injection:** {cmd_count} findings

**Vulnerability Details:**
{self._format_vulnerabilities(all_vulnerabilities[:5])}

📜 **5. EVIDENCE MAPPING (CVE, OWASP, Payload)**
**RAG Knowledge Base Applied:**
- OWASP Top 10 2023 mapping
- CVE database correlation
- PayloadAllTheThings integration
- ExploitDB references

🛠️ **6. RECOMMENDATIONS (LLM + RAG)**
{self._format_recommendations(scan_results)}

💡 **7. SAFETY SCORE & GỢI Ý TIẾP THEO**
**[SAFETY SCORE] {safety_score}/100**

**[GỢI Ý THÊM]**
✅ Thử quét API & endpoint `/login`, `/admin` với BurpSuite Intruder
✅ Kiểm tra file upload `/uploads/` bằng ffuf hoặc wfuzz
✅ Tiến hành RAG chain để tra CVE liên quan đến {http_analysis.get('server', 'Unknown')}
✅ Kích hoạt DeepScan mode: /scan-deep

## [BRAIN] **RAG + LLM PHÂN TÍCH CHI TIẾT**
{llm_analysis}

💡 **Gợi ý tiếp theo:**
• Tạo payload: /payload xss {target_url}
• Tạo payload: /payload sql {target_url}
• Xem hướng dẫn: /help"""
        
        return response
    
    def _format_paths(self, paths: List[Dict[str, Any]]) -> str:
        """Format discovered paths"""
        if not paths:
            return "No paths discovered"
        
        formatted = []
        for path in paths:
            status = path.get('status', 200)
            path_url = path.get('url', path.get('path', ''))
            tool = path.get('tool', 'unknown')
            
            # Status emoji
            if status == 200:
                status_emoji = "✅"
            elif status in [301, 302]:
                status_emoji = "🔄"
            elif status == 403:
                status_emoji = "🔒"
            elif status == 404:
                status_emoji = "❌"
            else:
                status_emoji = "⚠️"
            
            formatted.append(f"  {status_emoji} {path_url} (Status: {status}, Tool: {tool})")
        
        return "\n".join(formatted)
    
    def _format_security_headers(self, headers_analysis: Dict[str, Any]) -> str:
        """Format security headers analysis"""
        if not headers_analysis:
            return "No security headers analysis available"
        
        present = headers_analysis.get('present', [])
        missing = headers_analysis.get('missing', [])
        
        formatted = []
        
        if present:
            formatted.append("**✅ Headers có sẵn:**")
            for header in present[:3]:
                formatted.append(f"  • {header['header']}: {header['description']}")
        
        if missing:
            formatted.append("**❌ Headers thiếu:**")
            for header in missing[:3]:
                formatted.append(f"  • {header['header']}: {header['description']}")
        
        return "\n".join(formatted) if formatted else "No security headers found"
    
    def _format_body_analysis(self, body_analysis: Dict[str, Any]) -> str:
        """Format body analysis results"""
        if not body_analysis or 'error' in body_analysis:
            return "Body analysis failed or not available"
        
        formatted = []
        
        # Forms analysis
        forms = body_analysis.get('forms', [])
        if forms:
            formatted.append("**📝 Forms Found:**")
            for i, form in enumerate(forms[:3], 1):
                action = form.get('action', 'N/A')
                method = form.get('method', 'GET')
                inputs = form.get('inputs', [])
                formatted.append(f"  {i}. Action: {action} (Method: {method})")
                for inp in inputs[:3]:
                    name = inp.get('name', 'unnamed')
                    input_type = inp.get('type', 'text')
                    formatted.append(f"     - {name} ({input_type})")
        
        # JavaScript sinks
        js_sinks = body_analysis.get('js_sinks', [])
        if js_sinks:
            formatted.append("**⚠️ JavaScript Sinks (Dangerous Functions):**")
            for sink in js_sinks[:2]:
                pattern = sink.get('pattern', 'unknown')
                matches = sink.get('matches', 0)
                formatted.append(f"  • {pattern} ({matches} occurrences)")
        
        # Hidden comments
        comments = body_analysis.get('hidden_comments', [])
        if comments:
            formatted.append("**💬 Hidden Comments:**")
            for comment in comments[:2]:
                formatted.append(f"  • {comment[:100]}...")
        
        # XSS points
        xss_points = body_analysis.get('xss_points', [])
        if xss_points:
            formatted.append("**🎯 Potential XSS Points:**")
            for point in xss_points[:2]:
                tag = point.get('tag', 'unknown')
                attr = point.get('attribute', 'unknown')
                formatted.append(f"  • {tag}[{attr}] - {point.get('type', 'unknown')}")
        
        # SQL injection points
        sql_points = body_analysis.get('sql_injection_points', [])
        if sql_points:
            formatted.append("**🗄️ Potential SQL Injection Points:**")
            for point in sql_points[:2]:
                form_action = point.get('form_action', 'N/A')
                input_name = point.get('input_name', 'unnamed')
                risk = point.get('risk_level', 'unknown')
                formatted.append(f"  • {form_action} -> {input_name} (Risk: {risk})")
        
        return "\n".join(formatted) if formatted else "No significant findings in body analysis"
    
    def _format_subdomains(self, subdomains: List[Dict[str, Any]]) -> str:
        """Format subdomain discovery results"""
        if not subdomains:
            return "No subdomains discovered"
        
        formatted = []
        for subdomain in subdomains[:5]:  # Limit to first 5
            subdomain_name = subdomain.get('subdomain', 'unknown')
            domain = subdomain.get('domain', 'unknown')
            tool = subdomain.get('tool', 'unknown')
            formatted.append(f"  🌐 {subdomain_name} (Tool: {tool})")
        
        if len(subdomains) > 5:
            formatted.append(f"  ... and {len(subdomains) - 5} more subdomains")
        
        return "\n".join(formatted)
    
    def _format_technology_detection(self, whatweb_results: Dict[str, Any]) -> str:
        """Format technology detection results"""
        if not whatweb_results or 'error' in whatweb_results:
            return "Technology detection failed or not available"
        
        formatted = []
        
        # Basic info
        server = whatweb_results.get('server', 'Unknown')
        title = whatweb_results.get('title', 'Unknown')
        status_code = whatweb_results.get('status_code', 0)
        
        formatted.append(f"**Server:** {server}")
        formatted.append(f"**Title:** {title}")
        formatted.append(f"**Status:** {status_code}")
        
        # Technologies
        technologies = whatweb_results.get('technologies', {})
        if technologies:
            formatted.append("**Technologies Detected:**")
            tech_count = 0
            for tech_name, tech_info in technologies.items():
                if tech_count >= 5:  # Limit to first 5
                    break
                if isinstance(tech_info, dict):
                    version = tech_info.get('version', ['Unknown'])[0] if tech_info.get('version') else 'Unknown'
                    formatted.append(f"  • {tech_name} {version}")
                else:
                    formatted.append(f"  • {tech_name}")
                tech_count += 1
            
            if len(technologies) > 5:
                formatted.append(f"  ... and {len(technologies) - 5} more technologies")
        
        return "\n".join(formatted)
    
    def _format_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format vulnerability findings"""
        if not vulnerabilities:
            return "No vulnerabilities detected"
        
        formatted = []
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            severity = vuln.get('severity', 'unknown')
            url = vuln.get('url', 'N/A')
            tool = vuln.get('tool', 'unknown')
            
            # Severity emoji
            if severity.lower() == 'high':
                severity_emoji = "🔴"
            elif severity.lower() == 'medium':
                severity_emoji = "🟡"
            elif severity.lower() == 'low':
                severity_emoji = "🟢"
            else:
                severity_emoji = "⚪"
            
            formatted.append(f"  {severity_emoji} **{vuln_type.upper()}** - {url} (Tool: {tool})")
        
        return "\n".join(formatted)
    
    def _format_recommendations(self, scan_results: Dict[str, Any]) -> str:
        """Format security recommendations"""
        recommendations = []
        
        # HTTP analysis recommendations
        http_analysis = scan_results.get('http_analysis', {})
        security_headers = http_analysis.get('security_headers', {})
        
        if security_headers.get('security_score', 0) < 50:
            recommendations.append("• Bổ sung security headers (CSP, HSTS, X-Frame-Options)")
        
        # Vulnerability-based recommendations
        all_vulnerabilities = []
        all_vulnerabilities.extend(scan_results.get('nikto_results', []))
        all_vulnerabilities.extend(scan_results.get('nuclei_results', []))
        all_vulnerabilities.extend(scan_results.get('sqlmap_results', []))
        all_vulnerabilities.extend(scan_results.get('dalfox_results', []))
        
        has_sqli = any('sql' in vuln.get('type', '').lower() for vuln in all_vulnerabilities)
        has_xss = any('xss' in vuln.get('type', '').lower() for vuln in all_vulnerabilities)
        
        if has_sqli:
            recommendations.append("• Sử dụng prepared statements cho truy vấn SQL")
        
        if has_xss:
            recommendations.append("• Implement output encoding và Content Security Policy")
        
        # Path-based recommendations
        all_paths = []
        all_paths.extend(scan_results.get('ffuf_results', []))
        
        has_admin = any('admin' in path.get('url', '').lower() or 'admin' in path.get('path', '').lower() for path in all_paths)
        if has_admin:
            recommendations.append("• Kiểm tra bảo mật admin panel và access control")
        
        if not recommendations:
            recommendations.append("• Thực hiện regular security assessments")
            recommendations.append("• Implement security monitoring và logging")
        
        return "\n".join(recommendations)
    
    def _calculate_safety_score(self, scan_results: Dict[str, Any]) -> int:
        """Calculate safety score based on scan results"""
        score = 100
        
        # Deduct points for vulnerabilities
        all_vulnerabilities = []
        all_vulnerabilities.extend(scan_results.get('nikto_results', []))
        all_vulnerabilities.extend(scan_results.get('nuclei_results', []))
        all_vulnerabilities.extend(scan_results.get('sqlmap_results', []))
        all_vulnerabilities.extend(scan_results.get('dalfox_results', []))
        
        for vuln in all_vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity == 'high':
                score -= 20
            elif severity == 'medium':
                score -= 10
            elif severity == 'low':
                score -= 5
        
        # Deduct points for poor security headers
        http_analysis = scan_results.get('http_analysis', {})
        security_headers = http_analysis.get('security_headers', {})
        security_score = security_headers.get('security_score', 0)
        
        if security_score < 30:
            score -= 15
        elif security_score < 60:
            score -= 10
        
        # Deduct points for sensitive paths
        all_paths = []
        all_paths.extend(scan_results.get('ffuf_results', []))
        
        sensitive_paths = ['admin', 'config', 'backup', 'upload', 'test', 'debug']
        for path in all_paths:
            path_str = (path.get('url', '') + path.get('path', '')).lower()
            if any(sensitive in path_str for sensitive in sensitive_paths):
                score -= 5
        
        return max(0, min(100, score))
    
    async def _handle_payload_command(self, message: str) -> ChatResponse:
        """Handle /payload command"""
        return ChatResponse(
            message="Payload functionality coming soon...",
            command=ChatCommand.PAYLOAD,
            suggestions=["/help", "/scan http://testphp.vulnweb.com/"]
        )
    
    async def _handle_help_command(self) -> ChatResponse:
        """Handle /help command"""
        return ChatResponse(
            message="""[HELP] **VA-WebSec Assistant Commands**

## [SCAN] **Security Scanning**
• `/scan <URL>` - Comprehensive security scan with real tools
• Example: `/scan http://testphp.vulnweb.com/`

## [PAYLOAD] **Payload Generation**
• `/payload <type> <URL>` - Generate payloads for specific vulnerability
• Example: `/payload xss http://testphp.vulnweb.com/`

## [HELP] **Support**
• `/help` - Show this help message

**Available Test Sites:**
• http://testphp.vulnweb.com/
• http://demo.testfire.net/""",
            command=ChatCommand.HELP,
            suggestions=[
                "/scan http://testphp.vulnweb.com/",
                "/payload xss http://testphp.vulnweb.com/",
                "/help"
            ]
        )
    
    async def _handle_greeting_command(self) -> ChatResponse:
        """Handle greeting command"""
        return ChatResponse(
            message="""[WAVE] **Xin chào! Tôi là VA-WebSec Assistant**

Tôi có thể giúp bạn:
• 🔍 **Scan bảo mật** với các tool thực tế (Nikto, Nuclei, FFUF)
• 🧠 **Phân tích thông minh** với RAG + LLM
• 🎯 **Tạo payload** cho các lỗ hổng cụ thể
• 📊 **Báo cáo chi tiết** về kết quả scan

**Thử ngay:** `/scan http://testphp.vulnweb.com/`""",
            command=ChatCommand.GREETING,
            suggestions=[
                "/scan http://testphp.vulnweb.com/",
                "/help",
                "/payload xss http://testphp.vulnweb.com/"
            ]
        )
    
    async def _handle_natural_conversation(self, message: str) -> ChatResponse:
        """Handle natural conversation"""
        return ChatResponse(
            message="Tôi hiểu bạn muốn nói chuyện, nhưng tôi chuyên về bảo mật web. Hãy thử:\n• `/scan <URL>` để scan bảo mật\n• `/help` để xem hướng dẫn",
            command=ChatCommand.UNKNOWN,
            suggestions=["/help", "/scan http://testphp.vulnweb.com/"]
        )
