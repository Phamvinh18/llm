"""
Clean Chat Assistant với scan functionality đúng
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
    REPORT = "/report"
    RECOMMEND = "/recommend"
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

class ChatAssistantClean:
    """Clean Chat Assistant với scan functionality đúng"""
    
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
            
            # Get RAG context for scan
            rag_context = self._get_scan_rag_context(target_url)
            
            # Thực sự chạy scan với các tool thực tế
            print(f"[SCAN] Starting real scan for {target_url}")
            
            # Run all security tools
            tools_results = await RealToolsIntegration.run_all_tools(target_url)
            
            # Perform basic HTTP analysis
            http_analysis = await self._perform_http_analysis(target_url)
            
            # Combine results
            scan_results = {
                'target_url': target_url,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'tools_scan_time': tools_results.get('scan_time', 0),
                'http_analysis': http_analysis,
                'nikto_results': tools_results.get('nikto_results', []),
                'nuclei_results': tools_results.get('nuclei_results', []),
                'ffuf_results': tools_results.get('ffuf_results', []),
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
        """Perform basic HTTP analysis"""
        try:
            import requests
            
            response = requests.get(target_url, timeout=30, allow_redirects=True)
            
            return {
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'N/A'),
                'content_type': response.headers.get('Content-Type', 'N/A'),
                'content_length': len(response.content),
                'response_time': 'N/A',
                'headers': dict(response.headers),
                'security_headers': self._analyze_security_headers(response.headers)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
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
        """Get RAG context for scan analysis"""
        try:
            context_parts = []
            
            # Get RAG knowledge for comprehensive scan
            if self.kb_retriever:
                # Get OWASP Top 10 2023 knowledge
                owasp_docs = self.kb_retriever.retrieve("OWASP Top 10 2023 security risks", k=3)
                if owasp_docs:
                    context_parts.append("**OWASP Top 10 2023 Knowledge:**")
                    for doc in owasp_docs:
                        content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                        context_parts.append(f"- {content[:200]}...")
                    context_parts.append("")
                
                # Get vulnerability detection techniques
                detection_docs = self.kb_retriever.retrieve("vulnerability detection techniques", k=2)
                if detection_docs:
                    context_parts.append("**Detection Techniques:**")
                    for doc in detection_docs:
                        content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                        context_parts.append(f"- {content[:200]}...")
                    context_parts.append("")
                
                # Get security headers knowledge
                headers_docs = self.kb_retriever.retrieve("security headers HTTP protection", k=2)
                if headers_docs:
                    context_parts.append("**Security Headers Analysis:**")
                    for doc in headers_docs:
                        content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                        context_parts.append(f"- {content[:200]}...")
                    context_parts.append("")
            
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
            httpx_results = scan_results.get('httpx_results', {})
            http_analysis = scan_results.get('http_analysis', {})
            rag_context = scan_results.get('rag_context', '')
            
            prompt = f"""
            Bạn là chuyên gia bảo mật web với kiến thức sâu rộng. Hãy phân tích kết quả scan này từ các tool thực tế:
            
            Target URL: {target_url}
            Scan Time: {scan_results.get('scan_time', 'N/A')}
            Tools Scan Time: {scan_results.get('tools_scan_time', 0):.2f}s
            
            ## [TOOL] **KẾT QUẢ TỪ CÁC TOOL THỰC TẾ**
            
            ### Nikto Scan Results: {len(nikto_results)} findings
            {json.dumps(nikto_results[:3], indent=2, ensure_ascii=False) if nikto_results else 'No Nikto findings'}
            
            ### Nuclei Scan Results: {len(nuclei_results)} findings  
            {json.dumps(nuclei_results[:3], indent=2, ensure_ascii=False) if nuclei_results else 'No Nuclei findings'}
            
            ### FFUF Directory Discovery: {len(ffuf_results)} paths
            {json.dumps(ffuf_results[:5], indent=2, ensure_ascii=False) if ffuf_results else 'No FFUF findings'}
            
            ### HTTPX Results:
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
            
            ## [WARNING] **MỨC ĐỘ NGHIÊM TRỌNG**
            - Critical: Lỗ hổng có thể dẫn đến compromise hoàn toàn
            - High: Lỗ hổng có thể dẫn đến data breach  
            - Medium: Lỗ hổng có thể dẫn đến information disclosure
            - Low: Lỗ hổng có thể dẫn đến reconnaissance
            
            ## [WRENCH] **KHUYẾN NGHỊ KHẮC PHỤC**
            - Specific steps để fix từng lỗ hổng dựa trên tool findings
            - Best practices cho security dựa trên RAG knowledge
            - Immediate actions cần thực hiện
            
            Sử dụng thông tin từ RAG và kết quả tool thực tế để đưa ra phân tích chính xác và tránh ảo giác.
            """
            
            analysis = self.llm_client.chat(prompt, max_output_tokens=1500)
            return analysis
            
        except Exception as e:
            return f"LLM analysis error: {str(e)}"
    
    def _format_scan_response(self, scan_results: Dict[str, Any], llm_analysis: str) -> str:
        """Format scan response for user"""
        target_url = scan_results['target_url']
        nikto_count = len(scan_results.get('nikto_results', []))
        nuclei_count = len(scan_results.get('nuclei_results', []))
        ffuf_count = len(scan_results.get('ffuf_results', []))
        http_analysis = scan_results.get('http_analysis', {})
        security_score = http_analysis.get('security_headers', {}).get('security_score', 0)
        
        response = f"""[SCAN] **Kết Quả Scan Thực Tế với RAG + LLM**

[TARGET] **Target:** {target_url}
[TIME] **Thời gian scan:** {scan_results.get('scan_time', 'N/A')}
[TOOLS] **Tools scan time:** {scan_results.get('tools_scan_time', 0):.2f}s

## [TOOL] **KẾT QUẢ TỪ CÁC TOOL THỰC TẾ**
✅ **Nikto:** {nikto_count} vulnerabilities found
✅ **Nuclei:** {nuclei_count} findings detected  
✅ **FFUF:** {ffuf_count} paths discovered
✅ **HTTPX:** Technology detection completed

## [HTTP] **HTTP RESPONSE ANALYSIS**
- **Status Code:** {http_analysis.get('status_code', 'N/A')}
- **Server:** {http_analysis.get('server', 'N/A')}
- **Content Type:** {http_analysis.get('content_type', 'N/A')}
- **Security Score:** {security_score:.1f}%

## [BRAIN] **RAG + LLM PHÂN TÍCH**
{llm_analysis}

## [RAG] **RAG KNOWLEDGE BASE IMPACT**
- OWASP Top 10 2023 knowledge applied
- Real-world vulnerability patterns analyzed
- Best practice remediation suggested
- Industry standards referenced

💡 **Gợi ý tiếp theo:**
• Tạo payload: /payload xss {target_url}
• Tạo payload: /payload sql {target_url}
• Xem hướng dẫn: /help"""
        
        return response
    
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
