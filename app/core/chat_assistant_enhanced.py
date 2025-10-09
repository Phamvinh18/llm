"""
Enhanced Chat Assistant - Sử dụng Scan Orchestrator mới
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
from app.core.enhanced_rag_retriever import EnhancedRAGRetriever
from app.core.scan_orchestrator import ScanOrchestrator
from app.core.evidence_storage import EvidenceStorage

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
    EVIDENCE = "/evidence"
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

class EnhancedChatAssistant:
    """Enhanced Chat Assistant với Scan Orchestrator"""
    
    def __init__(self):
        self.llm_client = GeminiClient()
        self.rag_retriever = EnhancedRAGRetriever()
        self.scan_orchestrator = ScanOrchestrator()
        self.evidence_storage = EvidenceStorage()
        self.conversation_history = []
    
    async def process_message(self, user_message: str, user_id: str = "default") -> ChatResponse:
        """Xử lý tin nhắn từ người dùng"""
        try:
            message = user_message.strip()
            command = self._detect_command(message)
            
            # Process based on command
            if command == ChatCommand.PAYLOAD:
                return await self._handle_payload_command(message)
            elif command == ChatCommand.SCAN:
                return await self._handle_scan_command(message)
            elif command == ChatCommand.SCAN_STATUS:
                return await self._handle_scan_status_command(message)
            elif command == ChatCommand.SCAN_RESULTS:
                return await self._handle_scan_results_command(message)
            elif command == ChatCommand.EVIDENCE:
                return await self._handle_evidence_command(message)
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
        elif message_lower.startswith('/evidence'):
            return ChatCommand.EVIDENCE
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
    
    async def _handle_scan_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /scan với Enhanced Orchestrator System"""
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
            
            # Start scan with orchestrator system
            result = await self.scan_orchestrator.start_scan(target_url)
            
            if result["success"]:
                job_id = result["job_id"]
                
                # Create response message with RAG importance
                response_message = f"""🚀 **Enhanced Security Scan với RAG Intelligence**

🎯 **Target:** `{target_url}`
🆔 **Job ID:** `{job_id}`
🧠 **RAG Knowledge Base:** ✅ Active
📁 **Evidence Storage:** ✅ Enabled

🔄 **Enhanced Scan Pipeline:**
1. 🔍 **Reconnaissance** - HTTPX, WhatWeb analysis
2. 🕷️ **Crawling** - GoSpider intelligent crawling  
3. 🎯 **Fuzzing** - FFUF directory discovery
4. 🛡️ **Vulnerability Detection** - Nuclei, Dalfox, Nikto
5. ✅ **Confirmatory Tests** - Marker reflection, evidence capture
6. 🤖 **LLM + RAG Enrichment** - Provenance tracking
7. 📊 **Evidence Storage** - Screenshots, HAR, raw outputs

✨ **RAG Intelligence Features:**
• 📚 OWASP Top 10 2023 knowledge
• 🎯 Advanced payload techniques  
• 🌍 Real-world vulnerability patterns
• 🔧 Best practice remediation
• 🗄️ CVE database integration
• 📋 Provenance tracking for all claims

⏳ **Status:** Scan đang chạy... Sử dụng `/scan-status` để kiểm tra tiến độ.

🎯 **RAG Impact - Knowledge Base cung cấp:**
• Context chính xác cho từng loại lỗ hổng
• Advanced detection techniques
• Comprehensive remediation guidance  
• Real-world attack patterns
• Industry best practices
• Evidence-based analysis

💡 **Next Steps:**
• Kiểm tra tiến độ: `/scan-status {job_id}`
• Xem kết quả: `/scan-results {job_id}`
• Tải evidence: `/evidence {job_id}`
• Tạo báo cáo: `/report {job_id}`"""
                
                return ChatResponse(
                    message=response_message,
                    command=ChatCommand.SCAN,
                    target_url=target_url,
                    suggestions=[
                        f"Kiểm tra tiến độ: /scan-status {job_id}",
                        f"Xem kết quả: /scan-results {job_id}",
                        f"Tải evidence: /evidence {job_id}",
                        "Tạo payload: /payload xss " + target_url
                    ]
                )
            else:
                return ChatResponse(
                    message=f"[ERROR] Không thể bắt đầu scan: {result.get('error', 'Unknown error')}",
                    command=ChatCommand.SCAN,
                    suggestions=[
                        "Kiểm tra URL có hợp lệ không",
                        "Kiểm tra target có trong allowlist không",
                        "Sử dụng /help để xem hướng dẫn"
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
    
    async def _handle_scan_status_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /scan-status"""
        try:
            parts = message.split()
            if len(parts) < 2:
                return ChatResponse(
                    message="[ERROR] Vui lòng cung cấp Job ID. Ví dụ: /scan-status job_12345678",
                    command=ChatCommand.SCAN_STATUS,
                    suggestions=[
                        "Cung cấp Job ID hợp lệ",
                        "Ví dụ: /scan-status job_12345678",
                        "Sử dụng /help để xem hướng dẫn"
                    ]
                )
            
            job_id = parts[1]
            job = self.scan_orchestrator.get_scan_status(job_id)
            
            if not job:
                return ChatResponse(
                    message=f"[ERROR] Không tìm thấy job với ID: {job_id}",
                    command=ChatCommand.SCAN_STATUS,
                    suggestions=[
                        "Kiểm tra Job ID",
                        "Xem danh sách jobs: /jobs",
                        "Bắt đầu scan mới: /scan <URL>"
                    ]
                )
            
            # Create status message
            status_emoji = {
                "pending": "⏳",
                "running": "🔄",
                "completed": "✅",
                "failed": "❌",
                "cancelled": "🚫"
            }
            
            emoji = status_emoji.get(job.status.value, "❓")
            
            response_message = f"""{emoji} **Scan Status**

🆔 **Job ID:** `{job.job_id}`
🎯 **Target:** `{job.target_url}`
📊 **Status:** {job.status.value.upper()}
🔄 **Stage:** {job.current_stage.value.replace('_', ' ').title()}
📈 **Progress:** {job.progress}%

⏰ **Timestamps:**
• Created: {job.created_at}
• Started: {job.started_at or 'Not started'}
• Completed: {job.completed_at or 'Not completed'}

{f"❌ **Error:** {job.error_message}" if job.error_message else ""}

💡 **Next Steps:**
{f"• Xem kết quả: /scan-results {job_id}" if job.status.value == "completed" else ""}
{f"• Hủy scan: /scan-cancel {job_id}" if job.status.value == "running" else ""}
• Tạo scan mới: /scan <URL>"""
            
            return ChatResponse(
                message=response_message,
                command=ChatCommand.SCAN_STATUS,
                suggestions=[
                    f"Xem kết quả: /scan-results {job_id}" if job.status.value == "completed" else f"Kiểm tra lại: /scan-status {job_id}",
                    "Tạo scan mới: /scan <URL>",
                    "Xem help: /help"
                ]
            )
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi kiểm tra status: {str(e)}",
                command=ChatCommand.SCAN_STATUS,
                suggestions=[
                    "Kiểm tra Job ID",
                    "Thử lại sau",
                    "Sử dụng /help để xem hướng dẫn"
                ]
            )
    
    async def _handle_scan_results_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /scan-results"""
        try:
            parts = message.split()
            if len(parts) < 2:
                return ChatResponse(
                    message="[ERROR] Vui lòng cung cấp Job ID. Ví dụ: /scan-results job_12345678",
                    command=ChatCommand.SCAN_RESULTS,
                    suggestions=[
                        "Cung cấp Job ID hợp lệ",
                        "Ví dụ: /scan-results job_12345678",
                        "Sử dụng /help để xem hướng dẫn"
                    ]
                )
            
            job_id = parts[1]
            results = self.scan_orchestrator.get_scan_results(job_id)
            
            if not results:
                return ChatResponse(
                    message=f"[ERROR] Không tìm thấy kết quả cho Job ID: {job_id}",
                    command=ChatCommand.SCAN_RESULTS,
                    suggestions=[
                        "Kiểm tra Job ID",
                        "Kiểm tra status: /scan-status {job_id}",
                        "Bắt đầu scan mới: /scan <URL>"
                    ]
                )
            
            findings = results.get("findings", [])
            
            # Create results summary
            severity_counts = {}
            for finding in findings:
                severity = finding.get("severity", "Unknown")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            severity_emojis = {
                "Critical": "🔴",
                "High": "🟠", 
                "Medium": "🟡",
                "Low": "🟢",
                "Unknown": "⚪"
            }
            
            severity_summary = " | ".join([
                f"{severity_emojis.get(sev, '⚪')} {sev}: {count}" 
                for sev, count in severity_counts.items()
            ])
            
            response_message = f"""📊 **Scan Results**

🆔 **Job ID:** `{job_id}`
🎯 **Target:** `{results.get('target_url', '')}`
📊 **Status:** {results.get('status', '').upper()}
📈 **Progress:** {results.get('progress', 0)}%

🚨 **Findings Summary:**
{severity_summary}
**Total:** {len(findings)} findings

📁 **Evidence Available:**
• Raw outputs: {len(results.get('raw_outputs', {}))} files
• Evidence directory: `{results.get('evidence_dir', '')}`

🧠 **RAG-Enhanced Analysis:**
• All findings enriched with RAG knowledge
• Provenance tracking for all claims
• Evidence-based confidence scoring
• Industry-standard remediation

💡 **Next Steps:**
• Tải evidence: `/evidence {job_id}`
• Tạo báo cáo: `/report {job_id}`
• Xem chi tiết: `/scan-results {job_id} detailed`"""
            
            return ChatResponse(
                message=response_message,
                command=ChatCommand.SCAN_RESULTS,
                suggestions=[
                    f"Tải evidence: /evidence {job_id}",
                    f"Tạo báo cáo: /report {job_id}",
                    "Tạo scan mới: /scan <URL>"
                ]
            )
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi lấy kết quả: {str(e)}",
                command=ChatCommand.SCAN_RESULTS,
                suggestions=[
                    "Kiểm tra Job ID",
                    "Thử lại sau",
                    "Sử dụng /help để xem hướng dẫn"
                ]
            )
    
    async def _handle_evidence_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /evidence"""
        try:
            parts = message.split()
            if len(parts) < 2:
                return ChatResponse(
                    message="""📁 **Evidence Management**

🎯 **Cách sử dụng:**
• `/evidence <job_id>` - Liệt kê evidence files
• `/evidence <job_id> <filename>` - Tải specific file
• `/evidence <job_id> archive` - Tải evidence archive

📋 **Ví dụ:**
• `/evidence job_12345678`
• `/evidence job_12345678 nuclei.json`
• `/evidence job_12345678 archive`

💡 **Evidence Types:**
• Raw tool outputs (JSON)
• Screenshots (PNG)
• HAR files (Network traffic)
• Request/Response data
• Confirmatory test results""",
                    command=ChatCommand.EVIDENCE,
                    suggestions=[
                        "Liệt kê files: /evidence <job_id>",
                        "Tải archive: /evidence <job_id> archive",
                        "Xem help: /help"
                    ]
                )
            
            job_id = parts[1]
            
            if len(parts) > 2 and parts[2] == "archive":
                # Download archive
                archive_path = self.evidence_storage.create_evidence_archive(job_id)
                if archive_path:
                    return ChatResponse(
                        message=f"📦 **Evidence Archive Ready**

🆔 **Job ID:** `{job_id}`
📁 **Archive:** `{archive_path}`
📊 **Size:** {os.path.getsize(archive_path) if os.path.exists(archive_path) else 0} bytes

💡 **Archive contains:**
• All raw tool outputs
• Screenshots and HAR files
• Request/response data
• Evidence index

🔗 **Download:** Use API endpoint `/scan/evidence/{job_id}/archive`",
                        command=ChatCommand.EVIDENCE,
                        suggestions=[
                            f"Liệt kê files: /evidence {job_id}",
                            "Tạo báo cáo: /report " + job_id,
                            "Xem kết quả: /scan-results " + job_id
                        ]
                    )
                else:
                    return ChatResponse(
                        message=f"[ERROR] Không thể tạo archive cho Job ID: {job_id}",
                        command=ChatCommand.EVIDENCE,
                        suggestions=[
                            "Kiểm tra Job ID",
                            "Kiểm tra evidence files",
                            "Thử lại sau"
                        ]
                    )
            else:
                # List evidence files
                files = self.evidence_storage.list_evidence_files(job_id)
                
                if not files:
                    return ChatResponse(
                        message=f"[ERROR] Không tìm thấy evidence files cho Job ID: {job_id}",
                        command=ChatCommand.EVIDENCE,
                        suggestions=[
                            "Kiểm tra Job ID",
                            "Kiểm tra scan status",
                            "Bắt đầu scan mới: /scan <URL>"
                        ]
                    )
                
                # Categorize files
                raw_outputs = [f for f in files if f.endswith('.json')]
                screenshots = [f for f in files if f.endswith('.png')]
                har_files = [f for f in files if f.endswith('.har')]
                other_files = [f for f in files if not any(f.endswith(ext) for ext in ['.json', '.png', '.har'])]
                
                response_message = f"""📁 **Evidence Files**

🆔 **Job ID:** `{job_id}`
📊 **Total Files:** {len(files)}

🔧 **Raw Tool Outputs:** {len(raw_outputs)}
{chr(10).join([f"• {os.path.basename(f)}" for f in raw_outputs[:5]])}
{f"... and {len(raw_outputs) - 5} more" if len(raw_outputs) > 5 else ""}

📸 **Screenshots:** {len(screenshots)}
{chr(10).join([f"• {os.path.basename(f)}" for f in screenshots[:3]])}
{f"... and {len(screenshots) - 3} more" if len(screenshots) > 3 else ""}

🌐 **HAR Files:** {len(har_files)}
{chr(10).join([f"• {os.path.basename(f)}" for f in har_files[:3]])}
{f"... and {len(har_files) - 3} more" if len(har_files) > 3 else ""}

📄 **Other Files:** {len(other_files)}
{chr(10).join([f"• {os.path.basename(f)}" for f in other_files[:3]])}
{f"... and {len(other_files) - 3} more" if len(other_files) > 3 else ""}

💡 **Next Steps:**
• Tải archive: `/evidence {job_id} archive`
• Tải specific file: `/evidence {job_id} <filename>`
• Tạo báo cáo: `/report {job_id}`"""
                
                return ChatResponse(
                    message=response_message,
                    command=ChatCommand.EVIDENCE,
                    suggestions=[
                        f"Tải archive: /evidence {job_id} archive",
                        f"Tải file: /evidence {job_id} <filename>",
                        f"Tạo báo cáo: /report {job_id}"
                    ]
                )
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] Lỗi quản lý evidence: {str(e)}",
                command=ChatCommand.EVIDENCE,
                suggestions=[
                    "Kiểm tra Job ID",
                    "Thử lại sau",
                    "Sử dụng /help để xem hướng dẫn"
                ]
            )
    
    async def _handle_help_command(self) -> ChatResponse:
        """Xử lý lệnh /help"""
        help_message = """📚 **Enhanced Security Assistant - Hướng dẫn sử dụng**

## 🚀 **Lệnh Scan Chuyên Nghiệp**
• `/scan <URL>` - Bắt đầu enhanced scan với RAG intelligence
• `/scan-status <job_id>` - Kiểm tra trạng thái scan job
• `/scan-results <job_id>` - Xem kết quả scan chi tiết
• `/evidence <job_id>` - Quản lý evidence files
• `/scan-cancel <job_id>` - Hủy scan job đang chạy

## 🎯 **Lệnh Payload**
• `/payload <type> <URL>` - Tạo payload cho vulnerability type
  - Types: xss, sql_injection, misconfig, idor
  - Ví dụ: `/payload xss http://testphp.vulnweb.com`

## 📊 **Lệnh Báo cáo**
• `/report <job_id>` - Tạo báo cáo chuyên nghiệp
• `/recommend <vulnerability_type>` - Khuyến nghị khắc phục

## 🧠 **RAG Intelligence Features**
• 📚 OWASP Top 10 2023 knowledge
• 🎯 Advanced payload techniques  
• 🌍 Real-world vulnerability patterns
• 🔧 Best practice remediation
• 🗄️ CVE database integration
• 📋 Provenance tracking for all claims

## 🔄 **Enhanced Scan Pipeline**
1. **Reconnaissance** - HTTPX, WhatWeb analysis
2. **Crawling** - GoSpider intelligent crawling  
3. **Fuzzing** - FFUF directory discovery
4. **Vulnerability Detection** - Nuclei, Dalfox, Nikto
5. **Confirmatory Tests** - Marker reflection, evidence capture
6. **LLM + RAG Enrichment** - Provenance tracking
7. **Evidence Storage** - Screenshots, HAR, raw outputs

## 💡 **Ví dụ sử dụng**
1. **Scan chuyên nghiệp:**
   `/scan http://testphp.vulnweb.com`
   → Tạo job với ID, dùng `/scan-status <job_id>` để theo dõi

2. **Tạo payload:**
   `/payload xss http://testphp.vulnweb.com`
   → Tạo payload XSS phù hợp với target

3. **Quản lý evidence:**
   `/evidence job_12345678`
   → Liệt kê và tải evidence files

## 🛡️ **Bảo mật**
• Chỉ scan targets trong allowlist
• Tất cả tools chạy trong sandbox
• Không thực hiện destructive actions
• Timeout và resource limits
• Evidence storage với provenance tracking

**Sử dụng `/help` để xem lại hướng dẫn này!**"""
        
        return ChatResponse(
            message=help_message,
            command=ChatCommand.HELP,
            suggestions=[
                "Bắt đầu scan: /scan <URL>",
                "Tạo payload: /payload xss <URL>",
                "Xem evidence: /evidence <job_id>"
            ]
        )
    
    async def _handle_greeting_command(self) -> ChatResponse:
        """Xử lý lệnh chào hỏi"""
        greeting_message = """👋 **Chào mừng đến với Enhanced Security Assistant!**

🚀 **Tôi có thể giúp bạn:**
• 🔍 **Scan bảo mật** với RAG intelligence
• 🎯 **Tạo payload** cho các loại lỗ hổng
• 📊 **Tạo báo cáo** chuyên nghiệp
• 🛠️ **Khuyến nghị khắc phục** dựa trên RAG knowledge

🧠 **RAG Intelligence:**
• 📚 OWASP Top 10 2023 knowledge
• 🎯 Advanced payload techniques  
• 🌍 Real-world vulnerability patterns
• 🔧 Best practice remediation
• 📋 Provenance tracking for all claims

💡 **Bắt đầu ngay:**
• `/scan http://testphp.vulnweb.com` - Scan bảo mật
• `/payload xss http://example.com` - Tạo payload XSS
• `/help` - Xem hướng dẫn chi tiết

🎯 **Tính năng nổi bật:**
• Evidence-based analysis
• Confirmatory testing
• Screenshot capture
• HAR file recording
• Provenance tracking

**Hãy thử một lệnh để bắt đầu!**"""
        
        return ChatResponse(
            message=greeting_message,
            command=ChatCommand.GREETING,
            suggestions=[
                "Bắt đầu scan: /scan http://testphp.vulnweb.com",
                "Tạo payload: /payload xss <URL>",
                "Xem help: /help"
            ]
        )
    
    async def _handle_payload_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /payload"""
        # Implementation tương tự như trước
        return ChatResponse(
            message="Payload command - Implementation pending",
            command=ChatCommand.PAYLOAD,
            suggestions=["Xem help: /help"]
        )
    
    async def _handle_report_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /report"""
        # Implementation tương tự như trước
        return ChatResponse(
            message="Report command - Implementation pending",
            command=ChatCommand.REPORT,
            suggestions=["Xem help: /help"]
        )
    
    async def _handle_recommend_command(self, message: str) -> ChatResponse:
        """Xử lý lệnh /recommend"""
        # Implementation tương tự như trước
        return ChatResponse(
            message="Recommend command - Implementation pending",
            command=ChatCommand.RECOMMEND,
            suggestions=["Xem help: /help"]
        )
    
    async def _handle_natural_conversation(self, message: str) -> ChatResponse:
        """Xử lý conversation tự nhiên"""
        # Implementation tương tự như trước
        return ChatResponse(
            message="Natural conversation - Implementation pending",
            command=ChatCommand.UNKNOWN,
            suggestions=["Sử dụng /help để xem hướng dẫn"]
        )