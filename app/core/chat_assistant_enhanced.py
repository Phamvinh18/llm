"""
Enhanced Chat Assistant - Advanced AI-powered security assistant with immediate scanning
"""

import os
import time
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

from app.core.chat_assistant_rag import ChatAssistantRAG, ChatCommand, ChatResponse, VulnerabilityType
from app.core.enhanced_scan_engine import EnhancedScanEngine, ScanProfile, ScanResult
from app.core.enhanced_rag_retriever import EnhancedRAGRetriever
from app.clients.gemini_client import GeminiClient

class EnhancedChatAssistant(ChatAssistantRAG):
    def __init__(self):
        super().__init__()
        self.scan_engine = EnhancedScanEngine()
        self.rag_retriever = EnhancedRAGRetriever()
        self.llm_client = GeminiClient()
    
    async def _handle_scan_command(self, message: str) -> ChatResponse:
        """Handle /scan command with immediate execution"""
        try:
            # Parse scan command
            parts = message.strip().split()
            if len(parts) < 2:
                return ChatResponse(
                    message="[ERROR] **Lỗi:** Vui lòng cung cấp URL để scan.\n\n**Cú pháp:** `/scan <URL>`\n**Ví dụ:** `/scan http://testphp.vulnweb.com`",
                    command=ChatCommand.SCAN,
                    vulnerability_type=None,
                    target_url=None,
                    payloads=[],
                    scan_results=None,
                    llm_analysis=None,
                    suggestions=[]
                )
            
            target_url = parts[1]
            
            # Validate URL
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'http://' + target_url
            
            # Check whitelist
            if not self._is_url_allowed(target_url):
                return ChatResponse(
                    message=f"[ERROR] **Lỗi:** URL `{target_url}` không được phép scan.\n\nVui lòng kiểm tra whitelist hoặc liên hệ admin.",
                    command=ChatCommand.SCAN,
                    vulnerability_type=None,
                    target_url=target_url,
                    payloads=[],
                    scan_results=None,
                    llm_analysis=None,
                    suggestions=[]
                )
            
            # Start immediate scan
            return await self._perform_immediate_scan(target_url)
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] **Lỗi khi thực hiện scan:** {str(e)}",
                command=ChatCommand.SCAN,
                vulnerability_type=None,
                target_url=None,
                payloads=[],
                scan_results=None,
                llm_analysis=None,
                suggestions=[]
            )
    
    async def _perform_immediate_scan(self, target_url: str) -> ChatResponse:
        """Perform immediate comprehensive scan"""
        try:
            # Start scan with FAST profile for immediate results
            scan_result = self.scan_engine.start_scan(target_url, ScanProfile.FAST)
            
            # Perform LLM analysis
            llm_analysis = await self._analyze_scan_results_with_llm(scan_result)
            
            # Format response message
            response_message = self._format_scan_response(scan_result, llm_analysis)
            
            return ChatResponse(
                message=response_message,
                command=ChatCommand.SCAN,
                vulnerability_type=None,
                target_url=target_url,
                payloads=[],
                scan_results=self._convert_scan_result_to_dict(scan_result),
                llm_analysis=llm_analysis,
                suggestions=self._generate_scan_suggestions(scan_result)
            )
            
        except Exception as e:
            return ChatResponse(
                message=f"[ERROR] **Lỗi khi thực hiện scan:** {str(e)}",
                command=ChatCommand.SCAN,
                vulnerability_type=None,
                target_url=target_url,
                payloads=[],
                scan_results=None,
                llm_analysis=None,
                suggestions=[]
            )
    
    async def _analyze_scan_results_with_llm(self, scan_result: ScanResult) -> str:
        """Analyze scan results using LLM with RAG context"""
        try:
            # Convert scan result to dict for RAG analysis
            scan_dict = self._convert_scan_result_to_dict(scan_result)
            
            # Generate enhanced analysis prompt
            analysis_prompt = self.rag_retriever.get_enhanced_analysis_prompt(scan_dict)
            
            # Get LLM analysis
            llm_response = await self.llm_client.chat(analysis_prompt)
            
            return llm_response if llm_response else "Không thể phân tích kết quả scan."
            
        except Exception as e:
            return f"Lỗi khi phân tích kết quả: {str(e)}"
    
    def _convert_scan_result_to_dict(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult to dictionary"""
        return {
            "target_url": scan_result.target_url,
            "profile": scan_result.profile,
            "start_time": scan_result.start_time,
            "end_time": scan_result.end_time,
            "findings": [
                {
                    "type": f.type,
                    "severity": f.severity,
                    "path": f.path,
                    "parameter": f.parameter,
                    "evidence": f.evidence,
                    "description": f.description,
                    "cwe": f.cwe,
                    "confidence": f.confidence
                }
                for f in scan_result.findings
            ],
            "http_response": scan_result.http_response,
            "headers_analysis": scan_result.headers_analysis,
            "body_analysis": scan_result.body_analysis,
            "technology_stack": scan_result.technology_stack,
            "discovered_paths": scan_result.discovered_paths,
            "security_score": scan_result.security_score
        }
    
    def _format_scan_response(self, scan_result: ScanResult, llm_analysis: str) -> str:
        """Format comprehensive scan response"""
        response_parts = []
        
        # Header
        response_parts.append("🎉 **Enhanced Scan Completed Successfully!**")
        response_parts.append("")
        
        # Summary
        response_parts.append("[SCAN] **TÓM TẮT SCAN:**")
        response_parts.append(f"[TARGET] **Target:** {scan_result.target_url}")
        response_parts.append(f"[TIME] **Thời gian:** {scan_result.end_time - scan_result.start_time:.2f}s")
        response_parts.append(f"[SECURITY] **Security Score:** {scan_result.security_score:.1f}/100")
        response_parts.append(f"[VULN] **Vulnerabilities:** {len(scan_result.findings)}")
        response_parts.append("")
        
        # HTTP Response Analysis
        if scan_result.http_response.get("success"):
            http_resp = scan_result.http_response
            response_parts.append("[HTTP] **HTTP RESPONSE ANALYSIS:**")
            response_parts.append(f"• **Status Code:** {http_resp.get('status_code', 'N/A')}")
            response_parts.append(f"• **Response Size:** {len(http_resp.get('content', ''))} bytes")
            response_parts.append(f"• **Response Time:** {http_resp.get('elapsed', 0):.2f}s")
            response_parts.append(f"• **Content Type:** {http_resp.get('headers', {}).get('Content-Type', 'N/A')}")
            response_parts.append(f"• **Final URL:** {http_resp.get('url', 'N/A')}")
            response_parts.append("")
        
        # Security Headers Analysis
        if scan_result.headers_analysis:
            headers_analysis = scan_result.headers_analysis
            response_parts.append("[SECURITY] **SECURITY HEADERS ANALYSIS:**")
            response_parts.append(f"• **Security Score:** {headers_analysis.get('security_score', 0):.1f}/100")
            
            security_headers = headers_analysis.get('security_headers', {})
            present_headers = [name for name, info in security_headers.items() if info.get('present', False)]
            missing_headers = [name for name, info in security_headers.items() if not info.get('present', False)]
            
            if present_headers:
                response_parts.append(f"• **Headers có sẵn:** {', '.join(present_headers)}")
            if missing_headers:
                response_parts.append(f"• **Headers thiếu:** {', '.join(missing_headers)}")
            
            response_parts.append("")
        
        # Technology Stack
        if scan_result.technology_stack:
            tech_stack = scan_result.technology_stack
            response_parts.append("[TOOL] **TECHNOLOGY STACK:**")
            response_parts.append(f"• **Web Server:** {tech_stack.get('web_server', 'Unknown')}")
            if tech_stack.get('cms'):
                response_parts.append(f"• **CMS:** {', '.join(tech_stack['cms'])}")
            if tech_stack.get('frameworks'):
                response_parts.append(f"• **Frameworks:** {', '.join(tech_stack['frameworks'])}")
            if tech_stack.get('languages'):
                response_parts.append(f"• **Languages:** {', '.join(tech_stack['languages'])}")
            response_parts.append("")
        
        # Discovered Paths
        if scan_result.discovered_paths:
            response_parts.append("[FOLDER] **DISCOVERED PATHS:**")
            response_parts.append(f"• **Tổng số:** {len(scan_result.discovered_paths)}")
            
            # Group by status code
            status_groups = {}
            for path in scan_result.discovered_paths:
                status = path.get('status_code', 'Unknown')
                if status not in status_groups:
                    status_groups[status] = []
                status_groups[status].append(path['path'])
            
            for status, paths in status_groups.items():
                response_parts.append(f"• **Status {status}:** {', '.join(paths[:5])}{'...' if len(paths) > 5 else ''}")
            response_parts.append("")
        
        # Vulnerabilities
        if scan_result.findings:
            response_parts.append("[ALERT] **VULNERABILITIES FOUND:**")
            
            # Group by severity
            severity_groups = {}
            for finding in scan_result.findings:
                severity = finding.severity
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(finding)
            
            for severity in ['High', 'Medium', 'Low']:
                if severity in severity_groups:
                    findings = severity_groups[severity]
                    emoji = "🔴" if severity == "High" else "🟡" if severity == "Medium" else "🟢"
                    response_parts.append(f"{emoji} **{severity} ({len(findings)}):**")
                    
                    for finding in findings[:3]:  # Show first 3 of each severity
                        response_parts.append(f"  • **{finding.type}** - {finding.description}")
                        if finding.evidence:
                            response_parts.append(f"    Evidence: `{finding.evidence[:100]}{'...' if len(finding.evidence) > 100 else ''}`")
                    
                    if len(findings) > 3:
                        response_parts.append(f"  • ... và {len(findings) - 3} lỗ hổng khác")
                    response_parts.append("")
        else:
            response_parts.append("[OK] **Không phát hiện lỗ hổng bảo mật nghiêm trọng**")
            response_parts.append("")
        
        # LLM Analysis
        if llm_analysis:
            response_parts.append("🤖 **PHÂN TÍCH BẢO MẬT BẰNG AI:**")
            response_parts.append(llm_analysis)
            response_parts.append("")
        
        # Recommendations
        recommendations = self._generate_scan_suggestions(scan_result)
        if recommendations:
            response_parts.append("💡 **KHUYẾN NGHỊ:**")
            for i, rec in enumerate(recommendations[:5], 1):
                response_parts.append(f"{i}. {rec}")
            response_parts.append("")
        
        return "\n".join(response_parts)
    
    def _generate_scan_suggestions(self, scan_result: ScanResult) -> List[str]:
        """Generate actionable suggestions based on scan results"""
        suggestions = []
        
        # Security headers suggestions
        headers_analysis = scan_result.headers_analysis
        if headers_analysis and headers_analysis.get('security_score', 0) < 50:
            suggestions.append("Cấu hình security headers (CSP, HSTS, X-Frame-Options)")
        
        # Vulnerability suggestions
        if scan_result.findings:
            high_severity = [f for f in scan_result.findings if f.severity == "High"]
            if high_severity:
                suggestions.append("Ưu tiên sửa các lỗ hổng High severity")
            
            xss_findings = [f for f in scan_result.findings if f.type == "XSS"]
            if xss_findings:
                suggestions.append("Implement input validation và output encoding cho XSS")
            
            sql_findings = [f for f in scan_result.findings if f.type == "SQL Injection"]
            if sql_findings:
                suggestions.append("Sử dụng prepared statements cho SQL injection")
        
        # Technology suggestions
        tech_stack = scan_result.technology_stack
        if tech_stack.get('web_server') == 'Unknown':
            suggestions.append("Cấu hình web server để ẩn version information")
        
        # Path discovery suggestions
        if scan_result.discovered_paths:
            sensitive_paths = [p for p in scan_result.discovered_paths if any(sensitive in p['path'].lower() for sensitive in ['admin', 'config', 'backup', '.git'])]
            if sensitive_paths:
                suggestions.append("Bảo vệ các paths nhạy cảm và loại bỏ backup files")
        
        # General suggestions
        if scan_result.security_score < 70:
            suggestions.append("Thực hiện security audit định kỳ")
            suggestions.append("Cập nhật dependencies và frameworks")
        
        return suggestions[:5]  # Return top 5 suggestions
    
    def _is_url_allowed(self, url: str) -> bool:
        """Check if URL is in whitelist"""
        try:
            whitelist_file = os.path.join(self.data_dir, 'whitelist.json')
            if os.path.exists(whitelist_file):
                with open(whitelist_file, 'r', encoding='utf-8') as f:
                    whitelist = json.load(f)
                    return url in whitelist
            return True  # Allow all if no whitelist
        except Exception:
            return True  # Allow all if error reading whitelist
