"""
Scan Results Formatter - Tạo output đẹp và chi tiết cho scan results
"""

import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

@dataclass
class ScanResult:
    """Structured scan result"""
    target_url: str
    status_code: int
    response_time: float
    content_length: int
    headers: Dict[str, str]
    body_preview: str
    vulnerabilities: List[Dict[str, Any]]
    security_score: float
    rag_insights: List[str]
    technology_stack: Dict[str, Any]
    discovered_paths: List[str]

class ScanResultsFormatter:
    """Formatter for beautiful scan results"""
    
    def __init__(self):
        self.emoji_map = {
            'success': '✅',
            'error': '❌',
            'warning': '⚠️',
            'info': 'ℹ️',
            'critical': '🚨',
            'high': '🔴',
            'medium': '🟡',
            'low': '🟢',
            'xss': '💉',
            'sql': '🗄️',
            'idor': '🔓',
            'misconfig': '⚙️',
            'headers': '📋',
            'body': '📄',
            'rag': '🧠',
            'llm': '🤖',
            'scan': '🔍',
            'target': '🎯',
            'time': '⏱️',
            'size': '📏'
        }
    
    def format_comprehensive_scan_result(self, scan_data: Dict[str, Any]) -> str:
        """Format comprehensive scan result with RAG insights"""
        try:
            # Extract data
            target_url = scan_data.get('target_url', 'Unknown')
            http_response = scan_data.get('http_response', {})
            headers_analysis = scan_data.get('headers_analysis', {})
            body_analysis = scan_data.get('body_analysis', {})
            findings = scan_data.get('findings', [])
            rag_insights = scan_data.get('rag_insights', [])
            technology_stack = scan_data.get('technology_stack', {})
            discovered_paths = scan_data.get('discovered_paths', [])
            security_score = scan_data.get('security_score', 0)
            
            # Build formatted output
            output = []
            
            # Header
            output.append("🚀 **COMPREHENSIVE SECURITY SCAN REPORT**")
            output.append("=" * 60)
            output.append("")
            
            # Target Information
            output.append("🎯 **TARGET INFORMATION**")
            output.append(f"URL: `{target_url}`")
            output.append(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            output.append(f"Security Score: {self._get_security_score_emoji(security_score)} {security_score}/100")
            output.append("")
            
            # HTTP Response Analysis
            output.append("📡 **HTTP RESPONSE ANALYSIS**")
            output.append(f"{self.emoji_map['time']} Status Code: `{http_response.get('status_code', 'N/A')}`")
            output.append(f"{self.emoji_map['time']} Response Time: `{http_response.get('elapsed', 0):.2f}s`")
            output.append(f"{self.emoji_map['size']} Content Length: `{len(http_response.get('content', ''))} bytes`")
            output.append(f"Content Type: `{http_response.get('headers', {}).get('Content-Type', 'N/A')}`")
            output.append(f"Final URL: `{http_response.get('url', 'N/A')}`")
            output.append("")
            
            # Security Headers Analysis
            output.append("🛡️ **SECURITY HEADERS ANALYSIS**")
            headers_score = headers_analysis.get('security_score', 0)
            output.append(f"Headers Score: {self._get_security_score_emoji(headers_score)} {headers_score}/100")
            
            # Present headers
            present_headers = headers_analysis.get('present', [])
            if present_headers:
                output.append("✅ **Present Headers:**")
                for header in present_headers:
                    header_name = header.get('header', 'Unknown')
                    header_value = header.get('value', '')
                    importance = header.get('importance', 'Medium')
                    rag_insight = header.get('rag_insight', '')
                    output.append(f"  • `{header_name}`: {header_value}")
                    output.append(f"    Importance: {importance} | RAG Insight: {rag_insight}")
            
            # Missing headers
            missing_headers = headers_analysis.get('missing', [])
            if missing_headers:
                output.append("❌ **Missing Headers:**")
                for header in missing_headers:
                    header_name = header.get('header', 'Unknown')
                    importance = header.get('importance', 'Medium')
                    rag_insight = header.get('rag_insight', '')
                    output.append(f"  • `{header_name}` - {importance} Priority")
                    output.append(f"    RAG Insight: {rag_insight}")
            
            output.append("")
            
            # Technology Stack
            output.append("🔧 **TECHNOLOGY STACK**")
            web_server = technology_stack.get('web_server', 'Unknown')
            cms = technology_stack.get('cms', [])
            frameworks = technology_stack.get('frameworks', [])
            languages = technology_stack.get('languages', [])
            
            output.append(f"Web Server: `{web_server}`")
            output.append(f"CMS: `{', '.join(cms) if cms else 'None detected'}`")
            output.append(f"Frameworks: `{', '.join(frameworks) if frameworks else 'None detected'}`")
            output.append(f"Languages: `{', '.join(languages) if languages else 'None detected'}`")
            output.append("")
            
            # Discovered Paths
            output.append("📁 **DISCOVERED PATHS**")
            output.append(f"Total Paths: `{len(discovered_paths)}`")
            if discovered_paths:
                output.append("Top 10 Paths:")
                for i, path in enumerate(discovered_paths[:10], 1):
                    output.append(f"  {i}. `{path}`")
            output.append("")
            
            # Vulnerabilities
            output.append("🚨 **VULNERABILITY ANALYSIS**")
            output.append(f"Total Findings: `{len(findings)}`")
            
            if findings:
                # Group by severity
                critical_findings = [f for f in findings if f.get('severity', '').lower() == 'critical']
                high_findings = [f for f in findings if f.get('severity', '').lower() == 'high']
                medium_findings = [f for f in findings if f.get('severity', '').lower() == 'medium']
                low_findings = [f for f in findings if f.get('severity', '').lower() == 'low']
                
                if critical_findings:
                    output.append(f"🚨 **CRITICAL ({len(critical_findings)})**")
                    for finding in critical_findings:
                        self._format_finding(output, finding)
                
                if high_findings:
                    output.append(f"🔴 **HIGH ({len(high_findings)})**")
                    for finding in high_findings:
                        self._format_finding(output, finding)
                
                if medium_findings:
                    output.append(f"🟡 **MEDIUM ({len(medium_findings)})**")
                    for finding in medium_findings:
                        self._format_finding(output, finding)
                
                if low_findings:
                    output.append(f"🟢 **LOW ({len(low_findings)})**")
                    for finding in low_findings:
                        self._format_finding(output, finding)
            else:
                output.append("✅ No vulnerabilities detected")
            
            output.append("")
            
            # RAG Insights
            output.append("🧠 **RAG INTELLIGENCE INSIGHTS**")
            if rag_insights:
                output.append(f"RAG Knowledge Base provided {len(rag_insights)} insights:")
                for i, insight in enumerate(rag_insights[:10], 1):
                    output.append(f"  {i}. {insight}")
            else:
                output.append("⚠️ No RAG insights available")
            
            output.append("")
            
            # Body Analysis
            output.append("📄 **BODY CONTENT ANALYSIS**")
            body_content = body_analysis.get('content', '')
            if body_content:
                output.append(f"Content Length: `{len(body_content)} characters`")
                output.append("Content Preview:")
                output.append("```")
                output.append(body_content[:500] + "..." if len(body_content) > 500 else body_content)
                output.append("```")
            else:
                output.append("No body content available")
            
            output.append("")
            
            # Recommendations
            output.append("💡 **RAG-ENHANCED RECOMMENDATIONS**")
            recommendations = headers_analysis.get('recommendations', [])
            if recommendations:
                for i, rec in enumerate(recommendations[:5], 1):
                    output.append(f"  {i}. {rec}")
            else:
                output.append("  • Implement comprehensive security headers")
                output.append("  • Regular security testing with RAG guidance")
                output.append("  • Follow OWASP Top 10 2023 best practices")
            
            output.append("")
            output.append("=" * 60)
            output.append("🎯 **RAG IMPACT**: This analysis was enhanced by RAG knowledge base")
            output.append("   providing context-aware vulnerability detection and remediation guidance.")
            
            return "\n".join(output)
            
        except Exception as e:
            return f"❌ Error formatting scan results: {str(e)}"
    
    def _format_finding(self, output: List[str], finding: Dict[str, Any]):
        """Format individual vulnerability finding"""
        vuln_type = finding.get('type', 'Unknown')
        severity = finding.get('severity', 'Unknown')
        path = finding.get('path', 'Unknown')
        evidence = finding.get('evidence', 'No evidence')
        poc = finding.get('poc', 'No PoC available')
        remediation = finding.get('remediation', 'No remediation available')
        
        # Get emoji for vulnerability type
        vuln_emoji = self.emoji_map.get(vuln_type.lower().replace(' ', '_'), '🔍')
        
        output.append(f"  {vuln_emoji} **{vuln_type.upper()}** - {severity}")
        output.append(f"    Path: `{path}`")
        output.append(f"    Evidence: `{evidence}`")
        output.append(f"    PoC: `{poc}`")
        output.append(f"    Remediation: {remediation}")
        output.append("")
    
    def _get_security_score_emoji(self, score: float) -> str:
        """Get emoji based on security score"""
        if score >= 80:
            return "🟢"
        elif score >= 60:
            return "🟡"
        elif score >= 40:
            return "🟠"
        else:
            return "🔴"
    
    def format_rag_importance_message(self) -> str:
        """Format message showing RAG importance"""
        return """
🧠 **RAG KNOWLEDGE BASE IMPACT**

The analysis above was powered by our RAG (Retrieval-Augmented Generation) system:

✅ **Context-Aware Analysis**: RAG provides specific knowledge for each vulnerability type
✅ **OWASP Top 10 2023**: Latest security standards and best practices
✅ **Real-World Patterns**: Based on actual attack scenarios and defenses
✅ **Intelligent Remediation**: Context-specific fix recommendations
✅ **Advanced Detection**: Enhanced payload techniques and evasion methods

**Without RAG**: Generic, potentially inaccurate analysis
**With RAG**: Precise, context-aware, industry-standard security assessment

🎯 **This is why RAG is crucial for modern security analysis!**
        """
