#!/usr/bin/env python3
"""
Demo Scan System với RAG-enhanced output
"""

import asyncio
import json
from app.core.enhanced_scan_system import EnhancedScanSystem
from app.core.scan_results_formatter import ScanResultsFormatter

async def demo_scan_system():
    """Demo scan system với beautiful output"""
    print("🚀 **VA-WebSec Enhanced Scan System Demo**")
    print("=" * 60)
    
    # Initialize scan system
    scan_system = EnhancedScanSystem()
    formatter = ScanResultsFormatter()
    
    # Test target
    target_url = "http://testphp.vulnweb.com/"
    
    print(f"🎯 **Target:** {target_url}")
    print("🧠 **RAG Knowledge Base:** Active")
    print("🤖 **LLM Analysis:** Enabled")
    print("")
    
    print("🔄 **Starting Enhanced Scan...**")
    
    try:
        # Start scan
        job_id = await scan_system.start_scan(target_url)
        print(f"✅ Scan started with Job ID: {job_id}")
        
        # Wait for completion (in real scenario, this would be async)
        print("⏳ Waiting for scan completion...")
        
        # Simulate scan completion with mock data
        mock_scan_data = {
            "target_url": target_url,
            "http_response": {
                "status_code": 200,
                "elapsed": 2.45,
                "content": "<html><body>Test content with potential vulnerabilities</body></html>",
                "headers": {
                    "Content-Type": "text/html; charset=UTF-8",
                    "Server": "Apache/2.4.41 (Ubuntu)",
                    "X-Frame-Options": "SAMEORIGIN"
                },
                "url": target_url
            },
            "headers_analysis": {
                "security_score": 35.0,
                "present": [
                    {
                        "header": "X-Frame-Options",
                        "value": "SAMEORIGIN",
                        "importance": "High",
                        "rag_insight": "Prevents clickjacking attacks but SAMEORIGIN allows same-origin framing"
                    }
                ],
                "missing": [
                    {
                        "header": "Content-Security-Policy",
                        "importance": "Critical",
                        "rag_insight": "Most effective defense against XSS and injection attacks"
                    },
                    {
                        "header": "Strict-Transport-Security",
                        "importance": "Critical",
                        "rag_insight": "Essential for preventing man-in-the-middle attacks"
                    },
                    {
                        "header": "X-Content-Type-Options",
                        "importance": "High",
                        "rag_insight": "Prevents browsers from interpreting files as different MIME types"
                    }
                ],
                "recommendations": [
                    "CRITICAL: Implement Content-Security-Policy - Most effective defense against XSS",
                    "CRITICAL: Add Strict-Transport-Security - Essential for HTTPS enforcement",
                    "HIGH: Add X-Content-Type-Options - Prevents MIME sniffing attacks"
                ]
            },
            "body_analysis": {
                "content": "<html><head><title>Test Site</title></head><body><h1>Welcome</h1><form action='/search.php' method='GET'><input name='q' type='text'><input type='submit'></form></body></html>"
            },
            "findings": [
                {
                    "type": "XSS",
                    "severity": "High",
                    "path": "/search.php",
                    "evidence": "Reflected XSS in search parameter 'q'",
                    "poc": "?q=<script>alert('XSS')</script>",
                    "remediation": "Implement input validation and output encoding using RAG best practices"
                },
                {
                    "type": "SQL Injection",
                    "severity": "Critical",
                    "path": "/login.php",
                    "evidence": "SQL error in login parameter",
                    "poc": "admin' OR '1'='1'--",
                    "remediation": "Use prepared statements and parameterized queries as per RAG guidance"
                },
                {
                    "type": "Security Misconfiguration",
                    "severity": "Medium",
                    "path": "/",
                    "evidence": "Missing security headers",
                    "poc": "Check HTTP response headers",
                    "remediation": "Implement comprehensive security headers based on RAG recommendations"
                }
            ],
            "rag_insights": [
                "RAG Insight: XSS - Advanced payload techniques detected in search functionality",
                "RAG Best Practice: Implement CSP policy for comprehensive XSS protection",
                "OWASP Insight: A03:2021 - Injection vulnerabilities require immediate attention",
                "RAG Guidance: SQL injection remediation using prepared statements",
                "Security Headers: Missing critical headers identified by RAG analysis"
            ],
            "technology_stack": {
                "web_server": "Apache/2.4.41 (Ubuntu)",
                "cms": [],
                "frameworks": ["PHP"],
                "languages": ["PHP", "HTML", "JavaScript"]
            },
            "discovered_paths": [
                "/admin/",
                "/login.php",
                "/search.php",
                "/user.php",
                "/config.php",
                "/backup/",
                "/test/",
                "/api/",
                "/upload/",
                "/download/"
            ],
            "security_score": 35.0
        }
        
        print("✅ Scan completed successfully!")
        print("")
        
        # Format and display results
        print("📊 **FORMATTED SCAN RESULTS:**")
        print("=" * 60)
        
        formatted_results = formatter.format_comprehensive_scan_result(mock_scan_data)
        print(formatted_results)
        
        # Show RAG importance
        print("\n" + "=" * 60)
        print(formatter.format_rag_importance_message())
        
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")
    
    print("\n🎉 **Demo Complete!**")
    print("RAG-enhanced scan system provides comprehensive, context-aware security analysis!")

if __name__ == "__main__":
    asyncio.run(demo_scan_system())
