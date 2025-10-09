#!/usr/bin/env python3
"""
Test RAG System với comprehensive scan
"""

import asyncio
import json
from app.core.enhanced_rag_retriever import EnhancedRAGRetriever
from app.core.scan_results_formatter import ScanResultsFormatter

async def test_rag_system():
    """Test RAG system với comprehensive scan"""
    print("=== Testing RAG System ===")
    
    # Test Enhanced RAG Retriever
    print("1. Testing Enhanced RAG Retriever...")
    try:
        rag_retriever = EnhancedRAGRetriever()
        print("✅ Enhanced RAG Retriever: Initialized")
        
        # Test retrieve method
        test_queries = [
            "XSS vulnerability detection",
            "OWASP Top 10 2023",
            "security headers HTTP protection",
            "SQL injection payloads"
        ]
        
        for query in test_queries:
            results = rag_retriever.retrieve(query, k=3)
            print(f"✅ Query '{query}': Got {len(results)} results")
            for i, result in enumerate(results):
                print(f"   Result {i+1}: {result.content[:100]}...")
        
    except Exception as e:
        print(f"❌ Enhanced RAG Retriever: Failed - {e}")
    
    # Test Scan Results Formatter
    print("\n2. Testing Scan Results Formatter...")
    try:
        formatter = ScanResultsFormatter()
        print("✅ Scan Results Formatter: Initialized")
        
        # Create mock scan data
        mock_scan_data = {
            "target_url": "http://testphp.vulnweb.com/",
            "http_response": {
                "status_code": 200,
                "elapsed": 1.23,
                "content": "Mock content for testing",
                "headers": {
                    "Content-Type": "text/html",
                    "Server": "Apache/2.4.41"
                },
                "url": "http://testphp.vulnweb.com/"
            },
            "headers_analysis": {
                "security_score": 45.0,
                "present": [
                    {
                        "header": "X-Frame-Options",
                        "value": "SAMEORIGIN",
                        "importance": "High",
                        "rag_insight": "Prevents clickjacking attacks"
                    }
                ],
                "missing": [
                    {
                        "header": "Content-Security-Policy",
                        "importance": "Critical",
                        "rag_insight": "Most effective defense against XSS"
                    }
                ],
                "recommendations": [
                    "CRITICAL: Implement Content-Security-Policy - Most effective defense against XSS",
                    "HIGH: Add Strict-Transport-Security - Essential for HTTPS enforcement"
                ]
            },
            "body_analysis": {
                "content": "Mock HTML content with potential vulnerabilities..."
            },
            "findings": [
                {
                    "type": "XSS",
                    "severity": "High",
                    "path": "/search.php",
                    "evidence": "Reflected XSS in search parameter",
                    "poc": "?q=<script>alert('XSS')</script>",
                    "remediation": "Implement input validation and output encoding"
                },
                {
                    "type": "SQL Injection",
                    "severity": "Critical",
                    "path": "/login.php",
                    "evidence": "SQL error in login parameter",
                    "poc": "admin' OR '1'='1'--",
                    "remediation": "Use prepared statements"
                }
            ],
            "rag_insights": [
                "RAG Insight: XSS - Advanced payload techniques detected",
                "RAG Best Practice: Implement CSP policy for protection",
                "OWASP Insight: A03:2021 - Injection vulnerabilities"
            ],
            "technology_stack": {
                "web_server": "Apache/2.4.41",
                "cms": ["WordPress"],
                "frameworks": ["PHP"],
                "languages": ["PHP", "JavaScript"]
            },
            "discovered_paths": [
                "/admin/",
                "/login.php",
                "/search.php",
                "/user.php"
            ],
            "security_score": 45.0
        }
        
        # Format results
        formatted_results = formatter.format_comprehensive_scan_result(mock_scan_data)
        print("✅ Scan Results Formatted Successfully")
        print(f"Formatted output length: {len(formatted_results)} characters")
        print("\n--- FORMATTED OUTPUT PREVIEW ---")
        print(formatted_results[:500] + "...")
        
    except Exception as e:
        print(f"❌ Scan Results Formatter: Failed - {e}")
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    asyncio.run(test_rag_system())
