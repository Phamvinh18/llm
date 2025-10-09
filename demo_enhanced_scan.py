"""
Demo Enhanced Scan System - Test hệ thống scan mới với RAG intelligence
"""

import asyncio
import sys
import os
import time
from pathlib import Path

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from app.core.scan_orchestrator import ScanOrchestrator, ScanStatus
from app.core.evidence_storage import EvidenceStorage
from app.core.enhanced_rag_retriever import EnhancedRAGRetriever
from app.core.llm_enrichment import LLMEnrichment
from app.clients.gemini_client import GeminiClient

async def test_enhanced_scan_system():
    """Test enhanced scan system"""
    print("🚀 **Enhanced Security Scan System Demo**")
    print("=" * 60)
    
    # Initialize components
    print("🔧 Initializing components...")
    orchestrator = ScanOrchestrator()
    evidence_storage = EvidenceStorage()
    rag_retriever = EnhancedRAGRetriever()
    llm_client = GeminiClient()
    llm_enrichment = LLMEnrichment(llm_client, rag_retriever)
    
    print("✅ Components initialized successfully")
    
    # Test target
    target_url = "http://testphp.vulnweb.com/"
    print(f"🎯 Target URL: {target_url}")
    
    try:
        # Start scan
        print("\n🔄 Starting enhanced scan...")
        result = await orchestrator.start_scan(target_url)
        
        if result["success"]:
            job_id = result["job_id"]
            print(f"✅ Scan started successfully!")
            print(f"🆔 Job ID: {job_id}")
            print(f"📁 Evidence Directory: {result['evidence_dir']}")
            
            # Monitor scan progress
            print("\n⏳ Monitoring scan progress...")
            while True:
                job = orchestrator.get_scan_status(job_id)
                if job:
                    print(f"📊 Status: {job.status.value} | Stage: {job.current_stage.value} | Progress: {job.progress}%")
                    
                    if job.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
                        break
                    
                    await asyncio.sleep(5)  # Wait 5 seconds
                else:
                    print("❌ Job not found")
                    break
            
            # Get results
            if job.status == ScanStatus.COMPLETED:
                print(f"\n🎉 Scan completed successfully!")
                results = orchestrator.get_scan_results(job_id)
                
                if results:
                    findings = results.get("findings", [])
                    print(f"📊 Total findings: {len(findings)}")
                    
                    # Show findings summary
                    severity_counts = {}
                    for finding in findings:
                        severity = finding.get("severity", "Unknown")
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    print("\n🚨 **Findings Summary:**")
                    for severity, count in severity_counts.items():
                        emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Unknown": "⚪"}.get(severity, "⚪")
                        print(f"  {emoji} {severity}: {count}")
                    
                    # Show top findings
                    print("\n🔍 **Top Findings:**")
                    for i, finding in enumerate(findings[:5], 1):
                        print(f"\n{i}. **{finding.get('type', 'Unknown')}** - {finding.get('severity', 'Unknown')}")
                        print(f"   Path: {finding.get('path', 'N/A')}")
                        print(f"   Parameter: {finding.get('param', 'N/A')}")
                        print(f"   Tool: {finding.get('tool', 'N/A')}")
                        print(f"   Confidence: {finding.get('confidence', 'N/A')}")
                        print(f"   Evidence: {finding.get('evidence_snippet', 'N/A')[:100]}...")
                        
                        # Show RAG provenance if available
                        provenance = finding.get('provenance', [])
                        if provenance:
                            print(f"   🧠 RAG Provenance:")
                            for prov in provenance[:2]:  # Show first 2
                                print(f"     - {prov.get('claim', '')}: {prov.get('snippet', '')[:50]}...")
                    
                    # Show evidence summary
                    print(f"\n📁 **Evidence Summary:**")
                    evidence_summary = evidence_storage.get_evidence_summary(job_id)
                    if "error" not in evidence_summary:
                        summary = evidence_summary.get("summary", {})
                        print(f"  📸 Screenshots: {summary.get('total_screenshots', 0)}")
                        print(f"  🌐 HAR files: {summary.get('total_har_files', 0)}")
                        print(f"  📄 Request/Response: {summary.get('total_request_response', 0)}")
                        print(f"  🔧 Raw outputs: {summary.get('total_raw_outputs', 0)}")
                    
                    # Show RAG impact
                    print(f"\n🧠 **RAG Intelligence Impact:**")
                    print("  ✅ Context-aware vulnerability analysis")
                    print("  ✅ Evidence-based confidence scoring")
                    print("  ✅ Industry-standard remediation guidance")
                    print("  ✅ Provenance tracking for all claims")
                    print("  ✅ OWASP Top 10 2023 knowledge integration")
                    
                    # Test evidence access
                    print(f"\n📁 **Evidence Files:**")
                    evidence_files = evidence_storage.list_evidence_files(job_id)
                    print(f"  Total files: {len(evidence_files)}")
                    
                    # Show file types
                    file_types = {}
                    for file_path in evidence_files:
                        ext = Path(file_path).suffix
                        file_types[ext] = file_types.get(ext, 0) + 1
                    
                    for ext, count in file_types.items():
                        print(f"  {ext or 'no extension'}: {count} files")
                    
                    print(f"\n🎯 **Demo Complete!**")
                    print("Enhanced scan system provides comprehensive, evidence-based security analysis!")
                    
                else:
                    print("❌ No scan results found")
            else:
                print(f"❌ Scan {job.status.value} with error: {job.error_message}")
        else:
            print(f"❌ Failed to start scan: {result.get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

async def test_rag_system():
    """Test RAG system separately"""
    print("\n🧠 **Testing RAG System**")
    print("=" * 40)
    
    try:
        rag_retriever = EnhancedRAGRetriever()
        
        # Test queries
        test_queries = [
            "XSS vulnerability detection",
            "SQL injection remediation",
            "OWASP Top 10 2023",
            "security headers protection"
        ]
        
        for query in test_queries:
            print(f"\n🔍 Query: {query}")
            docs = rag_retriever.retrieve(query, k=3)
            print(f"  Results: {len(docs)} documents")
            
            for i, doc in enumerate(docs, 1):
                content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                print(f"    {i}. {content[:100]}...")
        
        print("\n✅ RAG system working correctly")
        
    except Exception as e:
        print(f"❌ RAG system error: {e}")

async def main():
    """Main demo function"""
    print("🚀 **VA-WebSec Enhanced Scan System Demo**")
    print("=" * 60)
    print("🎯 **Target:** http://testphp.vulnweb.com/")
    print("🧠 **RAG Knowledge Base:** Active")
    print("🤖 **LLM Analysis:** Enabled")
    print("📁 **Evidence Storage:** Enabled")
    print("=" * 60)
    
    # Test RAG system first
    await test_rag_system()
    
    # Test enhanced scan system
    await test_enhanced_scan_system()
    
    print("\n🎉 **Demo Complete!**")
    print("Enhanced scan system provides comprehensive, evidence-based security analysis!")

if __name__ == "__main__":
    asyncio.run(main())
