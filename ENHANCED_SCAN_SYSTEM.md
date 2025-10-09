# 🚀 Enhanced Security Scan System với RAG Intelligence

## 📋 Tổng quan

Hệ thống Enhanced Security Scan là một giải pháp toàn diện cho việc quét bảo mật web với tích hợp RAG (Retrieval-Augmented Generation) và LLM để cung cấp phân tích thông minh, evidence-based và provenance tracking.

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────────┐
│                    Enhanced Scan System                     │
├─────────────────────────────────────────────────────────────┤
│  🎯 Scan Orchestrator  │  📁 Evidence Storage  │  🧠 RAG    │
│  • Job Management      │  • Raw Outputs        │  • OWASP   │
│  • Tool Pipeline       │  • Screenshots        │  • CVE     │
│  • Progress Tracking   │  • HAR Files          │  • Payloads│
├─────────────────────────────────────────────────────────────┤
│  🔧 Tool Parsers       │  🤖 LLM Enrichment    │  📊 API    │
│  • Nuclei              │  • Provenance Track   │  • REST    │
│  • Dalfox              │  • Evidence Analysis  │  • WebSocket│
│  • Nikto               │  • Confidence Score   │  • Real-time│
│  • FFUF                │  • Safe PoC Gen       │            │
└─────────────────────────────────────────────────────────────┘
```

## 🔄 Scan Pipeline

### 1. **Reconnaissance** 🔍
- **HTTPX**: HTTP analysis và fingerprinting
- **WhatWeb**: Technology detection
- **Output**: JSON với server info, technologies

### 2. **Crawling** 🕷️
- **GoSpider**: Intelligent web crawling
- **Output**: Discovered URLs, forms, parameters

### 3. **Fuzzing** 🎯
- **FFUF**: Directory và parameter fuzzing
- **Output**: Hidden paths, parameters

### 4. **Vulnerability Detection** 🛡️
- **Nuclei**: Template-based scanning
- **Dalfox**: XSS detection
- **Nikto**: Web server vulnerabilities
- **Output**: Raw findings với evidence

### 5. **Confirmatory Tests** ✅
- **Marker Reflection**: Test payload reflection
- **Screenshot Capture**: Visual evidence
- **HAR Recording**: Network traffic
- **Output**: Confirmed findings

### 6. **RAG Enrichment** 🧠
- **Knowledge Retrieval**: OWASP, CVE, payloads
- **LLM Analysis**: Severity, confidence, remediation
- **Provenance Tracking**: Source attribution
- **Output**: Enriched findings

### 7. **Evidence Storage** 📁
- **Raw Outputs**: Tool JSON files
- **Screenshots**: PNG images
- **HAR Files**: Network traffic
- **Request/Response**: HTTP data
- **Output**: Complete evidence package

## 🧠 RAG Intelligence Features

### **Knowledge Base**
- **OWASP Top 10 2023**: Latest security standards
- **CVE Database**: Vulnerability information
- **Payload Collections**: Attack techniques
- **Remediation Guides**: Fix recommendations
- **Best Practices**: Industry standards

### **Provenance Tracking**
- **Source Attribution**: Every claim có nguồn gốc
- **Evidence Linking**: Findings linked to evidence
- **Confidence Scoring**: Evidence-based confidence
- **Reference Tracking**: RAG document sources

## 📊 API Endpoints

### **Scan Management**
```bash
POST /scan/start
GET  /scan/status/{job_id}
GET  /scan/results/{job_id}
POST /scan/cancel/{job_id}
```

### **Evidence Management**
```bash
GET  /scan/evidence/{job_id}
GET  /scan/evidence/{job_id}/{filename}
GET  /scan/evidence/{job_id}/archive
```

### **Report Generation**
```bash
GET  /scan/report/{job_id}?format=json
GET  /scan/report/{job_id}?format=html
POST /scan/enrich/{job_id}
```

## 🔧 Tool Integration

### **Nuclei Parser**
```python
# Parse nuclei output
parser = NucleiParser()
findings = parser.parse(content, target_url, output_file)
```

### **Dalfox Parser**
```python
# Parse dalfox output
parser = DalfoxParser()
findings = parser.parse(content, target_url, output_file)
```

### **Evidence Storage**
```python
# Save evidence
storage = EvidenceStorage()
screenshot = await storage.capture_screenshot(url, job_id, finding_id)
har_file = await storage.capture_har(url, job_id, finding_id)
```

## 🎯 Usage Examples

### **1. Start Scan**
```python
from app.core.scan_orchestrator import ScanOrchestrator

orchestrator = ScanOrchestrator()
result = await orchestrator.start_scan("http://testphp.vulnweb.com/")

if result["success"]:
    job_id = result["job_id"]
    print(f"Scan started: {job_id}")
```

### **2. Monitor Progress**
```python
job = orchestrator.get_scan_status(job_id)
print(f"Status: {job.status.value}")
print(f"Progress: {job.progress}%")
print(f"Stage: {job.current_stage.value}")
```

### **3. Get Results**
```python
results = orchestrator.get_scan_results(job_id)
findings = results["findings"]

for finding in findings:
    print(f"Type: {finding['type']}")
    print(f"Severity: {finding['severity']}")
    print(f"Confidence: {finding['confidence']}")
    print(f"Evidence: {finding['evidence_snippet']}")
```

### **4. Access Evidence**
```python
from app.core.evidence_storage import EvidenceStorage

storage = EvidenceStorage()
files = storage.list_evidence_files(job_id)
archive = storage.create_evidence_archive(job_id)
```

## 📋 Finding Schema

```json
{
  "id": "f-001",
  "job_id": "job_b36a1b48",
  "target": "http://testphp.vulnweb.com",
  "type": "XSS-Reflected",
  "path": "/search.php",
  "param": "searchFor",
  "tool": "dalfox",
  "severity": "High",
  "confidence": "High",
  "cvss_v3": "6.1",
  "exploitability_score": 87,
  "evidence_snippet": "<input name=\"searchFor\" value=\"\"><script>alert(1)</script>",
  "raw_outputs": ["/reports/job_b36a1b48/raw/dalfox.json"],
  "request_response": "/reports/job_b36a1b48/raw/req_res_f001.har",
  "screenshot": "/reports/job_b36a1b48/raw/f001.png",
  "confirmatory_tests": [
    {
      "name": "marker-reflection",
      "result": "passed",
      "output": "/reports/.../marker.txt"
    }
  ],
  "related_domains": ["static.testphp.vulnweb.com"],
  "exploit_vectors": ["<script>alert(1)</script>"],
  "remediation_suggestions": [
    {
      "type": "php",
      "code": "echo htmlspecialchars($_GET['searchFor'], ENT_QUOTES, 'UTF-8');"
    }
  ],
  "provenance": [
    {
      "claim": "remediation",
      "source_doc_id": "doc_owasp_xss_01",
      "snippet": "Use contextual output encoding..."
    }
  ],
  "created_at": "2025-10-09T10:57:51Z"
}
```

## 🛡️ Security Features

### **Safe Scanning**
- **Allowlist**: Chỉ scan targets được phép
- **Non-destructive**: Không thực hiện destructive actions
- **Timeout**: Resource limits cho mỗi tool
- **Sandbox**: Tools chạy trong isolated environment

### **Evidence Integrity**
- **Provenance**: Mọi claim có nguồn gốc
- **Verification**: Confirmatory tests
- **Storage**: Immutable evidence storage
- **Audit**: Complete audit trail

## 🚀 Getting Started

### **1. Install Dependencies**
```bash
pip install -r requirements.txt
```

### **2. Setup Tools**
```bash
# Install security tools
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/gospider/cmd/gospider@latest
```

### **3. Run Demo**
```bash
python demo_enhanced_scan.py
```

### **4. Start API Server**
```bash
python run_all.py
```

## 📈 Performance

### **Scan Times**
- **Small site** (< 100 pages): 2-5 minutes
- **Medium site** (100-1000 pages): 5-15 minutes
- **Large site** (> 1000 pages): 15-30 minutes

### **Resource Usage**
- **Memory**: 512MB - 2GB per scan
- **CPU**: 2-4 cores per scan
- **Storage**: 10MB - 100MB per scan

## 🔍 Troubleshooting

### **Common Issues**

1. **Tools not found**
   ```bash
   # Check tool installation
   which nuclei
   which dalfox
   which httpx
   ```

2. **Permission denied**
   ```bash
   # Check file permissions
   chmod +x /path/to/tools
   ```

3. **Timeout errors**
   ```bash
   # Increase timeout in config
   timeout = 300  # 5 minutes
   ```

### **Debug Mode**
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📚 References

- [OWASP Top 10 2023](https://owasp.org/Top10/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [Dalfox Documentation](https://github.com/hahwul/dalfox)
- [RAG Best Practices](https://docs.langchain.com/docs/use-cases/question-answering)

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Add tests
4. Submit pull request

## 📄 License

MIT License - see LICENSE file for details.

---

**🎯 Enhanced Security Scan System - Comprehensive, Evidence-based, RAG-powered Security Analysis**
