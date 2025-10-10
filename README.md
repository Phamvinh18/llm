
### 📋 Yêu cầu hệ thống
- Python 3.8+
- Windows/Linux/macOS
- 4GB RAM (khuyến nghị)
- Kết nối internet (cho LLM API)

🔧 Cài đặt

1. Clone repository
```bash
git clone <repository-url>
cd llm-main
```

2. Cài đặt dependencies
```bash
pip install -r requirements.txt
```

3. Thiết lập môi trường
```bash
# Tạo file .env
python setup.py
```

4. Cài đặt security tools (tùy chọn)
```bash
# Cài đặt tools cơ bản
python install_security_tools.py

# Cài đặt tools nâng cao
python install_enhanced_tools.py
```

Khởi chạy nhanh

Cách 1: Sử dụng script tự động
```bash
python run_all.py
```

Cách 2: Khởi chạy thủ công
```bash
# Terminal 1: Backend API
python -m uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload

# Terminal 2: Frontend UI
cd app/ui
python -m streamlit run streamlit_app.py --server.port 8501
```

Cách 3: Sử dụng PowerShell (Windows)
```powershell
.\run_all.ps1
```

Cách 4: Sử dụng Batch (Windows)
```cmd
run_all.bat
```
Truy cập hệ thống
- **Frontend UI**: http://localhost:8501
- **Backend API**: http://localhost:8002
- **API Documentation**: http://localhost:8002/docs

Scan Commands
```bash
/scan http://testphp.vulnweb.com/
/scan http://demo.testfire.net/
/scan http://httpbin.org/
```

Payload Generation
```bash
/payload xss
/payload sql_injection
/payload misconfig
/payload idor
```

Help và Information
```bash
/help
/examples
/vulnerabilities
```

### 🖥️ Web Interface

1. **Mở trình duyệt**: http://localhost:8501
2. **Chọn tab**: "Chat Assistant"
3. **Nhập lệnh**: `/scan http://testphp.vulnweb.com/`
4. **Xem kết quả**: Phân tích chi tiết với recommendations

## 📊 Kết quả scan mẫu

### 🔒 Security Headers Analysis
```
[SECURITY] Security Score: 15.0/100 (Kém)
[ERROR] Headers bảo mật thiếu:
  • Content-Security-Policy: Prevents XSS attacks
  • X-Frame-Options: Prevents clickjacking
  • Strict-Transport-Security: Enforces HTTPS

### 📁 Cấu trúc thư mục
```
llm-main/
├── app/
│   ├── api/                 # API endpoints
│   │   ├── chat_assistant.py
│   │   ├── router.py
│   │   └── ...
│   ├── core/               # Core logic
│   │   ├── chat_assistant_rag.py
│   │   ├── enhanced_scan_engine.py
│   │   ├── enhanced_scan_system.py
│   │   └── ...
│   ├── ui/                 # User interface
│   │   ├── streamlit_app.py
│   │   └── chat_assistant_ui.py
│   ├── data/               # Data và knowledge base
│   │   ├── enhanced_master_rag.json
│   │   └── whitelist.json
│   └── clients/            # External clients
│       └── gemini_client.py
├── tools/                  # Security tools
├── requirements.txt        # Dependencies
├── run_all.py             # Auto launcher
└── README.md
```

### 🔄 Workflow
1. **User Input** → Chat Assistant
2. **Command Detection** → Enhanced Scan System
3. **Security Scanning** → Multiple engines
4. **RAG Retrieval** → Knowledge base
5. **LLM Analysis** → AI-powered insights
6. **Report Generation** → Comprehensive results

## ⚙️ Cấu hình

### 🔑 Environment Variables (.env)
```env
# Gemini API Configuration
GEMINI_API_KEY=your_api_key_here
GEMINI_API_URL=https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent

# Database Configuration
DATABASE_URL=sqlite:///./app/data/vawebsec.db

# Target Whitelist
TARGET_WHITELIST_FILE=app/data/whitelist.json
```

