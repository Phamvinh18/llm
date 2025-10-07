# 🛡️ VA-WebSec - Virtual Assistant for Web Security Testing

**VA-WebSec** là một hệ thống trợ lý ảo thông minh cho việc kiểm tra bảo mật web, được tích hợp với RAG (Retrieval-Augmented Generation) và LLM để cung cấp phân tích bảo mật chuyên nghiệp và chính xác.

## 🌟 Tính năng chính

### 🔍 **Enhanced Security Scanning**
- **Advanced XSS Detection**: 50+ payloads với encoding variations
- **SQL Injection Testing**: Comprehensive error-based và blind SQL injection
- **Security Headers Analysis**: Weighted scoring system với quality assessment
- **Path Discovery**: 200+ common paths với risk assessment
- **Technology Stack Detection**: CMS, frameworks, server identification

### 🤖 **AI-Powered Analysis**
- **RAG Integration**: Knowledge base về lỗ hổng bảo mật
- **LLM Analysis**: Phân tích thông minh với evidence và recommendations
- **Natural Language Processing**: Giao tiếp tự nhiên với chat assistant
- **Contextual Understanding**: Hiểu ngữ cảnh và đưa ra khuyến nghị phù hợp

### 💬 **Interactive Chat Assistant**
- **Slash Commands**: `/scan`, `/payload`, `/help`
- **Natural Conversation**: Giao tiếp như con người
- **Real-time Analysis**: Phân tích và báo cáo tức thì
- **Test URL Generation**: Tự động tạo URL test cho lỗ hổng

## 🚀 Cài đặt và Khởi chạy

### 📋 Yêu cầu hệ thống
- Python 3.8+
- Windows/Linux/macOS
- 4GB RAM (khuyến nghị)
- Kết nối internet (cho LLM API)

### 🔧 Cài đặt

#### 1. Clone repository
```bash
git clone <repository-url>
cd llm-main
```

#### 2. Cài đặt dependencies
```bash
pip install -r requirements.txt
```

#### 3. Thiết lập môi trường
```bash
# Tạo file .env
python setup.py
```

#### 4. Cài đặt security tools (tùy chọn)
```bash
# Cài đặt tools cơ bản
python install_security_tools.py

# Cài đặt tools nâng cao
python install_enhanced_tools.py
```

### ⚡ Khởi chạy nhanh

#### Cách 1: Sử dụng script tự động
```bash
python run_all.py
```

#### Cách 2: Khởi chạy thủ công
```bash
# Terminal 1: Backend API
python -m uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload

# Terminal 2: Frontend UI
cd app/ui
python -m streamlit run streamlit_app.py --server.port 8501
```

#### Cách 3: Sử dụng PowerShell (Windows)
```powershell
.\run_all.ps1
```

#### Cách 4: Sử dụng Batch (Windows)
```cmd
run_all.bat
```

## 🎯 Cách sử dụng

### 🌐 Truy cập hệ thống
- **Frontend UI**: http://localhost:8501
- **Backend API**: http://localhost:8002
- **API Documentation**: http://localhost:8002/docs

### 💬 Chat Assistant Commands

#### 🔍 Scan Commands
```bash
/scan http://testphp.vulnweb.com/
/scan http://demo.testfire.net/
/scan http://httpbin.org/
```

#### 🎯 Payload Generation
```bash
/payload xss
/payload sql_injection
/payload misconfig
/payload idor
```

#### ❓ Help và Information
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
```

### 📁 Discovered Paths
```
[FOLDER] Tổng số: 25 paths
[FOLDER] Status 200: 8 paths
[FOLDER] Status 403: 12 paths
[FOLDER] Status 401: 5 paths

[ALERT] High Risk (3):
  • /admin - Admin Panel
  • /phpmyadmin/ - Database Management
  • /backup.sql - Database Backup
```

### 🚨 Vulnerability Detection
```
[ALERT] XSS-Reflected (5):
  1. XSS-Reflected (CWE-79)
     Parameter: test
     [TEST] URL: http://testphp.vulnweb.com/search.php?test=<script>alert(1)</script>
     Evidence: Direct payload reflection detected
     Confidence: 95%
```

## 🏗️ Kiến trúc hệ thống

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

### 🎛️ Scan Profiles
- **FAST**: Scan cơ bản (1-2 phút)
- **ENHANCED**: Scan nâng cao (3-5 phút)
- **DEEP**: Scan sâu (5-10 phút)

## 🛠️ API Endpoints

### 💬 Chat Assistant
```http
POST /api/chat-assistant/chat
Content-Type: application/json

{
  "message": "/scan http://testphp.vulnweb.com/",
  "user_id": "user123"
}
```

### 🔍 Health Check
```http
GET /api/chat-assistant/health
GET /api/health
```

### 📚 Help và Examples
```http
GET /api/chat-assistant/help
GET /api/chat-assistant/examples
GET /api/chat-assistant/vulnerabilities
```

## 🔧 Troubleshooting

### ❌ Lỗi thường gặp

#### 1. Chat Assistant "Not Found"
```bash
# Kiểm tra backend
curl http://localhost:8002/api/health

# Restart backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload
```

#### 2. Frontend không load
```bash
# Kiểm tra port 8501
netstat -an | findstr 8501

# Restart frontend
cd app/ui
python -m streamlit run streamlit_app.py --server.port 8501
```

#### 3. LLM Analysis Error
```bash
# Kiểm tra API key
echo $GEMINI_API_KEY

# Test API connection
python -c "from app.clients.gemini_client import GeminiClient; print(GeminiClient().chat('test'))"
```

#### 4. Unicode Encoding Error
```bash
# Đã được fix tự động trong code
# Nếu vẫn gặp lỗi, set encoding:
set PYTHONIOENCODING=utf-8
```

### 🔍 Debug Mode
```bash
# Enable debug logging
export DEBUG=1
python run_all.py
```

## 📈 Performance

### ⏱️ Scan Times
- **Basic Scan**: 30-60 giây
- **Enhanced Scan**: 2-5 phút
- **Deep Scan**: 5-10 phút

### 💾 Resource Usage
- **RAM**: 200-500MB
- **CPU**: 10-30% (during scan)
- **Network**: 1-10MB per scan

## 🔒 Security Features

### 🛡️ Built-in Protections
- **Input Validation**: Tất cả inputs được validate
- **Output Encoding**: XSS protection
- **Rate Limiting**: API rate limiting
- **Target Whitelist**: Chỉ scan targets được phép

### 🚫 Responsible Disclosure
- Chỉ scan targets trong whitelist
- Không thực hiện attacks thực tế
- Chỉ phát hiện và báo cáo lỗ hổng

## 🤝 Contributing

### 📝 Development Setup
```bash
# Clone và setup
git clone <repo>
cd llm-main
pip install -r requirements.txt

# Run tests
python -m pytest tests/

# Code formatting
black app/
flake8 app/
```

### 🐛 Bug Reports
1. Tạo issue với mô tả chi tiết
2. Include logs và error messages
3. Specify environment (OS, Python version)

### 💡 Feature Requests
1. Mô tả tính năng mong muốn
2. Use case và benefits
3. Implementation suggestions (nếu có)

## 📄 License

MIT License - Xem file LICENSE để biết thêm chi tiết.

## 🙏 Acknowledgments

- **OWASP**: Security guidelines và best practices
- **Google Gemini**: LLM capabilities
- **Streamlit**: Web interface framework
- **FastAPI**: High-performance API framework

## 📞 Support

- **Documentation**: Xem file README.md này
- **Issues**: Tạo GitHub issue
- **Examples**: `/help` command trong chat assistant

---

**🎯 VA-WebSec - Making Web Security Testing Accessible and Intelligent!**

*Phiên bản: 2.0.0 | Cập nhật: 2024*