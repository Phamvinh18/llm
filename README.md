VA-WebSec - Virtual Assistant for Web Security Testing

Contents
- FastAPI backend (app/)
- Streamlit UI (app/ui/) with 3 pages: Chat Assistant, Burp Scanner, Scan Analysis
- Clients: Gemini (mock+real stub), Burp (mock+real stub), Nikto wrapper
- KB (app/data/payloads_expanded.json) and whitelist
- Tools (tools/generate_kb.py, tools/demo_runner.py)

APIs
- POST /api/smart-scan/smart-scan: **NEW** URL → LLM sinh requests → Scan → LLM phân tích → Exploitation guide
- POST /api/analyze: Analyze request/response pairs with heuristics + LLM
- POST /api/workflow/scan-and-analyze: Complete Burp scan → LLM analysis → curl generation
- POST /api/workflow/scan: Start new Burp scan
- GET /api/workflow/scans: List all scans
- POST /api/workflow/analyze-scan: Analyze existing scan with LLM
- GET /api/workflow/scan/{scan_id}/curl/{finding_id}: Get curl commands for testing

Features
- **Smart Scanner**: URL → LLM sinh requests → Scan → LLM phân tích → Exploitation guide
- Hybrid security analysis: Heuristics + LLM for vulnerability detection
- Burp integration with request/response capture
- Automatic curl command generation for manual testing
- False positive detection and severity justification
- Comprehensive UI for scan management and analysis

Workflow (Burp + Nikto + curl + LLM)
- Start scan (Burp) and kick off Nikto in background
- Retrieve findings with full request/response
- Heuristics + LLM analyze each finding
- Generate verification curl commands per finding
- Suggest payloads (built-in + LLM-augmented)

Useful endpoints
- POST /api/workflow/scan-and-analyze → end-to-end workflow
- GET /api/workflow/scan/{scan_id}/curl/{finding_id} → curl commands
- GET /api/workflow/scan/{scan_id}/payloads/{finding_id} → suggested payloads

n8n Integration
- Import `tools/n8n_workflow_scan_analyze.json` into n8n
- Variables in node "Set Config":
  - baseUrl: http://localhost:8000/api
  - targetUrl: http://juice-shop:3000 (hoặc URL của bạn)
  - autoAnalyze: true
- Workflow: Set Config → HTTP (scan-and-analyze) → split findings → HTTP (curl, payloads) → merge

Quickstart (with real APIs configured):

**Option 1: Automated Setup (Recommended)**
```bash
# 1. Setup virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 2. Run automated setup
python setup.py

# 3. Start the system
python -m uvicorn app.main:app --reload --port 8000
uvicorn app.main:app --reload --port 8000
python -m streamlit run app/ui/streamlit_app.py
streamlit run app/ui/streamlit_app.py
python run_ultimate.py
python test_acunetix_site.py
python test_juice_shop.py
```
python -m uvicorn app.main:app --reload --port 8000
python -m streamlit run app/ui/streamlit_app.py --server.port 8501
python test_acunetix_site.py

**Option 2: Manual Setup**

macOS/Linux:
1) unzip pentest-assistant.zip && cd va-websec-project
2) python -m venv .venv && source .venv/bin/activate
3) pip install -r requirements.txt
4) python -c "from app.db.session import init_db; init_db()"
5) python tools/generate_kb.py
6) uvicorn app.main:app --reload --port 8000
7) streamlit run app/ui/streamlit_app.py

Windows (PowerShell):
1) Expand-Archive .\pentest-assistant.zip -DestinationPath .\va-websec-project; cd .\va-websec-project
2) python -m venv .venv; .\.venv\Scripts\Activate.ps1
3) pip install -r requirements.txt
4) python -c "from app.db.session import init_db; init_db()"
5) python .\tools\generate_kb.py
6) uvicorn app.main:app --reload --port 8000
7) streamlit run app\ui\streamlit_app.py

**Configuration:**
- **Gemini API**: Pre-configured with your API key for real LLM analysis
- **Burp API**: Pre-configured for http://127.0.0.1:1337 with your API key
- **Environment**: Variables loaded from .env file automatically
- **Database**: SQLite database in app/data/vawebsec.db

Legal & Safety: Only scan systems you own or have explicit permission to test. Configure TARGET_WHITELIST_FILE to restrict targets.
