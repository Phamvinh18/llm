import streamlit as st
import requests
import json
import time

API = 'http://localhost:8002/api'
st.set_page_config(page_title='VA-WebSec Assistant', layout='wide')

# Custom CSS for improved design
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        text-align: center;
        color: white;
    }
    
    .metric-card {
        background: #f8f9fa;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        border-left: 4px solid #667eea;
        margin-bottom: 1rem;
        color: #2c3e50;
    }
    
    .metric-card-white {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        border-left: 4px solid #667eea;
        margin-bottom: 1rem;
        color: #2c3e50;
    }
    
    .metric-card-dark {
        background: #34495e;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        border-left: 4px solid #667eea;
        margin-bottom: 1rem;
        color: white;
    }
    
    .vulnerability-card {
        background: #fff5f5;
        border: 1px solid #fed7d7;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    
    .success-card {
        background: #f0fff4;
        border: 1px solid #9ae6b4;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    
    .info-card {
        background: #ebf8ff;
        border: 1px solid #90cdf4;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    
    .warning-card {
        background: #fffbeb;
        border: 1px solid #f6e05e;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    
    .input-example {
        background: #f7fafc;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 0.5rem;
        margin: 0.5rem 0;
        font-size: 0.9rem;
        color: #4a5568;
    }
    
    .feature-selector {
        background: #34495e;
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    
    .chat-container {
        background: #f8f9fa;
        border-radius: 10px;
        padding: 1rem;
        margin-bottom: 1rem;
        max-height: 500px;
        overflow-y: auto;
    }
    
    .chat-message {
        margin-bottom: 1rem;
        padding: 0.5rem;
        border-radius: 8px;
    }
    
    .chat-user {
        background: #e3f2fd;
        margin-left: 2rem;
    }
    
    .chat-bot {
        background: #f3e5f5;
        margin-right: 2rem;
    }
</style>
""", unsafe_allow_html=True)

# Main header
st.markdown("""
<div class="main-header">
    <h1>🚀 VA-WebSec Assistant</h1>
    <p>Advanced Web Security Testing & Vulnerability Assessment Platform</p>
</div>
""", unsafe_allow_html=True)

# Initialize session state
if 'session' not in st.session_state:
    st.session_state.session = 'sess-' + str(time.time()).replace('.', '')

# Sidebar for navigation
st.sidebar.title('VA-WebSec Assistant')
st.sidebar.markdown('<div class="feature-selector">', unsafe_allow_html=True)
page = st.sidebar.selectbox('Choose a page', ['Chat Assistant', 'Super Intelligent AI', 'Smart Scanner', 'Burp Scanner', 'Nikto Scanner', 'Scan Analysis', 'Monitoring Dashboard'])
st.sidebar.markdown('</div>', unsafe_allow_html=True)

def render_smart_chatbot_ui():
    """Render Smart Chatbot UI"""
    st.title('🤖 Smart Chatbot - Hiểu Ngôn Ngữ Tự Nhiên')
    st.markdown("**Tự động hiểu intent và thực hiện hành động • Scan • Payload • Attack • Discovery**")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Initialize chat history
        if 'smart_chat_history' not in st.session_state:
            st.session_state.smart_chat_history = []
        
        # Chat container
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        
        # Display chat history
        for i, chat in enumerate(st.session_state.smart_chat_history):
            if chat['type'] == 'user':
                st.markdown(f'<div class="chat-message chat-user"><strong>Bạn:</strong> {chat["message"]}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="chat-message chat-bot"><strong>Smart AI:</strong> {chat["message"]}</div>', unsafe_allow_html=True)
                
                # Display action result if available
                if 'action_result' in chat and chat['action_result']:
                    action_result = chat['action_result']
                    if action_result.get('success'):
                        st.success(f"[OK] {action_result.get('message', 'Action completed successfully')}")
                        
                        # Display action data if available
                        if 'data' in action_result and action_result['data']:
                            data = action_result['data']
                            
                            # Display scan results
                            if 'findings' in data:
                                st.subheader('[SCAN] Scan Results')
                                for finding in data['findings'][:5]:  # Show first 5 findings
                                    st.write(f"• **{finding.get('title', 'Unknown')}** - {finding.get('risk_level', 'Unknown')}")
                            
                            # Display payload results
                            elif 'payloads' in data:
                                st.subheader('[LIGHTNING] Generated Payloads')
                                for payload in data['payloads'][:3]:  # Show first 3 payloads
                                    st.code(payload, language='text')
                            
                            # Display request results
                            elif 'responses' in data:
                                st.subheader('[HTTP] Request Responses')
                                for response in data['responses'][:3]:  # Show first 3 responses
                                    st.write(f"• Status: {response.get('status', 'Unknown')}")
                                    st.write(f"• URL: {response.get('url', 'Unknown')}")
                            
                            # Display subdomain results
                            elif 'subdomains' in data:
                                st.subheader('[WEB] Found Subdomains')
                                for subdomain in data['subdomains']:
                                    st.write(f"• {subdomain.get('subdomain', 'Unknown')} - Status: {subdomain.get('status', 'Unknown')}")
                            
                            # Display file discovery results
                            elif 'files' in data:
                                st.subheader('[FOLDER] Found Files')
                                for file_info in data['files']:
                                    st.write(f"• {file_info.get('file', 'Unknown')} - Status: {file_info.get('status', 'Unknown')}")
                    else:
                        st.error(f"[ERROR] {action_result.get('message', 'Action failed')}")
                
                # Display suggestions if available
                if 'suggestions' in chat and chat['suggestions']:
                    st.subheader('💡 Suggestions')
                    for suggestion in chat['suggestions']:
                        if st.button(suggestion, key=f"suggestion_{i}_{suggestion}"):
                            # Add suggestion as user message
                            st.session_state.smart_chat_history.append({
                                'type': 'user',
                                'message': suggestion,
                                'timestamp': time.time()
                            })
                            st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Smart Chat input
        with st.form('smart_chat_form'):
            user_message = st.text_input('🤖 Nhập tin nhắn (hiểu ngôn ngữ tự nhiên):', 
                                       placeholder='Ví dụ: Hi, Hãy scan lỗ hổng của web http://testphp.vulnweb.com, Tạo payload XSS, Tấn công vào web...',
                                       help='AI sẽ tự động hiểu intent và thực hiện hành động phù hợp')
            
            col_btn1, col_btn2 = st.columns([1, 1])
            with col_btn1:
                if st.form_submit_button('🚀 Gửi tin nhắn', type='primary'):
                    if user_message.strip():
                        # Add user message to history
                        st.session_state.smart_chat_history.append({
                            'type': 'user',
                            'message': user_message,
                            'timestamp': time.time()
                        })
                        
                        try:
                            with st.spinner('🤖 Smart AI đang phân tích và thực hiện hành động...'):
                                # Send to Smart Chatbot API
                                smart_request = {
                                    'message': user_message,
                                    'session_id': st.session_state.session
                                }
                                
                                smart_response = requests.post(API + '/smart-chatbot/smart-chat', 
                                                             json=smart_request, 
                                                             timeout=120)
                                
                                if smart_response.status_code == 200:
                                    result = smart_response.json()
                                    
                                    # Add bot response to history
                                    bot_response = {
                                        'type': 'bot',
                                        'message': result['response'],
                                        'intent': result.get('intent', {}),
                                        'action_result': result.get('action_result', {}),
                                        'suggestions': result.get('suggestions', []),
                                        'timestamp': time.time()
                                    }
                                    
                                    st.session_state.smart_chat_history.append(bot_response)
                                    
                                    # Show intent information
                                    intent = result.get('intent', {})
                                    if intent:
                                        intent_type = intent.get('type', 'unknown')
                                        confidence = intent.get('confidence', 0)
                                        st.info(f"[TARGET] Detected Intent: {intent_type} (Confidence: {confidence:.1%})")
                                    
                                    # Show execution time
                                    execution_time = result.get('execution_time', 0)
                                    st.success(f"[OK] Smart AI đã xử lý trong {execution_time:.2f}s!")
                                    
                                    # Rerun to show new messages
                                    st.rerun()
                                else:
                                    st.error(f"[ERROR] Lỗi Smart Chatbot: {smart_response.text}")
                                    
                        except Exception as e:
                            st.error(f"[ERROR] Lỗi: {str(e)}")
                    else:
                        st.warning("[WARNING] Vui lòng nhập tin nhắn!")
            
            with col_btn2:
                if st.form_submit_button('[DELETE] Xóa lịch sử'):
                    st.session_state.smart_chat_history = []
                    st.rerun()
        
        # Quick action buttons
        st.subheader('[LIGHTNING] Quick Actions')
        col_q1, col_q2, col_q3, col_q4 = st.columns(4)
        
        with col_q1:
            if st.button('[HELLO] Chào hỏi'):
                st.session_state.smart_chat_history.append({
                    'type': 'user',
                    'message': 'Hi',
                    'timestamp': time.time()
                })
                st.rerun()
        
        with col_q2:
            if st.button('[SCAN] Scan Test Site'):
                st.session_state.smart_chat_history.append({
                    'type': 'user',
                    'message': 'Hãy scan lỗ hổng của web http://testphp.vulnweb.com',
                    'timestamp': time.time()
                })
                st.rerun()
        
        with col_q3:
            if st.button('[LIGHTNING] Tạo Payload'):
                st.session_state.smart_chat_history.append({
                    'type': 'user',
                    'message': 'Tạo payload XSS cho http://testphp.vulnweb.com',
                    'timestamp': time.time()
                })
                st.rerun()
        
        with col_q4:
            if st.button('[TARGET] Tấn công'):
                st.session_state.smart_chat_history.append({
                    'type': 'user',
                    'message': 'Tấn công vào web http://testphp.vulnweb.com',
                    'timestamp': time.time()
                })
                st.rerun()
    
    with col2:
        st.subheader('🤖 Smart Chatbot Status')
        
        # Chatbot capabilities
        st.markdown("### [TARGET] Capabilities")
        capabilities = [
            "[SCAN] **Scan lỗ hổng** - Burp, Smart, Nikto",
            "[LIGHTNING] **Tạo payload** - XSS, SQL, Path Traversal",
            "[TARGET] **Tấn công** - Gửi request, test lỗ hổng",
            "[WEB] **Tìm subdomain** - Subdomain enumeration",
            "[FOLDER] **File discovery** - Tìm file ẩn",
            "🧠 **LLM Analysis** - Phân tích với AI"
        ]
        
        for capability in capabilities:
            st.markdown(capability)
        
        # Intent examples
        st.markdown("### 💡 Intent Examples")
        examples = [
            "**Greeting**: Hi, Hello, Xin chào",
            "**Scan**: Hãy scan lỗ hổng của web...",
            "**Payload**: Tạo payload XSS cho...",
            "**Attack**: Tấn công vào web...",
            "**Discovery**: Tìm subdomain của...",
            "**File**: Tìm file ẩn trên website"
        ]
        
        for example in examples:
            st.markdown(example)
        
        # Statistics
        if st.session_state.smart_chat_history:
            st.markdown("### [CHART] Statistics")
            total_messages = len(st.session_state.smart_chat_history)
            user_messages = len([m for m in st.session_state.smart_chat_history if m['type'] == 'user'])
            bot_messages = len([m for m in st.session_state.smart_chat_history if m['type'] == 'bot'])
            
            st.metric("Total Messages", total_messages)
            st.metric("User Messages", user_messages)
            st.metric("Bot Messages", bot_messages)
        
        # Quick suggestions
        st.markdown("### 🚀 Quick Suggestions")
        quick_suggestions = [
            "Hi [HELLO]",
            "Scan http://testphp.vulnweb.com",
            "Tạo payload XSS",
            "Tấn công website",
            "Tìm subdomain",
            "Tìm file ẩn"
        ]
        
        for suggestion in quick_suggestions:
            if st.button(suggestion, key=f"quick_{suggestion}"):
                st.session_state.smart_chat_history.append({
                    'type': 'user',
                    'message': suggestion,
                    'timestamp': time.time()
                })
                st.rerun()

if page == 'Chat Assistant':
    from chat_assistant_ui import render_chat_assistant_ui
    render_chat_assistant_ui()

if page == 'Super Intelligent AI':
    # from super_intelligent_chatbot_ui import render_super_intelligent_chatbot_ui
    st.info("Super Intelligent AI feature is under development")

if page == 'Monitoring Dashboard':
    from monitoring_dashboard import render_monitoring_dashboard
    render_monitoring_dashboard()

elif page == 'Smart Scanner':
    st.title('🤖 Professional Smart Scanner - LLM Powered')
    st.markdown("**Workflow:** URL → LLM sinh requests → Scan → LLM phân tích → Detailed response analysis")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader('🚀 Start Smart Scan')
        
        with st.form('smart_scan_form'):
            smart_target = st.text_input('Target URL:', value='http://testphp.vulnweb.com', 
                                       help='Enter the target URL to scan')
            st.markdown('<div class="input-example">💡 Example: http://testphp.vulnweb.com (Acunetix Test Site) or http://localhost:3000 (Juice Shop)</div>', unsafe_allow_html=True)
            
            auto_analyze = st.checkbox('Auto-analyze with LLM', value=True)
            st.markdown('<div class="input-example">💡 Enable AI analysis for detailed vulnerability assessment</div>', unsafe_allow_html=True)
            
            if st.form_submit_button('Start Smart Scan', type='primary'):
                try:
                    with st.spinner('Starting Smart scan...'):
                        r = requests.post(API + '/smart-scan/smart-scan', 
                                        json={'target_url': smart_target, 'session_id': st.session_state.session}, 
                                        timeout=300)
                        
                        if r.status_code == 200:
                            result = r.json()
                            st.success(f"Smart scan completed! Scan ID: {result.get('scan_id', 'N/A')}")
                            st.session_state.smart_scan_result = result
                        else:
                            st.error(f"Smart scan failed: {r.text}")
                except Exception as e:
                    st.error(f"Smart scan failed: {str(e)}")
    
    with col2:
        st.subheader('[CHART] Smart Scanner Info')
        st.markdown("""
        **Features:**
        - LLM-powered request generation
        - Intelligent vulnerability detection
        - Advanced response analysis
        - Context-aware scanning
        """)

elif page == 'Burp Scanner':
    st.title('[SCAN] Burp Scanner & Analysis')
    st.markdown("**Integrated Burp Scanner with Chat Assistant**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader('🚀 Start New Scan')
        
        with st.form('burp_scan_form'):
            scan_target = st.text_input('Target URL:', value='http://testphp.vulnweb.com', 
                                      help='Enter the target URL to scan')
            st.markdown('<div class="input-example">💡 Example: http://testphp.vulnweb.com (Acunetix Test Site) or http://localhost:3000 (Juice Shop)</div>', unsafe_allow_html=True)
            
            auto_analyze = st.checkbox('Auto-analyze with LLM', value=True)
            st.markdown('<div class="input-example">💡 Enable AI analysis for detailed vulnerability assessment</div>', unsafe_allow_html=True)
            
            if st.form_submit_button('Start Scan', type='primary'):
                try:
                    with st.spinner('Starting Burp scan...'):
                        r = requests.post(API + '/workflow/scan-and-analyze', 
                                        json={'target_url': scan_target, 'session_id': st.session_state.session}, 
                                        timeout=600)  # Tăng timeout lên 10 phút
                        
                        if r.status_code == 200:
                            result = r.json()
                            st.success(f"[OK] Scan completed! Scan ID: {result['scan_id']}")
                            st.session_state.current_scan = result
                            
                            # Display scan results
                            if 'analysis' in result:
                                analysis = result['analysis']
                                summary = analysis.get('summary', {})
                                
                                # Display summary
                                col1, col2, col3, col4 = st.columns(4)
                                with col1:
                                    st.metric("Total Findings", summary.get('total_findings', 0))
                                with col2:
                                    st.metric("Critical", summary.get('critical_count', 0))
                                with col3:
                                    st.metric("High", summary.get('high_count', 0))
                                with col4:
                                    st.metric("Overall Risk", summary.get('overall_risk', 'Unknown'))
                                
                                # Display findings
                                findings = analysis.get('findings', [])
                                if findings:
                                    st.subheader("[SCAN] Vulnerability Findings")
                                    for i, finding in enumerate(findings[:5]):  # Show first 5
                                        with st.expander(f"Finding {i+1}: {finding.get('title', 'Unknown')} - {finding.get('risk', 'Unknown')}"):
                                            st.write(f"**URL:** {finding.get('url', 'N/A')}")
                                            st.write(f"**Severity:** {finding.get('severity', 'N/A')}")
                                            st.write(f"**Description:** {finding.get('description', 'N/A')}")
                                            
                                            # LLM Analysis
                                            if 'llm_analysis' in finding:
                                                st.write("**🤖 AI Analysis:**")
                                                llm_analysis = finding['llm_analysis']
                                                if llm_analysis:
                                                    st.write(f"Confidence: {llm_analysis.get('confidence', 0):.2f}")
                                                    st.write(f"Description: {llm_analysis.get('description', 'N/A')}")
                                            
                                            # Suggested payloads
                                            if 'suggested_payloads' in finding:
                                                st.write("**💡 Suggested Payloads:**")
                                                payloads = finding['suggested_payloads'][:3]  # Show first 3
                                                for payload in payloads:
                                                    st.code(payload)
                        else:
                            st.error(f"[ERROR] Scan failed: {r.text}")
                except Exception as e:
                    st.error(f"Scan failed: {str(e)}")
    
    with col2:
        st.subheader('[CHART] Burp Scanner Info')
        st.markdown("""
        **Features:**
        - Professional vulnerability scanning
        - LLM-powered analysis
        - Detailed findings report
        - Integration with Chat Assistant
        """)

elif page == 'Nikto Scanner':
    st.title('[SCAN] Nikto Scanner & Analysis')
    st.markdown("**Web Server Vulnerability Scanner**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader('🚀 Start Nikto Scan')
        
        with st.form('nikto_scan_form'):
            nikto_target = st.text_input('Target URL:', value='http://testphp.vulnweb.com', 
                                       help='Enter the target URL to scan')
            st.markdown('<div class="input-example">💡 Example: http://testphp.vulnweb.com (Acunetix Test Site) or http://localhost:3000 (Juice Shop)</div>', unsafe_allow_html=True)
            
            auto_analyze = st.checkbox('Auto-analyze with LLM', value=True)
            st.markdown('<div class="input-example">💡 Enable AI analysis for detailed vulnerability assessment</div>', unsafe_allow_html=True)
            
            if st.form_submit_button('Start Nikto Scan', type='primary'):
                try:
                    with st.spinner('Starting Nikto scan...'):
                        r = requests.post(API + '/nikto/start-scan', 
                                        json={'target_url': nikto_target, 'session_id': st.session_state.session}, 
                                        timeout=300)
                        
                        if r.status_code == 200:
                            result = r.json()
                            st.success(f"Nikto scan completed! Scan ID: {result['scan_id']}")
                            st.session_state.nikto_scan_result = result
                        else:
                            st.error(f"Nikto scan failed: {r.text}")
                except Exception as e:
                    st.error(f"Nikto scan failed: {str(e)}")
    
    with col2:
        st.subheader('[CHART] Nikto Scanner Info')
        st.markdown("""
        **Features:**
        - Web server vulnerability detection
        - CGI vulnerability scanning
        - Server misconfiguration detection
        - LLM-powered analysis
        """)

elif page == 'Scan Analysis':
    st.title('[CHART] Scan Analysis & Results')
    st.markdown("**Comprehensive vulnerability analysis and reporting**")
    
    # Display scan results if available
    if 'current_scan' in st.session_state:
        scan_data = st.session_state.current_scan
        st.subheader('[SCAN] Current Scan Results')
        
        # Scan summary
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Target", scan_data.get('target', 'N/A'))
        with col2:
            st.metric("Scan ID", scan_data.get('scan_id', 'N/A'))
        with col3:
            st.metric("Status", scan_data.get('status', 'N/A'))
        with col4:
            st.metric("Findings", len(scan_data.get('findings', [])))
        
        # Analysis results
        if 'analysis' in scan_data:
            analysis = scan_data['analysis']
            st.subheader('🧠 LLM Analysis Results')
            
            # Summary
            if 'summary' in analysis:
                st.info(f"**Summary:** {analysis['summary']}")
            
            # Findings
            if 'findings' in analysis:
                st.subheader('[ALERT] Vulnerabilities Found')
                for finding in analysis['findings']:
                    with st.expander(f"🔴 {finding.get('title', 'Unknown')} - {finding.get('risk_level', 'Unknown')}"):
                        st.write(f"**Description:** {finding.get('description', 'N/A')}")
                        st.write(f"**Risk Level:** {finding.get('risk_level', 'N/A')}")
                        st.write(f"**URL:** {finding.get('url', 'N/A')}")
                        
                        if 'remediation' in finding:
                            st.write(f"**Remediation:** {finding['remediation']}")
    
    else:
        st.info("No scan results available. Please run a scan first.")
