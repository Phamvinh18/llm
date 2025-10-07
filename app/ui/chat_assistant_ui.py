"""
Chat Assistant UI với RAG về lỗ hổng
"""

import streamlit as st
import requests
import json
import time

def render_chat_assistant_ui():
    """Render Chat Assistant UI với RAG"""
    st.title('[CHAT] Chat Assistant với RAG về Lỗ hổng')
    st.markdown("**Chatbot thông minh với RAG về XSS, SQL Injection, Misconfig, IDOR**")
    
    # API endpoint
    API = 'http://localhost:8002/api'
    
    # Chat interface
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.subheader('[CHAT] Chat Interface')
        
        # Input form
        with st.form('chat_form'):
            user_input = st.text_area(
                'Nhập tin nhắn của bạn:', 
                placeholder='Ví dụ:\n• /payload xss http://testphp.vulnweb.com\n• /scan http://demo.testfire.net\n• /help\n• hi',
                height=100,
                help='Sử dụng slash commands hoặc giao tiếp tự nhiên'
            )
            
            col_submit, col_clear = st.columns([1, 1])
            with col_submit:
                submit_button = st.form_submit_button('🚀 Gửi tin nhắn', use_container_width=True)
            with col_clear:
                clear_button = st.form_submit_button('[CLEAR] Clear', use_container_width=True)
        
        # Process message
        if submit_button and user_input:
            with st.spinner('Chat Assistant đang xử lý...'):
                try:
                    r = requests.post(f'{API}/chat-assistant/chat', 
                                    json={'message': user_input, 'user_id': 'streamlit_user'}, 
                                    timeout=600)  # Tăng timeout lên 10 phút
                    
                    if r.status_code == 200:
                        response = r.json()
                        if response.get('success'):
                            chat_response = response.get('response', {})
                            
                            # Display main response
                            st.success('[OK] Phản hồi từ Chat Assistant:')
                            st.markdown(chat_response.get('message', 'Không có phản hồi'))
                            
                            # Display payloads if available
                            payloads = chat_response.get('payloads', [])
                            if payloads:
                                st.subheader('[EXPLOSION] Payloads được tạo:')
                                for i, payload in enumerate(payloads[:5], 1):
                                    st.code(payload, language='text')
                                if len(payloads) > 5:
                                    st.info(f'... và {len(payloads) - 5} payloads khác')
                            
                            # Display scan results if available
                            scan_results = chat_response.get('scan_results', {})
                            if scan_results and 'error' not in scan_results:
                                st.subheader('[SCAN] Kết quả Scan:')
                                col_scan1, col_scan2 = st.columns(2)
                                
                                with col_scan1:
                                    st.metric('Status Code', scan_results.get('status_code', 'N/A'))
                                    st.metric('Response Size', f"{scan_results.get('response_size', 0)} bytes")
                                
                                with col_scan2:
                                    st.metric('Response Time', f"{scan_results.get('response_time', 0):.2f}s")
                                    st.metric('Content Type', scan_results.get('content_type', 'N/A')[:20])
                                
                                # Headers
                                headers = scan_results.get('headers', {})
                                if headers:
                                    with st.expander('[LIST] Response Headers'):
                                        for header, value in list(headers.items())[:10]:
                                            st.text(f"{header}: {value}")
                            
                            # Display LLM analysis if available
                            llm_analysis = chat_response.get('llm_analysis', '')
                            if llm_analysis:
                                st.subheader('🧠 Phân tích LLM:')
                                st.markdown(llm_analysis)
                            
                            # Display suggestions if available
                            suggestions = chat_response.get('suggestions', [])
                            if suggestions:
                                st.subheader('💡 Gợi ý tiếp theo:')
                                for suggestion in suggestions:
                                    st.markdown(f"• {suggestion}")
                            
                            # Add to chat history
                            if 'chat_history' not in st.session_state:
                                st.session_state.chat_history = []
                            st.session_state.chat_history.append({
                                'user_input': user_input,
                                'ai_response': chat_response.get('message', ''),
                                'payloads': payloads,
                                'scan_results': scan_results,
                                'llm_analysis': llm_analysis,
                                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                            })
                        else:
                            st.error('[ERROR] Chat Assistant trả về lỗi')
                    else:
                        st.error(f'[ERROR] Lỗi Chat Assistant: {r.text}')
                except Exception as e:
                    st.error(f'[ERROR] Lỗi: {str(e)}')
        
        # Clear chat history
        if clear_button:
            if 'chat_history' in st.session_state:
                st.session_state.chat_history = []
            st.success('Chat history đã được xóa!')
            st.rerun()
    
    with col2:
        st.subheader('[TARGET] Quick Actions')
        
        # Quick action buttons
        if st.button('[EXPLOSION] /payload xss', use_container_width=True):
            with st.spinner('Đang tạo payload XSS...'):
                try:
                    r = requests.post(f'{API}/chat-assistant/chat', 
                                    json={'message': '/payload xss http://testphp.vulnweb.com', 'user_id': 'streamlit_user'}, 
                                    timeout=600)  # Tăng timeout lên 10 phút
                    
                    if r.status_code == 200:
                        response = r.json()
                        if response.get('success'):
                            chat_response = response.get('response', {})
                            st.success('[OK] Payload XSS đã tạo!')
                            st.markdown(chat_response.get('message', 'Không có payload'))
                        else:
                            st.error('[ERROR] Lỗi tạo payload')
                    else:
                        st.error(f'[ERROR] Lỗi: {r.text}')
                except Exception as e:
                    st.error(f'[ERROR] Lỗi: {str(e)}')
        
        if st.button('[DATABASE] /payload sql', use_container_width=True):
            with st.spinner('Đang tạo payload SQL...'):
                try:
                    r = requests.post(f'{API}/chat-assistant/chat', 
                                    json={'message': '/payload sql_injection http://testphp.vulnweb.com', 'user_id': 'streamlit_user'}, 
                                    timeout=600)  # Tăng timeout lên 10 phút
                    
                    if r.status_code == 200:
                        response = r.json()
                        if response.get('success'):
                            chat_response = response.get('response', {})
                            st.success('[OK] Payload SQL đã tạo!')
                            st.markdown(chat_response.get('message', 'Không có payload'))
                        else:
                            st.error('[ERROR] Lỗi tạo payload')
                    else:
                        st.error(f'[ERROR] Lỗi: {r.text}')
                except Exception as e:
                    st.error(f'[ERROR] Lỗi: {str(e)}')
        
        if st.button('[SCAN] /scan', use_container_width=True):
            with st.spinner('Đang scan...'):
                try:
                    r = requests.post(f'{API}/chat-assistant/chat', 
                                    json={'message': '/scan http://testphp.vulnweb.com', 'user_id': 'streamlit_user'}, 
                                    timeout=600)  # Tăng timeout lên 10 phút
                    
                    if r.status_code == 200:
                        response = r.json()
                        if response.get('success'):
                            chat_response = response.get('response', {})
                            st.success('[OK] Scan hoàn thành!')
                            st.markdown(chat_response.get('message', 'Không có kết quả'))
                        else:
                            st.error('[ERROR] Lỗi scan')
                    else:
                        st.error(f'[ERROR] Lỗi: {r.text}')
                except Exception as e:
                    st.error(f'[ERROR] Lỗi: {str(e)}')
        
        if st.button('[BOOK] /help', use_container_width=True):
            with st.spinner('Đang tải hướng dẫn...'):
                try:
                    r = requests.post(f'{API}/chat-assistant/chat', 
                                    json={'message': '/help', 'user_id': 'streamlit_user'}, 
                                    timeout=600)  # Tăng timeout lên 10 phút
                    
                    if r.status_code == 200:
                        response = r.json()
                        if response.get('success'):
                            chat_response = response.get('response', {})
                            st.success('[OK] Hướng dẫn:')
                            st.markdown(chat_response.get('message', 'Không có hướng dẫn'))
                        else:
                            st.error('[ERROR] Lỗi tải hướng dẫn')
                    else:
                        st.error(f'[ERROR] Lỗi: {r.text}')
                except Exception as e:
                    st.error(f'[ERROR] Lỗi: {str(e)}')
        
        if st.button('[HELLO] /', use_container_width=True):
            with st.spinner('Đang chào...'):
                try:
                    r = requests.post(f'{API}/chat-assistant/chat', 
                                    json={'message': '/', 'user_id': 'streamlit_user'}, 
                                    timeout=600)  # Tăng timeout lên 10 phút
                    
                    if r.status_code == 200:
                        response = r.json()
                        if response.get('success'):
                            chat_response = response.get('response', {})
                            st.success('[OK] Lời chào:')
                            st.markdown(chat_response.get('message', 'Không có lời chào'))
                        else:
                            st.error('[ERROR] Lỗi chào')
                    else:
                        st.error(f'[ERROR] Lỗi: {r.text}')
                except Exception as e:
                    st.error(f'[ERROR] Lỗi: {str(e)}')
        
        # Vulnerability info
        st.subheader('[SECURITY] Lỗ hổng được hỗ trợ')
        st.markdown("""
        **XSS** - Cross-Site Scripting
        **SQL Injection** - SQL Injection  
        **Misconfig** - Security Misconfiguration
        **IDOR** - Insecure Direct Object Reference
        """)
        
        # RAG info
        st.subheader('🧠 RAG Features')
        st.markdown("""
        • URL tham chiếu thực tế
        • Giảm ảo giác LLM
        • Payloads chính xác
        • Phân tích chi tiết
        """)
    
    # Chat history
    st.subheader('[CERT] Chat History')
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []
    
    if st.session_state.chat_history:
        for i, chat in enumerate(reversed(st.session_state.chat_history[-5:])):  # Show last 5
            with st.expander(f"Chat {len(st.session_state.chat_history) - i}: {chat.get('user_input', '')[:50]}... ({chat.get('timestamp', '')})"):
                st.markdown(f"**User:** {chat.get('user_input', '')}")
                st.markdown(f"**AI:** {chat.get('ai_response', '')}")
                
                # Show payloads if available
                payloads = chat.get('payloads', [])
                if payloads:
                    st.markdown("**Payloads:**")
                    for payload in payloads[:3]:
                        st.code(payload, language='text')
                
                # Show scan results if available
                scan_results = chat.get('scan_results', {})
                if scan_results and 'error' not in scan_results:
                    st.markdown("**Scan Results:**")
                    st.json(scan_results)
                
                # Show LLM analysis if available
                llm_analysis = chat.get('llm_analysis', '')
                if llm_analysis:
                    st.markdown("**LLM Analysis:**")
                    st.markdown(llm_analysis)
    else:
        st.info('Chưa có chat history. Hãy bắt đầu chat!')
    
    # Health check
    st.subheader('[TOOL] System Status')
    try:
        r = requests.get(f'{API}/chat-assistant/health', timeout=5)
        if r.status_code == 200:
            health = r.json()
            st.success(f"[OK] {health.get('service', 'Chat Assistant')} - {health.get('status', 'healthy')}")
            
            # Show features
            features = health.get('features', [])
            if features:
                st.markdown("**Features:**")
                for feature in features:
                    st.markdown(f"• {feature}")
        else:
            st.error('[ERROR] Chat Assistant không khả dụng')
    except Exception as e:
        st.error(f'[ERROR] Lỗi kết nối: {str(e)}')
