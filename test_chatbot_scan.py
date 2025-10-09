#!/usr/bin/env python3
"""
Test script để kiểm tra chatbot scan functionality
"""

import asyncio
import requests
import json
import time

async def test_chatbot_scan():
    """Test chatbot scan functionality"""
    
    print("🧪 Testing Chatbot Scan Functionality")
    print("=" * 50)
    
    # Test URL
    test_url = "http://testphp.vulnweb.com/"
    scan_message = f"/scan {test_url}"
    
    # API endpoint
    api_url = "http://localhost:8002/api/chat-assistant/chat"
    
    print(f"📡 Testing scan command: {scan_message}")
    print(f"🎯 Target URL: {test_url}")
    print(f"🔗 API Endpoint: {api_url}")
    print()
    
    # Prepare request data
    request_data = {
        "message": scan_message,
        "user_id": "test_user"
    }
    
    try:
        print("⏳ Sending scan request...")
        start_time = time.time()
        
        # Send request with longer timeout
        response = requests.post(
            api_url,
            json=request_data,
            timeout=300,  # 5 minutes timeout
            headers={"Content-Type": "application/json"}
        )
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        print(f"⏱️  Scan completed in {scan_duration:.2f} seconds")
        print()
        
        if response.status_code == 200:
            result = response.json()
            
            print("✅ SUCCESS: Scan completed successfully!")
            print()
            print("📊 Response Summary:")
            print(f"   • Status: {result.get('success', 'Unknown')}")
            print(f"   • Command: {result.get('command', 'Unknown')}")
            print(f"   • Message Length: {len(result.get('message', ''))} characters")
            print(f"   • Suggestions: {len(result.get('suggestions', []))} items")
            print()
            
            # Show message preview
            message = result.get('message', '')
            if message:
                print("📝 Message Preview (first 500 chars):")
                print("-" * 50)
                print(message[:500])
                if len(message) > 500:
                    print("...")
                print("-" * 50)
                print()
            
            # Show suggestions
            suggestions = result.get('suggestions', [])
            if suggestions:
                print("💡 Suggestions:")
                for i, suggestion in enumerate(suggestions, 1):
                    print(f"   {i}. {suggestion}")
                print()
            
            # Check if message contains tool results
            if any(keyword in message.lower() for keyword in ['nikto', 'nuclei', 'ffuf', 'httpx', 'tool', 'vulnerability']):
                print("🔧 ✅ Tool integration detected in response!")
            else:
                print("⚠️  ⚠️  No tool integration detected in response")
            
            # Check if message contains RAG/LLM analysis
            if any(keyword in message.lower() for keyword in ['rag', 'llm', 'analysis', 'phân tích', 'đánh giá']):
                print("🧠 ✅ RAG/LLM analysis detected in response!")
            else:
                print("⚠️  ⚠️  No RAG/LLM analysis detected in response")
                
        else:
            print(f"❌ ERROR: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.Timeout:
        print("⏰ TIMEOUT: Scan took too long (>5 minutes)")
        print("This might be normal for comprehensive scans")
        
    except requests.exceptions.ConnectionError:
        print("🔌 CONNECTION ERROR: Cannot connect to API")
        print("Make sure the backend is running on port 8002")
        
    except Exception as e:
        print(f"💥 UNEXPECTED ERROR: {str(e)}")
        print(f"Error type: {type(e).__name__}")

def test_api_health():
    """Test API health first"""
    print("🏥 Testing API Health...")
    
    try:
        health_url = "http://localhost:8002/api/chat-assistant/health"
        response = requests.get(health_url, timeout=10)
        
        if response.status_code == 200:
            print("✅ API is healthy and responding")
            return True
        else:
            print(f"⚠️  API health check failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ API health check failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("🚀 Starting Chatbot Scan Test")
    print("=" * 60)
    print()
    
    # Test API health first
    if test_api_health():
        print()
        # Run the scan test
        asyncio.run(test_chatbot_scan())
    else:
        print("❌ Cannot proceed - API is not healthy")
    
    print()
    print("🏁 Test completed!")
