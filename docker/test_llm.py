#!/usr/bin/env python3

import requests
import json

def test_llm_service():
    """Test the LLM service directly."""
    
    url = "http://llm-service:8000/generate"
    
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [
            {
                "role": "user",
                "content": "Generate a plan for OSINT analysis"
            }
        ],
        "max_tokens": 1000
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Text: {response.text[:500]}...")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Response JSON: {json.dumps(data, indent=2)}")
        else:
            print(f"Error Response: {response.text}")
            
    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    test_llm_service()
