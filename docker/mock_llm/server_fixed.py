#!/usr/bin/env python3
"""
Mock LLM service for testing purposes.
This simulates an LLM API endpoint at /generate
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import uuid
from datetime import datetime

class MockLLMHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/generate':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                request_data = json.loads(post_data.decode('utf-8'))
                
                # Check if this is a follow-up request with tool results
                messages = request_data.get("messages", [])
                is_followup = any("tool_result" in str(msg) or "last_tool_result" in str(msg) for msg in messages)
                
                # Mock response with tool call for testing
                if is_followup:
                    # This is a follow-up request after tool execution
                    if "osint" in str(messages).lower():
                        response = {
                            "id": str(uuid.uuid4()),
                            "object": "chat.completion",
                            "created": int(datetime.now().timestamp()),
                            "model": request_data.get("model", "gpt-3.5-turbo"),
                            "choices": [{
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": """Based on the OSINT search results for 'example.com', I can provide the following security analysis:

**OSINT Results Summary:**
- Query: example.com
- Status: Placeholder implementation
- Potential data sources identified: Google dorks, social media, public records, dark web

**Security Implications:**
1. **Domain Information**: The OSINT search would typically reveal:
   - Domain registration details
   - DNS records and subdomains
   - Historical ownership changes
   - Associated IP addresses

2. **Attack Surface**: Public sources may reveal:
   - Exposed subdomains
   - Third-party services
   - Employee information on social media
   - Public repositories

3. **Recommendations:**
   - Monitor domain registration changes
   - Review exposed subdomains for vulnerabilities
   - Implement social media policies
   - Regular security assessments of public-facing assets

This completes the OSINT analysis. No further tool calls are needed at this time."""
                                },
                                "finish_reason": "stop"
                            }],
                            "usage": {
                                "prompt_tokens": 15,
                                "completion_tokens": 25,
                                "total_tokens": 40
                            }
                        }
                    elif "scan" in str(messages).lower() or "network" in str(messages).lower():
                        response = {
                            "id": str(uuid.uuid4()),
                            "object": "chat.completion",
                            "created": int(datetime.now().timestamp()),
                            "model": request_data.get("model", "gpt-3.5-turbo"),
                            "choices": [{
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": """Based on the network scan results for 192.168.1.1, here's my security analysis:

**Network Scan Results Summary:**
- Target: 192.168.1.1
- Status: Scan completed successfully
- Host is alive and responding to ping
- Open ports identified with service detection

**Security Assessment:**
1. **Port Analysis**: The scan identified open ports and their associated services:
   - Each open port represents a potential attack vector
   - Service versions help identify potential vulnerabilities
   - Response times indicate network performance

2. **Service Detection**: Results show:
   - Running services and their configurations
   - Potential misconfigurations or default settings
   - Services that may require additional hardening

3. **Host Information**:
   - OS fingerprinting helps determine the target system
   - MAC address indicates local network presence
   - Hostname resolution provides additional context

4. **Security Recommendations**:
   - Close unnecessary open ports
   - Update services to latest versions
   - Implement proper firewall rules
   - Monitor for unusual network activity
   - Regular security scanning and patching

The network security assessment is complete. All findings have been documented for further analysis and remediation planning."""
                                },
                                "finish_reason": "stop"
                            }],
                            "usage": {
                                "prompt_tokens": 15,
                                "completion_tokens": 25,
                                "total_tokens": 40
                            }
                        }
                    else:
                        # Generic follow-up response
                        response = {
                            "id": str(uuid.uuid4()),
                            "object": "chat.completion",
                            "created": int(datetime.now().timestamp()),
                            "model": request_data.get("model", "gpt-3.5-turbo"),
                            "choices": [{
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": "I have received the tool execution results and completed the analysis. The task has been successfully processed with the help of the available security tools."
                                },
                                "finish_reason": "stop"
                            }],
                            "usage": {
                                "prompt_tokens": 15,
                                "completion_tokens": 20,
                                "total_tokens": 35
                            }
                        }
                elif "osint" in request_data.get("model", "").lower() or "search" in str(request_data).lower():
                    response = {
                        "id": str(uuid.uuid4()),
                        "object": "chat.completion",
                        "created": int(datetime.now().timestamp()),
                        "model": request_data.get("model", "gpt-3.5-turbo"),
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": """I'll help you perform an OSINT search for 'example.com'. Let me use the appropriate tool to gather this information.

ACTION: TOOL_CALL
TOOL_NAME: osint_search
ARGUMENTS: {"query": "example.com"}

I've initiated the OSINT search. The tool will gather information from various public sources including Google dorks, social media, public records, and potentially dark web sources. Once I receive the results, I'll analyze them for security implications and provide you with a comprehensive assessment."""
                            },
                            "finish_reason": "stop"
                        }],
                        "usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 20,
                            "total_tokens": 30
                        }
                    }
                elif "scan" in str(request_data).lower() or "network" in str(request_data).lower() or "ip" in str(request_data).lower():
                    response = {
                        "id": str(uuid.uuid4()),
                        "object": "chat.completion",
                        "created": int(datetime.now().timestamp()),
                        "model": request_data.get("model", "gpt-3.5-turbo"),
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": """I'll scan the IP address 192.168.1.1 for open ports and services to identify potential security vulnerabilities.

ACTION: TOOL_CALL
TOOL_NAME: network_scan
ARGUMENTS: {"target_ip": "192.168.1.1"}

The network scan will check for open ports, identify running services, perform OS fingerprinting, and look for potential vulnerabilities. Once I have the scan results, I'll provide you with a detailed analysis of the security posture of this target."""
                            },
                            "finish_reason": "stop"
                        }],
                        "usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 20,
                            "total_tokens": 30
                        }
                    }
                else:
                    # Default mock response
                    response = {
                        "id": str(uuid.uuid4()),
                        "object": "chat.completion",
                        "created": int(datetime.now().timestamp()),
                        "model": request_data.get("model", "gpt-3.5-turbo"),
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "This is a mock LLM response for security analysis. In a real implementation, this would connect to an actual LLM service."
                            },
                            "finish_reason": "stop"
                        }],
                        "usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 20,
                            "total_tokens": 30
                        }
                    }
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
                
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                error_response = {"error": str(e)}
                self.wfile.write(json.dumps(error_response).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        info = {
            "service": "Mock LLM Service",
            "endpoint": "/generate",
            "method": "POST"
        }
        self.wfile.write(json.dumps(info).encode('utf-8'))

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), MockLLMHandler)
    print("Mock LLM service running on port 8000")
    print("Endpoint: http://localhost:8000/generate")
    server.serve_forever()
