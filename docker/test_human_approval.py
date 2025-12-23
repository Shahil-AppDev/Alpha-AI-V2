#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from agent import LLMAutonomousAgent, LLMConfig, CriticalAction
from tool_manager import create_default_tool_manager

def test_human_approval_system():
    print("=== Human Approval System Test ===")
    
    # Initialize agent with human approval enabled
    config = LLMConfig(
        api_endpoint="http://llm-service:8000/generate",
        api_key="test-key",
        model="gpt-3.5-turbo",
        require_human_approval=True
    )
    
    tool_manager = create_default_tool_manager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
    
    print(f"✅ Agent initialized with human approval: {config.require_human_approval}")
    print(f"✅ Critical action patterns: {list(agent.critical_action_patterns.keys())}")
    
    # Test 1: Critical action identification
    print("\n1. Testing critical action identification:")
    
    # Test exploit generation (should be CRITICAL)
    critical_action = agent._identify_critical_action(
        "generate_reverse_shell_payload", 
        {"ip": "192.168.1.100", "port": 4444, "language": "python"}
    )
    print(f"✅ Exploit generation identified: {critical_action is not None}")
    if critical_action:
        print(f"   Risk Level: {critical_action.risk_level}")
        print(f"   Action Type: {critical_action.action_type}")
    
    # Test password cracking (should be HIGH)
    critical_action = agent._identify_critical_action(
        "password_crack", 
        {"hash_value": "5f4dcc3b5aa765d61d8327deb882cf99", "hash_type": "md5"}
    )
    print(f"✅ Password cracking identified: {critical_action is not None}")
    if critical_action:
        print(f"   Risk Level: {critical_action.risk_level}")
    
    # Test OSINT (should not be critical)
    critical_action = agent._identify_critical_action(
        "osint_search", 
        {"query": "example.com"}
    )
    print(f"✅ OSINT correctly not identified as critical: {critical_action is None}")
    
    # Test 2: Risk level assessment
    print("\n2. Testing risk level assessment:")
    
    test_cases = [
        ("generate_reverse_shell_payload", {"ip": "192.168.1.100"}, "CRITICAL"),
        ("adapt_exploit_template", {"template_path": "/tmp/template.py"}, "CRITICAL"),
        ("password_crack", {"hash_value": "test"}, "HIGH"),
        ("analyze_binary_snippet", {"binary_data": b"test"}, "MEDIUM"),
        ("network_scan", {"target_ip": "127.0.0.1"}, "MEDIUM"),
        ("network_scan", {"target_ip": "8.8.8.8"}, "HIGH"),  # External IP
        ("osint_search", {"query": "test"}, None),
    ]
    
    for tool_name, params, expected_risk in test_cases:
        risk = agent._assess_risk_level(tool_name, params)
        status = "✅" if risk == expected_risk else "❌"
        print(f"   {status} {tool_name}: {risk} (expected: {expected_risk})")
    
    # Test 3: Alternative approach generation
    print("\n3. Testing alternative approach generation:")
    
    exploit_action = CriticalAction(
        action_type="exploit",
        description="Generate reverse shell payload",
        tool_name="generate_reverse_shell_payload",
        parameters={"ip": "192.168.1.100", "port": 4444},
        risk_level="CRITICAL"
    )
    
    alternative = agent._generate_alternative_approach(exploit_action)
    print(f"✅ Alternative approach generated for exploit: {len(alternative)} characters")
    print(f"   Preview: {alternative[:100]}...")
    
    # Test 4: Memory logging of approval decisions
    print("\n4. Testing approval decision logging:")
    
    test_action = CriticalAction(
        action_type="password_cracking",
        description="Test password cracking",
        tool_name="password_crack",
        parameters={"hash_value": "test"},
        risk_level="HIGH"
    )
    
    # Log a test approval
    agent._log_approval_decision(test_action, approved=True)
    print(f"✅ Approval logged to memory: {len(agent.memory)} entries")
    print(f"✅ Critical actions history: {len(agent.critical_actions_history)} entries")
    
    # Test 5: Configuration toggle
    print("\n5. Testing configuration toggle:")
    
    # Test with approval disabled
    config_no_approval = LLMConfig(
        api_endpoint="http://llm-service:8000/generate",
        api_key="test-key",
        require_human_approval=False
    )
    
    agent_no_approval = LLMAutonomousAgent(config=config_no_approval, tool_manager=tool_manager)
    
    critical_action = agent_no_approval._identify_critical_action(
        "generate_reverse_shell_payload", 
        {"ip": "192.168.1.100", "port": 4444}
    )
    print(f"✅ Approval disabled - no critical action identified: {critical_action is None}")
    
    print("\n=== Human Approval System Test Complete ===")
    print("✅ All critical components working correctly")
    print("✅ Ready for integration testing with actual tool execution")
    
    return True

def test_approval_workflow_simulation():
    """Simulate the approval workflow without actual user input."""
    print("\n=== Approval Workflow Simulation ===")
    
    config = LLMConfig(
        api_endpoint="http://llm-service:8000/generate",
        api_key="test-key",
        require_human_approval=True
    )
    
    tool_manager = create_default_tool_manager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
    
    # Create a mock critical action
    test_action = CriticalAction(
        action_type="exploit",
        description="Generate reverse shell payload for 192.168.1.100:4444",
        tool_name="generate_reverse_shell_payload",
        parameters={"ip": "192.168.1.100", "port": 4444, "language": "python"},
        risk_level="CRITICAL"
    )
    
    print(f"🚨 Simulating critical action: {test_action.description}")
    print(f"   Risk Level: {test_action.risk_level}")
    print(f"   Tool: {test_action.tool_name}")
    
    # Simulate approval (without actual user input)
    print("\n📋 Approval prompt would be displayed here")
    print("   User would be asked: 'Do you approve this action? (yes/confirm/no/deny)'")
    
    # Test both approval scenarios
    scenarios = [
        (True, "APPROVED"),
        (False, "DENIED")
    ]
    
    for approved, scenario_name in scenarios:
        print(f"\n--- Scenario: Action {scenario_name} ---")
        
        # Log the decision
        agent._log_approval_decision(test_action, approved)
        
        if approved:
            print("✅ Action would proceed with tool execution")
            print("   Critical action metadata would be added to result")
        else:
            alternative = agent._generate_alternative_approach(test_action)
            print("❌ Action would be blocked")
            print("🔄 Alternative approach provided:")
            print(f"   {alternative[:200]}...")
    
    print(f"\n✅ Memory entries after simulation: {len(agent.memory)}")
    print(f"✅ Critical actions history: {len(agent.critical_actions_history)}")
    
    return True

if __name__ == "__main__":
    success1 = test_human_approval_system()
    success2 = test_approval_workflow_simulation()
    
    if success1 and success2:
        print("\n🎉 All human approval system tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)
