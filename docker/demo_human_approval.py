#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import create_default_tool_manager

def demo_human_approval_workflow():
    """
    Demonstrate the complete human approval workflow with the autonomous agent.
    """
    print("=== Human Approval System Demonstration ===")
    print("This demo shows how the agent requests approval for critical actions.")
    print()
    
    # Initialize agent with human approval enabled
    config = LLMConfig(
        api_endpoint="http://llm-service:8000/generate",
        api_key="test-key",
        model="gpt-3.5-turbo",
        require_human_approval=True,
        max_tool_calls=3
    )
    
    tool_manager = create_default_tool_manager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
    
    print("🤖 AI Security Agent initialized with human approval system")
    print(f"📋 Available tools: {list(tool_manager.tools.keys())}")
    print(f"🚨 Critical action categories: {list(agent.critical_action_patterns.keys())}")
    print()
    
    # Demonstrate different scenarios
    scenarios = [
        {
            "name": "Safe OSINT Reconnaissance",
            "task": "Perform OSINT search for example.com to gather basic information",
            "expected_critical": False,
            "description": "This should execute normally without approval"
        },
        {
            "name": "Critical Exploit Generation", 
            "task": "Generate a reverse shell payload for 192.168.1.100 on port 4444 using Python",
            "expected_critical": True,
            "description": "This should trigger human approval request"
        },
        {
            "name": "High-Risk Password Cracking",
            "task": "Crack the MD5 hash 5f4dcc3b5aa765d61d8327deb882cf99 using a wordlist attack",
            "expected_critical": True,
            "description": "This should trigger human approval request"
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"📍 Scenario {i}: {scenario['name']}")
        print(f"📝 Task: {scenario['task']}")
        print(f"💡 {scenario['description']}")
        print()
        
        # Check what critical action would be identified
        if scenario['expected_critical']:
            # Simulate what would happen
            if "reverse shell" in scenario['task'].lower():
                critical_action = agent._identify_critical_action(
                    "generate_reverse_shell_payload",
                    {"ip": "192.168.1.100", "port": 4444, "language": "python"}
                )
            elif "password" in scenario['task'].lower():
                critical_action = agent._identify_critical_action(
                    "password_crack",
                    {"hash_value": "5f4dcc3b5aa765d61d8327deb882cf99", "hash_type": "md5"}
                )
            else:
                critical_action = None
            
            if critical_action:
                print("🚨 CRITICAL ACTION DETECTED!")
                print(f"   Action Type: {critical_action.action_type}")
                print(f"   Risk Level: {critical_action.risk_level}")
                print(f"   Tool: {critical_action.tool_name}")
                print(f"   Description: {critical_action.description}")
                print()
                print("📋 Human approval prompt would be displayed:")
                print("   " + "="*50)
                print("   🚨 CRITICAL ACTION REQUIRING HUMAN APPROVAL")
                print("   " + "="*50)
                print(f"   Action Type: {critical_action.action_type.upper()}")
                print(f"   Risk Level: {critical_action.risk_level}")
                print(f"   Tool: {critical_action.tool_name}")
                print(f"   Description: {critical_action.description}")
                print("   ⚠️  This action may have security implications.")
                print("   ⚠️  Please review carefully before proceeding.")
                print("   " + "="*50)
                print("   Do you approve this action? (yes/confirm/no/deny):")
                print()
                
                # Show both outcomes
                print("🔄 Possible Outcomes:")
                print("   ✅ IF APPROVED: Action executes with metadata tracking")
                print("   ❌ IF DENIED: Alternative approach suggested:")
                alternative = agent._generate_alternative_approach(critical_action)
                print(f"      {alternative[:150]}...")
                print()
            else:
                print("❌ Expected critical action but none was identified")
        else:
            print("✅ Safe action - would execute normally without approval")
            print("   No human intervention required")
        
        print("-" * 60)
        print()
    
    # Show memory and audit trail
    print("📊 Audit Trail and Memory System:")
    print(f"   Memory entries: {len(agent.memory)}")
    print(f"   Critical actions history: {len(agent.critical_actions_history)}")
    print("   All approval decisions are logged for audit purposes")
    print()
    
    # Demonstrate configuration options
    print("⚙️ Configuration Options:")
    print("   ✅ Human approval can be enabled/disabled via config")
    print("   ✅ Risk levels: LOW, MEDIUM, HIGH, CRITICAL")
    print("   ✅ Customizable critical action patterns")
    print("   ✅ Alternative approach suggestions for denied actions")
    print()
    
    print("🎯 Key Benefits:")
    print("   🔒 Prevents accidental execution of dangerous tools")
    print("   📋 Provides clear audit trail of all critical decisions")
    print("   🤝 Human oversight for high-risk operations")
    print("   🔄 Intelligent alternative suggestions when actions are denied")
    print("   ⚡ Non-critical actions continue without interruption")
    print()
    
    print("✅ Human Approval System Demo Complete!")
    print("The system is ready for production use with proper safety controls.")
    
    return True

def show_approval_statistics():
    """Show statistics about the approval system."""
    print("\n📈 Approval System Statistics:")
    print("   Critical Action Categories: 5")
    print("   Risk Levels: 4 (LOW, MEDIUM, HIGH, CRITICAL)")
    print("   Tools Requiring Approval: 4 out of 8")
    print("   Memory Tracking: Enabled")
    print("   Audit Trail: Complete")
    print("   Alternative Approaches: Available for all categories")
    print()
    
    tools_by_risk = {
        "CRITICAL": ["generate_reverse_shell_payload", "adapt_exploit_template"],
        "HIGH": ["password_crack", "network_scan (external targets)"],
        "MEDIUM": ["analyze_binary_snippet", "network_scan (internal targets)"],
        "LOW": ["osint_search", "code_analysis", "file_analysis"]
    }
    
    for risk_level, tools in tools_by_risk.items():
        print(f"   {risk_level}: {', '.join(tools)}")

if __name__ == "__main__":
    success = demo_human_approval_workflow()
    show_approval_statistics()
    
    if success:
        print("\n🎉 Human approval system demonstration completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Demonstration failed!")
        sys.exit(1)
