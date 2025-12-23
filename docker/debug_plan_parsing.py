#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import create_default_tool_manager

def debug_plan_parsing():
    """Debug the plan parsing logic."""
    
    config = LLMConfig(api_endpoint='http://llm-service:8000/generate', api_key='test-key')
    tool_manager = create_default_tool_manager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
    
    print("Testing plan parsing...")
    
    # Test response from LLM
    test_response = """PLAN:
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
    
    print("Test response:")
    print(test_response)
    print("\n" + "="*50)
    
    # Test the parsing
    plan = agent._parse_plan_from_response(test_response)
    
    print("Parsed plan:")
    print(f"Plan: {plan}")
    print(f"Number of steps: {len(plan) if plan else 0}")
    
    if plan:
        for i, step in enumerate(plan, 1):
            print(f"  Step {i}: {step}")
    
    return plan

if __name__ == "__main__":
    debug_plan_parsing()
