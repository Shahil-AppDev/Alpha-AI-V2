#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import create_default_tool_manager

def debug_plan_generation():
    """Debug the plan generation issue."""
    
    config = LLMConfig(api_endpoint='http://llm-service:8000/generate', api_key='test-key')
    tool_manager = create_default_tool_manager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
    
    print("Testing plan generation...")
    
    # Test plan generation
    result = agent._generate_plan('Perform OSINT on example.com')
    
    print("Plan generation result:")
    print(f"Success: {result['success']}")
    print(f"Error: {result.get('error', 'None')}")
    print(f"Plan: {result.get('plan', 'None')}")
    print(f"Raw response: {result.get('raw_response', 'None')[:200]}...")
    
    return result

if __name__ == "__main__":
    debug_plan_generation()
