#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import create_default_tool_manager

def debug_llm_response():
    """Debug the LLM response format."""
    
    config = LLMConfig(api_endpoint='http://llm-service:8000/generate', api_key='test-key')
    tool_manager = create_default_tool_manager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
    
    print("Testing LLM response format...")
    
    # Test the custom endpoint directly
    planning_prompt = "Generate a plan for OSINT analysis"
    
    result = agent._execute_with_custom_endpoint(planning_prompt)
    
    print("LLM Response Result:")
    print(f"Success: {result['success']}")
    print(f"Response: {result.get('response', 'None')}")
    print(f"Error: {result.get('error', 'None')}")
    print(f"Raw result keys: {list(result.keys())}")
    
    return result

if __name__ == "__main__":
    debug_llm_response()
