#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import ToolManager

def debug_plan_parsing():
    config = LLMConfig(
        api_endpoint='http://llm-service:8000/generate',
        api_key='test-key',
        model='gpt-3.5-turbo',
        max_tokens=1000,
        temperature=0.7
    )

    tool_manager = ToolManager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)

    # Test the LLM response directly
    planning_prompt = "Generate a plan for security analysis"
    
    try:
        llm_response = agent._execute_with_custom_endpoint(planning_prompt)
        print("LLM Response Success:", llm_response["success"])
        print("LLM Response Content:", llm_response["response"])
        
        # Test plan parsing
        plan = agent._parse_plan_from_response(llm_response["response"])
        print("Parsed Plan:", plan)
        
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    debug_plan_parsing()
