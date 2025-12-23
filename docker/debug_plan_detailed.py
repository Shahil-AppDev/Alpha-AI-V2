#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import ToolManager

def debug_plan_generation_detailed():
    config = LLMConfig(
        api_endpoint='http://llm-service:8000/generate',
        api_key='test-key',
        model='gpt-3.5-turbo',
        max_tokens=1000,
        temperature=0.7
    )

    tool_manager = ToolManager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)

    # Test the exact same objective as in the test
    objective = "Find vulnerabilities in example.com and generate a security report"
    
    print("Testing plan generation with objective:", objective)
    
    try:
        plan_result = agent._generate_plan(objective)
        print("Plan generation result:")
        print("Success:", plan_result["success"])
        if not plan_result["success"]:
            print("Error:", plan_result["error"])
        else:
            print("Plan steps:", len(plan_result["plan"]))
            for i, step in enumerate(plan_result["plan"], 1):
                print(f"  {i}. {step['description']} ({step['type']})")
        
    except Exception as e:
        print("Error:", e)
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_plan_generation_detailed()
