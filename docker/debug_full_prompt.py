#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import ToolManager

def debug_full_prompt():
    config = LLMConfig(
        api_endpoint='http://llm-service:8000/generate',
        api_key='test-key',
        model='gpt-3.5-turbo',
        max_tokens=1000,
        temperature=0.7
    )

    tool_manager = ToolManager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)

    # Create the exact planning prompt that _generate_plan uses
    objective = "Find vulnerabilities in example.com and generate a security report"
    
    planning_prompt = f"""
You are an AI security expert. Break down the following high-level objective into a sequence of specific, actionable steps:

Objective: {objective}

Available tools: {', '.join(agent.tool_manager.tools.keys()) if agent.tool_manager else 'No tools available'}

Create a detailed plan with 3-7 steps. Each step should:
1. Be specific and actionable
2. Have a clear description of what needs to be done
3. Be achievable with the available tools
4. Follow a logical sequence for security analysis

Format your response as follows:
PLAN:
1. [Step Description]
   Type: [analysis/reconnaissance/exploitation/reporting]
   
2. [Step Description]
   Type: [analysis/reconnaissance/exploitation/reporting]
   
[Continue for all steps]

Example:
PLAN:
1. Perform OSINT reconnaissance on target.com
   Type: reconnaissance
   
2. Scan the target for open ports and services
   Type: reconnaissance
   
3. Analyze the web application for vulnerabilities
   Type: analysis
   
4. Attempt to exploit identified vulnerabilities
   Type: exploitation
   
5. Generate a comprehensive security report
   Type: reporting
"""
    
    print("Testing full planning prompt...")
    print("Prompt length:", len(planning_prompt))
    
    try:
        llm_response = agent._execute_with_custom_endpoint(planning_prompt)
        print("LLM Response Success:", llm_response["success"])
        print("LLM Response Content:")
        print(repr(llm_response["response"]))
        
        # Test plan parsing
        plan = agent._parse_plan_from_response(llm_response["response"])
        print("Parsed Plan:", plan)
        
    except Exception as e:
        print("Error:", e)
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_full_prompt()
