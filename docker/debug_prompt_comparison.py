#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import create_default_tool_manager

def debug_prompt_comparison():
    """Compare the prompts being sent in different scenarios."""
    
    config = LLMConfig(api_endpoint='http://llm-service:8000/generate', api_key='test-key')
    tool_manager = create_default_tool_manager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
    
    print("=== Debugging Prompt Comparison ===")
    
    # Test 1: Direct simple prompt (working)
    print("\n1. Testing direct simple prompt:")
    simple_prompt = "Generate a plan for OSINT analysis"
    print(f"Prompt: {simple_prompt}")
    
    result1 = agent._execute_with_custom_endpoint(simple_prompt)
    print(f"Success: {result1['success']}")
    if result1['success']:
        print(f"Response preview: {result1['response'][:200]}...")
    
    # Test 2: Full planning prompt from agent (failing)
    print("\n2. Testing full planning prompt:")
    
    # Get the actual planning prompt the agent uses
    planning_prompt = f"""
You are an AI security expert. Break down the following high-level objective into a sequence of specific, actionable steps:

Objective: Perform OSINT on example.com

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
   Type: reporting"""
    
    print(f"Prompt length: {len(planning_prompt)} characters")
    print(f"Prompt preview: {planning_prompt[:300]}...")
    
    result2 = agent._execute_with_custom_endpoint(planning_prompt)
    print(f"Success: {result2['success']}")
    if result2['success']:
        print(f"Response preview: {result2['response'][:200]}...")
        # Test parsing
        plan = agent._parse_plan_from_response(result2['response'])
        print(f"Parsed plan steps: {len(plan) if plan else 0}")
    else:
        print(f"Error: {result2.get('error', 'Unknown')}")
    
    # Test 3: Test the actual _generate_plan method
    print("\n3. Testing actual _generate_plan method:")
    result3 = agent._generate_plan("Perform OSINT on example.com")
    print(f"Success: {result3['success']}")
    if not result3['success']:
        print(f"Error: {result3.get('error', 'Unknown')}")
    else:
        print(f"Plan steps: {len(result3.get('plan', []))}")

if __name__ == "__main__":
    debug_prompt_comparison()
