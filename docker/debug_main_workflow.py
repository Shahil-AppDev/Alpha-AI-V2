#!/usr/bin/env python3

import sys
sys.path.append('/app/src')

from main import AISecurityTool

def debug_main_workflow():
    """Debug the main application workflow step by step."""
    
    print("=== Debugging Main Application Workflow ===")
    
    try:
        # Initialize the tool
        print("1. Initializing AISecurityTool...")
        tool = AISecurityTool()
        print("✅ Initialization successful")
        
        # Test plan generation directly
        print("\n2. Testing plan generation...")
        plan_result = tool.agent._generate_plan("Perform OSINT on example.com")
        print(f"Plan generation success: {plan_result['success']}")
        if not plan_result['success']:
            print(f"Plan generation error: {plan_result.get('error', 'Unknown')}")
            return False
        else:
            print(f"Plan generated with {len(plan_result['plan'])} steps")
            for i, step in enumerate(plan_result['plan'], 1):
                print(f"  Step {i}: {step['description']}")
        
        # Test plan_and_execute with debugging
        print("\n3. Testing plan_and_execute workflow...")
        print("Calling plan_and_execute...")
        
        # Add debug logging to see what's happening
        result = tool.agent.plan_and_execute("Perform OSINT on example.com")
        
        print(f"plan_and_execute success: {result['success']}")
        if not result['success']:
            print(f"plan_and_execute error: {result.get('error', 'Unknown')}")
        else:
            print("✅ plan_and_execute successful")
        
        return result['success']
        
    except Exception as e:
        print(f"❌ Exception in workflow: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = debug_main_workflow()
    print(f"\n{'✅ Workflow successful' if success else '❌ Workflow failed'}")
