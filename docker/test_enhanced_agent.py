#!/usr/bin/env python3
"""
Test script for the enhanced LLMAutonomousAgent with memory and planning capabilities.
"""

import sys
import os
sys.path.append('/app/src')

from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import ToolManager

def test_memory_functionality():
    """Test the memory functionality of the enhanced agent."""
    print("=== Testing Memory Functionality ===")
    
    # Initialize agent with ToolManager
    config = LLMConfig(
        api_endpoint="http://llm-service:8000/generate",
        api_key="test-key",
        model="gpt-3.5-turbo",
        max_tokens=1000,
        temperature=0.7
    )
    
    tool_manager = ToolManager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
    
    # Test adding to memory
    agent.add_to_memory({
        "type": "test_observation",
        "content": "Test memory entry for vulnerability scanning",
        "metadata": {"test": True}
    })
    
    print(f"Memory entries after adding test: {len(agent.memory)}")
    
    # Test relevant memory retrieval
    relevant_memory = agent.get_relevant_memory("scan for vulnerabilities", limit=5)
    print(f"Relevant memory entries found: {len(relevant_memory)}")
    
    for i, entry in enumerate(relevant_memory, 1):
        print(f"  {i}. [{entry['type']}] {entry['content'][:50]}...")
    
    return True

def test_plan_generation():
    """Test the plan generation functionality."""
    print("\n=== Testing Plan Generation ===")
    
    config = LLMConfig(
        api_endpoint="http://llm-service:8000/generate",
        api_key="test-key",
        model="gpt-3.5-turbo",
        max_tokens=1000,
        temperature=0.7
    )
    
    tool_manager = ToolManager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
    
    # Test plan generation
    objective = "Find vulnerabilities in example.com and generate a security report"
    plan_result = agent._generate_plan(objective)
    
    if plan_result["success"]:
        print(f"Plan generated successfully with {len(plan_result['plan'])} steps:")
        for i, step in enumerate(plan_result["plan"], 1):
            print(f"  {i}. {step['description']} ({step['type']})")
    else:
        print(f"Plan generation failed: {plan_result['error']}")
    
    return plan_result["success"]

def test_simple_task_execution():
    """Test simple task execution with memory."""
    print("\n=== Testing Simple Task Execution with Memory ===")
    
    config = LLMConfig(
        api_endpoint="http://llm-service:8000/generate",
        api_key="test-key",
        model="gpt-3.5-turbo",
        max_tokens=1000,
        temperature=0.7
    )
    
    tool_manager = ToolManager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
    
    # Execute a simple task
    task = "Analyze the following code for security vulnerabilities: import os; os.system(user_input)"
    result = agent.execute_task(task)
    
    print(f"Task execution success: {result['success']}")
    print(f"Memory entries after task: {result.get('memory_entries', 0)}")
    
    if result["success"]:
        print(f"Response: {result['response'][:200]}...")
    
    return result["success"]

def test_plan_and_execute():
    """Test the plan_and_execute functionality."""
    print("\n=== Testing Plan and Execute ===")
    
    config = LLMConfig(
        api_endpoint="http://llm-service:8000/generate",
        api_key="test-key",
        model="gpt-3.5-turbo",
        max_tokens=1000,
        temperature=0.7
    )
    
    tool_manager = ToolManager()
    agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
    
    # Test plan and execute with a simple objective
    objective = "Perform basic security analysis on example.com"
    result = agent.plan_and_execute(objective)
    
    print(f"Plan and execute success: {result['success']}")
    
    if result["success"]:
        print(f"Steps completed: {result['steps_completed']}")
        print(f"Memory entries: {result['memory_entries']}")
        print(f"Final summary: {result['final_summary'][:200]}...")
    else:
        print(f"Plan and execute failed: {result['error']}")
    
    return result["success"]

def main():
    """Run all tests."""
    print("Testing Enhanced LLMAutonomousAgent with Memory and Planning")
    print("=" * 70)
    
    tests = [
        ("Memory Functionality", test_memory_functionality),
        ("Plan Generation", test_plan_generation),
        ("Simple Task Execution", test_simple_task_execution),
        ("Plan and Execute", test_plan_and_execute)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"Error in {test_name}: {e}")
            results[test_name] = False
    
    print("\n" + "=" * 70)
    print("Test Results Summary:")
    for test_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {test_name}: {status}")
    
    total_tests = len(results)
    passed_tests = sum(results.values())
    print(f"\nOverall: {passed_tests}/{total_tests} tests passed")
    
    return passed_tests == total_tests

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
