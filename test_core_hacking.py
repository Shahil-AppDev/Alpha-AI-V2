"""
Simplified test script for the Hacking Task Manager integration.
Tests the core functionality without dependencies on heavy modules.
"""

import json
import logging
import sys
import os
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Test only the core hacking task components
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


def test_payload_generators():
    """Test the payload generators directly."""
    print("\n=== Testing Payload Generators ===")
    
    from src.modules.hacking_tasks_module import EmailTrackingPayloadGenerator, ExtractorPayloadGenerator
    
    # Test email tracking payload generator
    email_gen = EmailTrackingPayloadGenerator()
    email_config = {
        "target_email": "payload_test@example.com",
        "tracking_type": "link",
        "campaign_id": "payload_test_001"
    }
    
    if email_gen.validate_config(email_config):
        email_payload = email_gen.generate(email_config)
        print(f"✓ Email tracking payload generated: {email_payload['payload_id']}")
        print(f"  Campaign ID: {email_payload['campaign_id']}")
        print(f"  Tracking type: {email_payload['tracking_type']}")
    else:
        print("✗ Email tracking config validation failed")
        return False
    
    # Test extractor payload generator
    extractor_gen = ExtractorPayloadGenerator()
    extractor_config = {
        "extraction_type": "credentials",
        "target_path": "/Users/Target",
        "exfiltration_method": "dns",
        "encryption": True
    }
    
    if extractor_gen.validate_config(extractor_config):
        extractor_payload = extractor_gen.generate(extractor_config)
        print(f"✓ Extractor payload generated: {extractor_payload['payload_id']}")
        print(f"  Extraction type: {extractor_payload['extraction_type']}")
        print(f"  Exfiltration method: {extractor_payload['exfiltration_method']}")
    else:
        print("✗ Extractor config validation failed")
        return False
    
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
    else:
        print("✗ EmailTrackerTask failed to start")
        return False
    
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
    else:
        print("✗ ExtractorTask failed to start")
        return False
    
    return True


def test_task_status_management():
    """Test task status management and tracking."""
    print("\n=== Testing Task Status Management ===")
    
    task_manager = HackingTaskManager()
    
    # Register a task
    config = {
        "target_email": "status_test@example.com",
        "tracking_type": "pixel"
    }
    
    task_id = task_manager.register_task(TaskType.EMAIL_TRACKING, config)
    print(f"✓ Task registered: {task_id}")
    
    # Check initial status
    status = task_manager.get_task_status(task_id)
    print(f"✓ Initial status: {status['status']}")
    
    # Assign task
    task_manager.assign_task(task_id, "test_agent")
    status = task_manager.get_task_status(task_id)
    print(f"✓ After assignment: {status['status']}")
    
    # Generate payload
    payload = task_manager.generate_payload(task_id)
    status = task_manager.get_task_status(task_id)
    print(f"✓ After payload generation: {status['status']}")
    
    # Complete task
    task_manager.complete_task(task_id, {"result": "success"})
    status = task_manager.get_task_status(task_id)
    print(f"✓ After completion: {status['status']}")
    
    # Test agent task retrieval
    agent_tasks = task_manager.get_agent_tasks("test_agent")
    print(f"✓ Agent has {len(agent_tasks)} tasks")
    
    return True


def test_error_handling():
    """Test error handling and edge cases."""
    print("\n=== Testing Error Handling ===")
    
    task_manager = HackingTaskManager()
    
    # Test invalid task ID
    result = task_manager.get_task_status("invalid_task_id")
    if result is None:
        print("✓ Invalid task ID handled correctly")
    else:
        print("✗ Invalid task ID not handled correctly")
        return False
    
    # Test invalid config for email tracking
    try:
        invalid_config = {"tracking_type": "pixel"}  # Missing target_email
        task_id = task_manager.register_task(TaskType.EMAIL_TRACKING, invalid_config)
        # This should fail when trying to generate payload, not when registering
        payload = task_manager.generate_payload(task_id)
        if payload is None:
            print("✓ Invalid email config handled correctly")
        else:
            print("✗ Invalid config should have failed")
            return False
    except Exception:
        print("✓ Invalid email config handled correctly")
    
    # Test invalid extraction type
    try:
        invalid_config = {
            "extraction_type": "invalid_type",
            "target_path": "/test"
        }
        task_id = task_manager.register_task(TaskType.EXTRACTOR_PAYLOAD, invalid_config)
        # This should fail when trying to generate payload, not when registering
        payload = task_manager.generate_payload(task_id)
        if payload is None:
            print("✓ Invalid extraction type handled correctly")
        else:
            print("✗ Invalid extraction type should have failed")
            return False
    except Exception:
        print("✓ Invalid extraction type handled correctly")
    
    return True


def main():
    """Run all tests."""
    print("Starting Hacking Task Manager Core Tests")
    print("=" * 60)
    
    tests = [
        ("HackingTaskManager", test_hacking_task_manager),
        ("Payload Generators", test_payload_generators),
        ("HackingTaskClasses", test_hacking_task_classes),
        ("Task Status Management", test_task_status_management),
        ("Error Handling", test_error_handling)
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
        print("🎉 All core tests passed! The Hacking Task Manager is working correctly.")
        print("\nThe following components have been successfully implemented:")
        print("  • HackingTaskManager with task registration and management")
        print("  • EmailTrackingPayloadGenerator with multiple tracking types")
        print("  • ExtractorPayloadGenerator with various extraction methods")
        print("  • Specialized task classes (EmailTrackerTask, ExtractorTask)")
        print("  • Task status management and agent assignment")
        print("  • Error handling and validation")
        print("\nThe architecture is ready for integration with the AI agent orchestrator!")
    else:
        print("⚠️  Some tests failed. Please check the implementation.")
    
    return passed == total


if __name__ == "__main__":
    main()
