"""
Test script for the BlackArch Tool Manager integration.
Tests the complete workflow from tool registration to execution.
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

# Test only the core BlackArch components
from src.modules.blackarch_tool_manager import BlackArchToolManager, ToolCategory, ToolStatus


def test_blackarch_tool_manager():
    """Test the BlackArchToolManager independently."""
    print("=== Testing BlackArchToolManager ===")
    
    # Create tool manager
    tool_manager = BlackArchToolManager()
    
    # Test default tool registration
    print(f"✓ Default tools registered: {len(tool_manager.tools)}")
    
    # Test tool categories
    categories = tool_manager.get_tool_categories()
    print(f"✓ Tool categories: {list(categories.keys())}")
    
    # Test tool registration
    custom_tool_id = tool_manager.register_tool(
        "test_tool",
        ToolCategory.MISC,
        "Test tool for unit testing",
        "echo",
        {"default_options": "Hello World", "requires_target": False}
    )
    print(f"✓ Custom tool registered: {custom_tool_id}")
    
    # Test tool assignment
    if tool_manager.assign_tool(custom_tool_id, "test_agent"):
        print(f"✓ Tool assigned to agent successfully")
    else:
        print("✗ Tool assignment failed")
        return False
    
    # Test tool execution (using echo command for safety)
    result = tool_manager.execute_tool(custom_tool_id, None, "Hello from BlackArch Tool Manager")
    
    if result.get("success"):
        print(f"✓ Tool executed successfully")
        print(f"  Command: {' '.join(result.get('command', []))}")
        print(f"  Output: {result.get('stdout', '').strip()}")
    else:
        print(f"✗ Tool execution failed: {result.get('error')}")
        return False
    
    # Test tool status
    status = tool_manager.get_tool_status(custom_tool_id)
    if status and status.get("status") == "completed":
        print(f"✓ Tool status updated correctly: {status['status']}")
    else:
        print(f"✗ Tool status not updated correctly")
        return False
    
    # Test agent tools
    agent_tools = tool_manager.get_agent_tools("test_agent")
    if len(agent_tools) > 0:
        print(f"✓ Agent has {len(agent_tools)} assigned tools")
    else:
        print("✗ No tools found for agent")
        return False
    
    return True


def test_tool_categories():
    """Test tool categories and filtering."""
    print("\n=== Testing Tool Categories ===")
    
    tool_manager = BlackArchToolManager()
    
    # Test all categories
    all_categories = list(ToolCategory)
    print(f"✓ Available categories: {[cat.value for cat in all_categories]}")
    
    # Test filtering by category
    for category in [ToolCategory.SCANNING, ToolCategory.WEB_APPLICATION, ToolCategory.PASSWORD_ATTACKS]:
        tools = tool_manager.list_tools(category_filter=category)
        print(f"✓ {category.value} category: {len(tools)} tools")
        
        if len(tools) == 0:
            print(f"  Warning: No tools found in {category.value} category")
    
    # Test search functionality
    search_results = tool_manager.search_tools("scan")
    print(f"✓ Search for 'scan': {len(search_results)} results")
    
    search_results = tool_manager.search_tools("web")
    print(f"✓ Search for 'web': {len(search_results)} results")
    
    return True


def test_specific_tools():
    """Test specific BlackArch tools."""
    print("\n=== Testing Specific Tools ===")
    
    tool_manager = BlackArchToolManager()
    
    # Test nmap tool
    nmap_tools = [tool for tool in tool_manager.tools.values() if tool.name == "nmap"]
    if nmap_tools:
        nmap_tool = nmap_tools[0]
        print(f"✓ Found nmap tool: {nmap_tool.description}")
        
        # Test assignment
        if tool_manager.assign_tool(nmap_tool.tool_id, "test_agent"):
            print(f"✓ Nmap tool assigned successfully")
            
            # Test command building (without execution for safety)
            command = tool_manager._build_command(nmap_tool, "127.0.0.1", "-p 22,80,443")
            print(f"✓ Nmap command built: {' '.join(command)}")
        else:
            print("✗ Nmap tool assignment failed")
            return False
    else:
        print("✗ Nmap tool not found")
        return False
    
    # Test nikto tool
    nikto_tools = [tool for tool in tool_manager.tools.values() if tool.name == "nikto"]
    if nikto_tools:
        nikto_tool = nikto_tools[0]
        print(f"✓ Found nikto tool: {nikto_tool.description}")
        
        # Test command building
        command = tool_manager._build_command(nikto_tool, "http://example.com", "-o nikto_output.txt")
        print(f"✓ Nikto command built: {' '.join(command)}")
    else:
        print("✗ Nikto tool not found")
        return False
    
    # Test sqlmap tool
    sqlmap_tools = [tool for tool in tool_manager.tools.values() if tool.name == "sqlmap"]
    if sqlmap_tools:
        sqlmap_tool = sqlmap_tools[0]
        print(f"✓ Found sqlmap tool: {sqlmap_tool.description}")
        
        # Test command building
        command = tool_manager._build_command(sqlmap_tool, "http://example.com/test?id=1", "--batch --dbs")
        print(f"✓ SQLMap command built: {' '.join(command)}")
    else:
        print("✗ SQLMap tool not found")
        return False
    
    # Test hydra tool
    hydra_tools = [tool for tool in tool_manager.tools.values() if tool.name == "hydra"]
    if hydra_tools:
        hydra_tool = hydra_tools[0]
        print(f"✓ Found hydra tool: {hydra_tool.description}")
        
        # Test command building
        command = tool_manager._build_command(hydra_tool, "127.0.0.1", "-l admin -P /usr/share/wordlists/rockyou.txt ssh")
        print(f"✓ Hydra command built: {' '.join(command)}")
    else:
        print("✗ Hydra tool not found")
        return False
    
    return True


def test_error_handling():
    """Test error handling and edge cases."""
    print("\n=== Testing Error Handling ===")
    
    tool_manager = BlackArchToolManager()
    
    # Test invalid tool ID
    result = tool_manager.get_tool_status("invalid_tool_id")
    if result is None:
        print("✓ Invalid tool ID handled correctly")
    else:
        print("✗ Invalid tool ID not handled correctly")
        return False
    
    # Test tool execution without assignment
    available_tools = tool_manager.get_available_tools()
    if available_tools:
        tool_id = available_tools[0]
        result = tool_manager.execute_tool(tool_id, "127.0.0.1", "-p 80")
        
        if not result.get("success") and "not assigned" in result.get("error", ""):
            print("✓ Unassigned tool execution handled correctly")
        else:
            print("✗ Unassigned tool execution not handled correctly")
            return False
    
    # Test invalid category filter
    try:
        # This should not raise an exception but return empty results
        tools = tool_manager.list_tools(category_filter=ToolCategory.MISC)
        print(f"✓ Category filtering works: {len(tools)} tools in MISC category")
    except Exception as e:
        print(f"✗ Category filtering failed: {str(e)}")
        return False
    
    # Test search with no results
    results = tool_manager.search_tools("nonexistent_tool_xyz")
    if len(results) == 0:
        print("✓ Search with no results handled correctly")
    else:
        print("✗ Search with no results not handled correctly")
        return False
    
    return True


def test_update_mechanism():
    """Test the BlackArch tools update mechanism."""
    print("\n=== Testing Update Mechanism ===")
    
    tool_manager = BlackArchToolManager()
    
    # Test update function (this will likely fail on non-BlackArch systems, which is expected)
    result = tool_manager.update_blackarch_tools()
    
    # The result should either succeed (if on BlackArch) or fail gracefully
    if isinstance(result, dict) and "success" in result:
        if result.get("success"):
            print("✓ BlackArch tools update succeeded")
        else:
            print(f"✓ BlackArch tools update failed gracefully: {result.get('message', 'Unknown error')}")
    else:
        print("✗ Update mechanism returned invalid result")
        return False
    
    return True


def test_agent_integration():
    """Test agent integration scenarios."""
    print("\n=== Testing Agent Integration ===")
    
    tool_manager = BlackArchToolManager()
    
    # Create multiple agents and assign tools
    agents = ["agent_001", "agent_002", "agent_003"]
    
    for agent_id in agents:
        # Get available tools
        available_tools = tool_manager.get_available_tools()
        
        # Assign first available tool to each agent
        if available_tools:
            tool_id = available_tools[0]
            if tool_manager.assign_tool(tool_id, agent_id):
                print(f"✓ Assigned tool {tool_id} to {agent_id}")
            else:
                print(f"✗ Failed to assign tool to {agent_id}")
                return False
    
    # Check agent assignments
    for agent_id in agents:
        agent_tools = tool_manager.get_agent_tools(agent_id)
        if len(agent_tools) > 0:
            print(f"✓ Agent {agent_id} has {len(agent_tools)} tools")
        else:
            print(f"✗ Agent {agent_id} has no tools")
            return False
    
    # Test tool execution by different agents
    for agent_id in agents:
        agent_tools = tool_manager.get_agent_tools(agent_id)
        if agent_tools:
            tool_id = agent_tools[0]["tool_id"]
            tool = tool_manager.tools[tool_id]
            
            # Execute with echo command for safety
            if tool.command == "echo":
                result = tool_manager.execute_tool(tool_id, None, "Hello from agent")
                if result.get("success"):
                    print(f"✓ Agent {agent_id} executed tool successfully")
                else:
                    print(f"✗ Agent {agent_id} tool execution failed")
                    return False
    
    return True


def test_complete_workflow():
    """Test a complete workflow from tool registration to execution."""
    print("\n=== Testing Complete Workflow ===")
    
    tool_manager = BlackArchToolManager()
    
    # Step 1: Register a custom tool
    custom_tool_id = tool_manager.register_tool(
        "workflow_test_tool",
        ToolCategory.MISC,
        "Tool for workflow testing",
        "echo",
        {"default_options": "Workflow Test", "requires_target": False}
    )
    print(f"✓ Step 1: Custom tool registered - {custom_tool_id}")
    
    # Step 2: Assign tool to agent
    agent_id = "workflow_agent"
    if tool_manager.assign_tool(custom_tool_id, agent_id):
        print(f"✓ Step 2: Tool assigned to agent - {agent_id}")
    else:
        print("✗ Step 2: Tool assignment failed")
        return False
    
    # Step 3: Check tool status
    status = tool_manager.get_tool_status(custom_tool_id)
    if status and status.get("status") == "assigned":
        print("✓ Step 3: Tool status verified - assigned")
    else:
        print("✗ Step 3: Tool status incorrect")
        return False
    
    # Step 4: Execute tool
    result = tool_manager.execute_tool(custom_tool_id, None, "Complete Workflow Test")
    if result.get("success"):
        print("✓ Step 4: Tool executed successfully")
        print(f"  Output: {result.get('stdout', '').strip()}")
    else:
        print("✗ Step 4: Tool execution failed")
        return False
    
    # Step 5: Verify final status
    final_status = tool_manager.get_tool_status(custom_tool_id)
    if final_status and final_status.get("status") == "completed":
        print("✓ Step 5: Final status verified - completed")
    else:
        print("✗ Step 5: Final status incorrect")
        return False
    
    # Step 6: Check execution history
    if len(final_status.get("execution_history", [])) > 0:
        print("✓ Step 6: Execution history recorded")
    else:
        print("✗ Step 6: No execution history found")
        return False
    
    print("✓ Complete workflow test passed!")
    return True


def main():
    """Run all tests."""
    print("Starting BlackArch Tool Manager Integration Tests")
    print("=" * 60)
    
    tests = [
        ("BlackArchToolManager", test_blackarch_tool_manager),
        ("Tool Categories", test_tool_categories),
        ("Specific Tools", test_specific_tools),
        ("Error Handling", test_error_handling),
        ("Update Mechanism", test_update_mechanism),
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
        print("🎉 All tests passed! The BlackArch Tool Manager integration is working correctly.")
        print("\nThe following components have been successfully implemented:")
        print("  • BlackArchToolManager with tool registration and management")
        print("  • Tool categories and filtering system")
        print("  • Specific BlackArch tools (nmap, nikto, sqlmap, hydra)")
        print("  • Tool execution with subprocess and error handling")
        print("  • Agent assignment and task management")
        print("  • Update mechanism for BlackArch tools")
        print("  • Complete workflow from registration to execution")
        print("\nThe architecture is ready for integration with the AI agent orchestrator!")
    else:
        print("⚠️  Some tests failed. Please check the implementation.")
    
    return passed == total


if __name__ == "__main__":
    main()
