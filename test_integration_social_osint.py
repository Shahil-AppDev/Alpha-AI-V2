"""
Integration Test for SocialOSINTAgent with LLMAutonomousAgent

This test verifies that the SocialOSINTAgent is properly integrated with the
main LLMAutonomousAgent system and can be called through the tool manager.
"""

import asyncio
import json
import logging
import sys
import os
from datetime import datetime

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import create_default_tool_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def test_social_osint_integration():
    """Test the complete SocialOSINTAgent integration."""
    print("🚀 Testing SocialOSINTAgent Integration with LLMAutonomousAgent")
    print("=" * 70)
    
    try:
        # Create LLM configuration
        config = LLMConfig(
            api_endpoint="http://localhost:8000/v1",
            api_key="dummy-key",
            model="gpt-3.5-turbo",
            max_tokens=1000,
            temperature=0.7
        )
        
        # Create tool manager with OSINT tools
        tool_manager = create_default_tool_manager()
        
        # Create agent with all managers
        agent = LLMAutonomousAgent(
            config=config,
            tool_manager=tool_manager
        )
        
        print(f"✅ Agent initialized with {len(tool_manager.tools)} tools")
        
        # Check that OSINT tools are registered
        osint_tools = [name for name in tool_manager.tools.keys() if name.startswith('osint_')]
        print(f"✅ Found {len(osint_tools)} OSINT tools: {osint_tools}")
        
        # Test 1: Add OSINT target
        print("\n📋 Test 1: Adding OSINT target...")
        result = tool_manager.execute_tool(
            "osint_add_target",
            name="Integration Test User",
            email="integration@test.com",
            social_profiles=json.dumps({
                'twitter': '@integrationtest',
                'linkedin': 'integration-test'
            })
        )
        
        if result.success:
            target_id = result.result['target_id']
            print(f"✅ Target added successfully: {target_id}")
        else:
            print(f"❌ Failed to add target: {result.error_message}")
            return False
        
        # Test 2: Collect OSINT data
        print("\n📡 Test 2: Collecting OSINT data...")
        result = tool_manager.execute_tool(
            "osint_collect_data",
            target_id=target_id,
            sources=json.dumps(['social_media', 'public_records'])
        )
        
        if result.success:
            data_count = result.result['data_count']
            sources = result.result['sources']
            print(f"✅ Collected {data_count} data items from {len(sources)} sources")
        else:
            print(f"❌ Failed to collect data: {result.error_message}")
            return False
        
        # Test 3: Analyze target
        print("\n🧠 Test 3: Analyzing target...")
        result = tool_manager.execute_tool(
            "osint_analyze_target",
            target_id=target_id
        )
        
        if result.success:
            sentiment_score = result.result['sentiment_score']
            threat_level = result.result['threat_level']
            print(f"✅ Analysis complete - Sentiment: {sentiment_score:.2f}, Threat: {threat_level}")
        else:
            print(f"❌ Failed to analyze target: {result.error_message}")
            return False
        
        # Test 4: Run OSINT tools
        print("\n🛠️  Test 4: Running OSINT tools...")
        result = tool_manager.execute_tool(
            "osint_run_tools",
            target="integrationtest.com",
            tools=json.dumps(['the_harvester', 'sherlock'])
        )
        
        if result.success:
            tools_run = result.result['tools_run']
            success_rate = result.result['success_rate']
            print(f"✅ Ran {len(tools_run)} tools with {success_rate} success rate")
        else:
            print(f"❌ Failed to run OSINT tools: {result.error_message}")
            return False
        
        # Test 5: Generate report
        print("\n📄 Test 5: Generating OSINT report...")
        result = tool_manager.execute_tool(
            "osint_generate_report",
            target_id=target_id,
            report_type="summary"
        )
        
        if result.success:
            report_type = result.result['report_type']
            print(f"✅ {report_type.title()} report generated successfully")
        else:
            print(f"❌ Failed to generate report: {result.error_message}")
            return False
        
        # Test 6: Get target summary
        print("\n📊 Test 6: Getting target summary...")
        result = tool_manager.execute_tool(
            "osint_get_target_summary",
            target_id=target_id
        )
        
        if result.success:
            data_count = result.result['data_count']
            analysis_complete = result.result['analysis_complete']
            threat_level = result.result['threat_level']
            print(f"✅ Summary - Data: {data_count}, Analyzed: {analysis_complete}, Threat: {threat_level}")
        else:
            print(f"❌ Failed to get summary: {result.error_message}")
            return False
        
        # Test 7: List targets
        print("\n📋 Test 7: Listing all targets...")
        result = tool_manager.execute_tool("osint_list_targets")
        
        if result.success:
            target_count = result.result['target_count']
            print(f"✅ Found {target_count} targets in system")
        else:
            print(f"❌ Failed to list targets: {result.error_message}")
            return False
        
        # Test 8: Test password cracking
        print("\n🔐 Test 8: Testing password cracking...")
        test_hashes = json.dumps([
            "5f4dcc3b5aa765d61d8327deb882cf99",  # 'password'
            "e99a18c428cb38d5f260853678922e03"   # 'abc123'
        ])
        
        result = tool_manager.execute_tool(
            "osint_crack_passwords",
            target_id=target_id,
            password_hashes=test_hashes
        )
        
        if result.success:
            total_hashes = result.result['total_hashes']
            cracked_count = result.result['cracked_count']
            success_rate = result.result['success_rate']
            print(f"✅ Cracked {cracked_count}/{total_hashes} hashes ({success_rate})")
        else:
            print(f"❌ Failed to crack passwords: {result.error_message}")
            return False
        
        # Test 9: Clean up - Remove target
        print("\n🧹 Test 9: Cleaning up - Removing target...")
        result = tool_manager.execute_tool(
            "osint_remove_target",
            target_id=target_id
        )
        
        if result.success:
            print(f"✅ Target {target_id} removed successfully")
        else:
            print(f"❌ Failed to remove target: {result.error_message}")
            return False
        
        print("\n" + "=" * 70)
        print("🎉 All SocialOSINTAgent integration tests passed!")
        return True
        
    except Exception as e:
        print(f"\n💥 Integration test failed with error: {e}")
        logger.exception("Integration test error")
        return False


async def test_agent_direct_methods():
    """Test calling OSINT methods directly on the agent."""
    print("\n🔧 Testing Direct Agent OSINT Methods...")
    print("-" * 50)
    
    try:
        # Create agent
        config = LLMConfig(
            api_endpoint="http://localhost:8000/v1",
            api_key="dummy-key"
        )
        
        tool_manager = create_default_tool_manager()
        agent = LLMAutonomousAgent(config=config, tool_manager=tool_manager)
        
        # Test direct method calls
        result = await agent.osint_add_target(
            name="Direct Test User",
            email="direct@test.com"
        )
        
        if result['success']:
            target_id = result['target_id']
            print(f"✅ Direct add_target: {target_id}")
            
            # Test data collection
            data_result = await agent.osint_collect_data(target_id)
            if data_result['success']:
                print(f"✅ Direct collect_data: {data_result['data_count']} items")
            
            # Test analysis
            analysis_result = await agent.osint_analyze_target(target_id)
            if analysis_result['success']:
                print(f"✅ Direct analyze_target: {analysis_result['threat_level']} threat")
            
            # Clean up
            await agent.osint_remove_target(target_id)
            print("✅ Direct remove_target: success")
            
            return True
        else:
            print(f"❌ Direct method call failed: {result['error']}")
            return False
            
    except Exception as e:
        print(f"❌ Direct method test failed: {e}")
        return False


async def main():
    """Main test execution function."""
    print("SocialOSINTAgent Integration Test Suite")
    print("=" * 70)
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    # Run integration tests
    integration_success = await test_social_osint_integration()
    direct_success = await test_agent_direct_methods()
    
    # Generate test report
    report = {
        'test_suite': 'SocialOSINTAgent Integration',
        'timestamp': datetime.now().isoformat(),
        'integration_test': integration_success,
        'direct_methods_test': direct_success,
        'overall_success': integration_success and direct_success
    }
    
    # Save test report
    with open('test_integration_social_osint_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📋 Integration report saved to: test_integration_social_osint_report.json")
    
    if report['overall_success']:
        print("🎉 All integration tests passed! SocialOSINTAgent is fully integrated.")
        return True
    else:
        print("⚠️  Some integration tests failed. Check the logs above.")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
