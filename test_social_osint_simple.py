"""
Simple Integration Test for SocialOSINTAgent

This test verifies the SocialOSINTAgent functionality without the full agent stack
to avoid dependency conflicts.
"""

import asyncio
import json
import logging
import sys
import os
from datetime import datetime

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from modules.social_osint_agent import SocialOSINTAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def test_social_osint_simple():
    """Test the SocialOSINTAgent functionality."""
    print("🚀 Testing SocialOSINTAgent Functionality")
    print("=" * 50)
    
    try:
        # Create agent
        agent = SocialOSINTAgent()
        print("✅ SocialOSINTAgent initialized successfully")
        
        # Test 1: Add target
        print("\n📋 Test 1: Adding OSINT target...")
        target_id = await agent.add_target(
            name="Simple Test User",
            email="simple@test.com",
            company="Test Corp",
            social_profiles={
                'twitter': '@simpletest',
                'linkedin': 'simple-test'
            }
        )
        print(f"✅ Target added: {target_id}")
        
        # Test 2: Collect data
        print("\n📡 Test 2: Collecting OSINT data...")
        collected = await agent.collect_data(target_id)
        print(f"✅ Collected {len(collected)} data items")
        
        # Show data sources
        sources = list(set(d.source.value for d in collected))
        print(f"   Sources: {sources}")
        
        # Test 3: Analyze target
        print("\n🧠 Test 3: Analyzing target...")
        analysis = await agent.analyze_target(target_id)
        print(f"✅ Analysis complete")
        print(f"   Sentiment score: {analysis.sentiment_score:.2f}")
        print(f"   Threat level: {analysis.threat_level.value}")
        print(f"   Key findings: {len(analysis.key_findings)}")
        print(f"   Recommendations: {len(analysis.recommendations)}")
        
        # Test 4: Password cracking
        print("\n🔐 Test 4: Testing password cracking...")
        test_hashes = [
            "5f4dcc3b5aa765d61d8327deb882cf99",  # 'password'
            "e99a18c428cb38d5f260853678922e03"   # 'abc123'
        ]
        
        crack_results = await agent.crack_passwords(target_id, test_hashes)
        cracked_count = sum(1 for r in crack_results if r['success'])
        print(f"✅ Cracked {cracked_count}/{len(test_hashes)} hashes")
        
        for i, result in enumerate(crack_results):
            if result['success']:
                print(f"   Hash {i+1}: {result['password']}")
        
        # Test 5: OSINT tools
        print("\n🛠️  Test 5: Running OSINT tools...")
        tool_results = await agent.run_osint_tools("simpletest.com")
        successful_tools = [tool for tool, result in tool_results.items() if result.get('success', False)]
        print(f"✅ Ran {len(tool_results)} tools, {len(successful_tools)} successful")
        
        for tool, result in tool_results.items():
            status = "✅" if result.get('success', False) else "❌"
            print(f"   {status} {tool}")
        
        # Test 6: Generate reports
        print("\n📄 Test 6: Generating reports...")
        
        for report_type in ['summary', 'detailed', 'threat']:
            report = await agent.generate_report(target_id, report_type)
            print(f"✅ {report_type.title()} report generated")
        
        # Test 7: Target management
        print("\n📊 Test 7: Target management...")
        
        # List targets
        targets = agent.list_targets()
        print(f"✅ Found {len(targets)} targets")
        
        # Get summary
        summary = await agent.get_target_summary(target_id)
        print(f"✅ Target summary:")
        print(f"   Data count: {summary['data_count']}")
        print(f"   Sources: {summary['sources']}")
        print(f"   Analysis complete: {summary['analysis_complete']}")
        print(f"   Threat level: {summary['threat_level']}")
        
        # Test 8: Ethical compliance
        print("\n⚖️  Test 8: Testing ethical compliance...")
        from modules.social_osint_agent import EthicalCompliance
        
        compliance = EthicalCompliance()
        
        # Test data minimization
        raw_data = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'ssn': '123-45-6789',
            'credit_card': '4111-1111-1111-1111'
        }
        
        minimized = compliance.minimize_data_collection(raw_data)
        assert 'ssn' not in minimized, "SSN should be removed"
        assert 'credit_card' not in minimized, "Credit card should be removed"
        assert 'name' in minimized, "Name should remain"
        print("✅ Data minimization working correctly")
        
        # Test 9: Security integration
        print("\n🔒 Test 9: Testing security integration...")
        from modules.social_osint_agent import SecuritySystemIntegration
        
        integration = SecuritySystemIntegration()
        
        # Test SIEM integration
        siem_result = await integration.send_to_siem(analysis)
        assert siem_result == True, "SIEM integration should succeed"
        print("✅ SIEM integration working")
        
        # Test SOAR integration
        soar_result = await integration.trigger_soar_playbook(
            analysis.threat_level, 
            {'name': 'Test Target'}
        )
        print(f"✅ SOAR integration: {'Triggered' if soar_result else 'Not triggered'}")
        
        # Test 10: Clean up
        print("\n🧹 Test 10: Cleaning up...")
        remove_result = await agent.remove_target(target_id)
        assert remove_result == True, "Target removal should succeed"
        print("✅ Target removed successfully")
        
        print("\n" + "=" * 50)
        print("🎉 All SocialOSINTAgent tests passed!")
        return True
        
    except Exception as e:
        print(f"\n💥 Test failed with error: {e}")
        logger.exception("Test error")
        return False


async def test_tool_manager_integration():
    """Test OSINT tools through tool manager."""
    print("\n🔧 Testing Tool Manager Integration...")
    print("-" * 50)
    
    try:
        # Import tool manager functions
        from tool_manager import (
            osint_add_target, osint_collect_data, osint_analyze_target,
            osint_crack_passwords, osint_run_tools, osint_generate_report,
            osint_list_targets, osint_get_target_summary, osint_remove_target
        )
        
        # Test adding target
        result = osint_add_target(
            name="Tool Manager Test",
            email="tm@test.com",
            social_profiles=json.dumps({'twitter': '@tmt'})
        )
        
        assert result['success'] == True, "Add target should succeed"
        target_id = result['target_id']
        print(f"✅ Tool manager add_target: {target_id}")
        
        # Test collecting data
        result = osint_collect_data(target_id)
        assert result['success'] == True, "Collect data should succeed"
        print(f"✅ Tool manager collect_data: {result['data_count']} items")
        
        # Test analysis
        result = osint_analyze_target(target_id)
        assert result['success'] == True, "Analyze target should succeed"
        print(f"✅ Tool manager analyze_target: {result['threat_level']} threat")
        
        # Test password cracking
        test_hashes = json.dumps(["5f4dcc3b5aa765d61d8327deb882cf99"])
        result = osint_crack_passwords(target_id, test_hashes)
        assert result['success'] == True, "Password cracking should succeed"
        print(f"✅ Tool manager crack_passwords: {result['success_rate']}")
        
        # Test running tools
        result = osint_run_tools("tmtest.com", json.dumps(['the_harvester']))
        assert result['success'] == True, "Run tools should succeed"
        print(f"✅ Tool manager run_tools: {result['success_rate']}")
        
        # Test report generation
        result = osint_generate_report(target_id, "summary")
        assert result['success'] == True, "Generate report should succeed"
        print("✅ Tool manager generate_report: success")
        
        # Test listing targets
        result = osint_list_targets()
        assert result['success'] == True, "List targets should succeed"
        print(f"✅ Tool manager list_targets: {result['target_count']} targets")
        
        # Test getting summary
        result = osint_get_target_summary(target_id)
        assert result['success'] == True, "Get summary should succeed"
        print(f"✅ Tool manager get_summary: {result['data_count']} data items")
        
        # Clean up
        result = osint_remove_target(target_id)
        assert result['success'] == True, "Remove target should succeed"
        print("✅ Tool manager remove_target: success")
        
        return True
        
    except Exception as e:
        print(f"❌ Tool manager integration test failed: {e}")
        logger.exception("Tool manager test error")
        return False


async def main():
    """Main test execution function."""
    print("SocialOSINTAgent Simple Test Suite")
    print("=" * 50)
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    # Run tests
    agent_success = await test_social_osint_simple()
    tool_manager_success = await test_tool_manager_integration()
    
    # Generate test report
    report = {
        'test_suite': 'SocialOSINTAgent Simple',
        'timestamp': datetime.now().isoformat(),
        'agent_test': agent_success,
        'tool_manager_test': tool_manager_success,
        'overall_success': agent_success and tool_manager_success
    }
    
    # Save test report
    with open('test_social_osint_simple_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📋 Test report saved to: test_social_osint_simple_report.json")
    
    if report['overall_success']:
        print("🎉 All tests passed! SocialOSINTAgent is working correctly.")
        return True
    else:
        print("⚠️  Some tests failed. Check the logs above.")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
