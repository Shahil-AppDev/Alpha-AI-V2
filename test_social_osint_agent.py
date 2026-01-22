"""
Test Suite for SocialOSINTAgent

This comprehensive test suite validates the functionality of the Social and OSINT
Engineering Agent, including data collection, processing, analysis, password cracking,
and reporting capabilities.
"""

import asyncio
import json
import logging
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, Any

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from modules.social_osint_agent import (
    SocialOSINTAgent, OSINTTarget, CollectedData, AnalysisResult,
    DataSource, DataStatus, ThreatLevel, EthicalCompliance,
    SecuritySystemIntegration, PasswordCracker, OSINTToolManager
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SocialOSINTAgentTestSuite:
    """Comprehensive test suite for SocialOSINTAgent."""
    
    def __init__(self):
        self.agent = SocialOSINTAgent()
        self.test_results = []
        self.test_targets = []
    
    async def run_all_tests(self) -> bool:
        """Run all tests and return overall success status."""
        print("🚀 Starting SocialOSINTAgent Test Suite")
        print("=" * 60)
        
        test_methods = [
            self.test_agent_initialization,
            self.test_target_management,
            self.test_data_collection,
            self.test_data_processing,
            self.test_sentiment_analysis,
            self.test_password_cracking,
            self.test_osint_tools,
            self.test_report_generation,
            self.test_ethical_compliance,
            self.test_security_integration,
            self.test_complete_workflow,
            self.test_error_handling
        ]
        
        passed = 0
        total = len(test_methods)
        
        for test_method in test_methods:
            try:
                result = await test_method()
                if result:
                    passed += 1
                    print(f"✅ {test_method.__name__} PASSED")
                else:
                    print(f"❌ {test_method.__name__} FAILED")
                self.test_results.append({
                    'test': test_method.__name__,
                    'passed': result,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                print(f"💥 {test_method.__name__} ERROR: {e}")
                self.test_results.append({
                    'test': test_method.__name__,
                    'passed': False,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        print("\n" + "=" * 60)
        print(f"📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed!")
            return True
        else:
            print("⚠️  Some tests failed. Check the logs above.")
            return False
    
    async def test_agent_initialization(self) -> bool:
        """Test agent initialization and components."""
        print("\n🔧 Testing Agent Initialization...")
        
        # Check agent components
        assert hasattr(self.agent, 'collectors'), "Agent missing collectors"
        assert hasattr(self.agent, 'processor'), "Agent missing processor"
        assert hasattr(self.agent, 'password_cracker'), "Agent missing password_cracker"
        assert hasattr(self.agent, 'tool_manager'), "Agent missing tool_manager"
        assert hasattr(self.agent, 'report_generator'), "Agent missing report_generator"
        
        # Check collectors
        assert 'social_media' in self.agent.collectors, "Missing social media collector"
        assert 'public_records' in self.agent.collectors, "Missing public records collector"
        
        # Check data structures
        assert isinstance(self.agent.targets, dict), "Targets should be a dict"
        assert isinstance(self.agent.collected_data, dict), "Collected data should be a dict"
        assert isinstance(self.agent.analyses, dict), "Analyses should be a dict"
        
        print("   ✓ Agent components initialized correctly")
        return True
    
    async def test_target_management(self) -> bool:
        """Test target creation and management."""
        print("\n🎯 Testing Target Management...")
        
        # Test adding a target
        target_id = await self.agent.add_target(
            name="Test User",
            email="test@example.com",
            company="Test Corp",
            social_profiles={
                'twitter': '@testuser',
                'linkedin': 'test-user'
            }
        )
        
        assert target_id in self.agent.targets, "Target not added to agent"
        target = self.agent.targets[target_id]
        assert target.name == "Test User", "Target name incorrect"
        assert target.email == "test@example.com", "Target email incorrect"
        assert target.company == "Test Corp", "Target company incorrect"
        
        self.test_targets.append(target_id)
        
        # Test listing targets
        targets = self.agent.list_targets()
        assert len(targets) >= 1, "No targets found"
        assert any(t['id'] == target_id for t in targets), "Target not in list"
        
        # Test target summary
        summary = await self.agent.get_target_summary(target_id)
        assert summary['target']['name'] == "Test User", "Summary name incorrect"
        assert summary['data_count'] == 0, "Initial data count should be 0"
        
        # Test removing target
        remove_result = await self.agent.remove_target(target_id)
        assert remove_result, "Target removal failed"
        assert target_id not in self.agent.targets, "Target still exists after removal"
        
        print("   ✓ Target management working correctly")
        return True
    
    async def test_data_collection(self) -> bool:
        """Test data collection from various sources."""
        print("\n📡 Testing Data Collection...")
        
        # Add a test target
        target_id = await self.agent.add_target(
            name="Collection Test",
            email="collect@example.com",
            social_profiles={'twitter': '@collecttest', 'linkedin': 'collect-test'}
        )
        self.test_targets.append(target_id)
        
        # Test data collection
        collected = await self.agent.collect_data(target_id)
        assert len(collected) > 0, "No data collected"
        
        # Check collected data structure
        for data in collected:
            assert isinstance(data, CollectedData), "Invalid data type"
            assert data.target_id == target_id, "Data target ID mismatch"
            assert data.source in DataSource, "Invalid data source"
            assert data.status == DataStatus.PROCESSED, "Data not processed"
            assert data.confidence_score >= 0, "Invalid confidence score"
        
        # Test specific collectors
        social_media_data = [d for d in collected if d.source == DataSource.SOCIAL_MEDIA]
        public_records_data = [d for d in collected if d.source == DataSource.PUBLIC_RECORDS]
        
        assert len(social_media_data) > 0, "No social media data collected"
        assert len(public_records_data) > 0, "No public records data collected"
        
        print(f"   ✓ Collected {len(collected)} data items from {len(set(d.source for d in collected))} sources")
        return True
    
    async def test_data_processing(self) -> bool:
        """Test data processing and NLP analysis."""
        print("\n🧠 Testing Data Processing...")
        
        # Get collected data from previous test
        if not self.test_targets:
            target_id = await self.agent.add_target(
                name="Processing Test",
                email="process@example.com",
                social_profiles={'twitter': '@processtest'}
            )
            self.test_targets.append(target_id)
            collected = await self.agent.collect_data(target_id)
        else:
            target_id = self.test_targets[-1]
            collected = self.agent.collected_data[target_id]
        
        # Check processed data
        for data in collected:
            assert data.status == DataStatus.PROCESSED, "Data not processed"
            assert isinstance(data.processed_data, dict), "Processed data should be dict"
            
            # Check NLP components
            if 'sentiment' in data.processed_data:
                sentiment = data.processed_data['sentiment']
                assert 'sentiment' in sentiment, "Missing sentiment score"
                assert 'confidence' in sentiment, "Missing sentiment confidence"
                assert -1 <= sentiment['sentiment'] <= 1, "Invalid sentiment range"
            
            if 'entities' in data.processed_data:
                entities = data.processed_data['entities']
                assert isinstance(entities, dict), "Entities should be dict"
                assert 'emails' in entities, "Missing email entities"
                assert 'phones' in entities, "Missing phone entities"
            
            if 'keywords' in data.processed_data:
                keywords = data.processed_data['keywords']
                assert 'keywords' in keywords, "Missing keywords"
                assert 'total_words' in keywords, "Missing word count"
                assert isinstance(keywords['keywords'], dict), "Keywords should be dict"
        
        print("   ✓ Data processing and NLP analysis working correctly")
        return True
    
    async def test_sentiment_analysis(self) -> bool:
        """Test sentiment analysis functionality."""
        print("\n💭 Testing Sentiment Analysis...")
        
        # Test sentiment analysis directly
        processor = self.agent.processor
        
        # Test positive text
        positive_text = "I love this amazing project! It's fantastic and great!"
        positive_result = processor._analyze_sentiment(positive_text)
        assert positive_result['sentiment'] > 0, "Positive text should have positive sentiment"
        assert positive_result['positive_words'] > 0, "Should detect positive words"
        
        # Test negative text
        negative_text = "This is terrible and awful. I hate it, it's the worst!"
        negative_result = processor._analyze_sentiment(negative_text)
        assert negative_result['sentiment'] < 0, "Negative text should have negative sentiment"
        assert negative_result['negative_words'] > 0, "Should detect negative words"
        
        # Test neutral text
        neutral_text = "This is a document about software development."
        neutral_result = processor._analyze_sentiment(neutral_text)
        assert abs(neutral_result['sentiment']) < 0.5, "Neutral text should have neutral sentiment"
        
        print("   ✓ Sentiment analysis working correctly")
        return True
    
    async def test_password_cracking(self) -> bool:
        """Test password cracking integration."""
        print("\n🔐 Testing Password Cracking...")
        
        cracker = PasswordCracker()
        
        # Test with known MD5 hash (password)
        test_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        result = await cracker.crack_password(test_hash, 'md5', 'dictionary')
        
        assert 'success' in result, "Missing success field"
        assert 'password' in result, "Missing password field"
        assert 'method' in result, "Missing method field"
        assert 'time_taken' in result, "Missing time taken field"
        assert 'attempts' in result, "Missing attempts field"
        
        if result['success']:
            assert result['password'] is not None, "Password should not be None on success"
            print(f"   ✓ Successfully cracked password: {result['password']}")
        else:
            print("   ✓ Password cracking simulation completed (expected for demo)")
        
        # Test with unknown hash
        unknown_hash = "unknown_hash_value_12345"
        result2 = await cracker.crack_password(unknown_hash, 'md5', 'dictionary')
        assert result2['success'] == False, "Unknown hash should not crack"
        
        print("   ✓ Password cracking integration working correctly")
        return True
    
    async def test_osint_tools(self) -> bool:
        """Test OSINT tool integrations."""
        print("\n🛠️  Testing OSINT Tools...")
        
        tool_manager = OSINTToolManager()
        
        # Test available tools
        assert 'the_harvester' in tool_manager.tools, "Missing theHarvester"
        assert 'maltego' in tool_manager.tools, "Missing Maltego"
        assert 'recon-ng' in tool_manager.tools, "Missing Recon-ng"
        assert 'spiderfoot' in tool_manager.tools, "Missing SpiderFoot"
        assert 'sherlock' in tool_manager.tools, "Missing Sherlock"
        
        # Test running tools
        test_target = "example.com"
        tools_to_test = ['the_harvester', 'sherlock']
        
        for tool in tools_to_test:
            result = await tool_manager.run_tool(tool, test_target)
            assert 'success' in result, f"{tool} missing success field"
            assert 'results' in result, f"{tool} missing results field"
            
            if result['success']:
                print(f"   ✓ {tool} executed successfully")
            else:
                print(f"   ⚠ {tool} simulation completed")
        
        # Test invalid tool
        invalid_result = await tool_manager.run_tool('invalid_tool', test_target)
        assert invalid_result['success'] == False, "Invalid tool should fail"
        
        print("   ✓ OSINT tool integrations working correctly")
        return True
    
    async def test_report_generation(self) -> bool:
        """Test report generation functionality."""
        print("\n📄 Testing Report Generation...")
        
        # Use existing target or create new one
        if not self.test_targets:
            target_id = await self.agent.add_target(
                name="Report Test",
                email="report@example.com",
                company="Report Corp"
            )
            self.test_targets.append(target_id)
            await self.agent.collect_data(target_id)
            await self.agent.analyze_target(target_id)
        
        target_id = self.test_targets[-1]
        
        # Test different report types
        report_types = ['summary', 'detailed', 'threat']
        
        for report_type in report_types:
            try:
                report = await self.agent.generate_report(target_id, report_type)
                
                assert 'report_type' in report, "Missing report type"
                assert report['report_type'] == report_type, "Report type mismatch"
                assert 'target' in report, "Missing target information"
                
                if report_type == 'summary':
                    assert 'data_summary' in report, "Missing data summary"
                    assert 'key_findings' in report, "Missing key findings"
                elif report_type == 'detailed':
                    assert 'collected_data' in report, "Missing collected data"
                    assert 'analysis' in report, "Missing analysis"
                elif report_type == 'threat':
                    assert 'threat_assessment' in report, "Missing threat assessment"
                    assert 'recommendations' in report, "Missing recommendations"
                
                print(f"   ✓ {report_type} report generated successfully")
                
            except Exception as e:
                print(f"   ⚠ {report_type} report generation issue: {e}")
                return False
        
        print("   ✓ Report generation working correctly")
        return True
    
    async def test_ethical_compliance(self) -> bool:
        """Test ethical and privacy compliance mechanisms."""
        print("\n⚖️  Testing Ethical Compliance...")
        
        compliance = EthicalCompliance()
        
        # Test consent validation
        target = OSINTTarget(
            target_id="test",
            name="Test User",
            email="test@example.com"
        )
        
        # Should fail without consent
        assert compliance.validate_collection(target, [DataSource.SOCIAL_MEDIA]) == False, "Should fail without consent"
        
        # Test public source validation
        assert compliance._is_public_source(DataSource.SOCIAL_MEDIA) == True, "Social media should be public"
        assert compliance._is_public_source(DataSource.DARK_WEB) == False, "Dark web should not be public"
        
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
        assert 'email' in minimized, "Email should remain"
        
        # Test data retention
        old_data = CollectedData(
            data_id="old",
            target_id="test",
            source=DataSource.SOCIAL_MEDIA,
            raw_data={}
        )
        old_data.collected_at = datetime.now() - timedelta(days=40)
        
        assert compliance.should_retain_data(old_data) == False, "Old data should not be retained"
        
        print("   ✓ Ethical compliance mechanisms working correctly")
        return True
    
    async def test_security_integration(self) -> bool:
        """Test security system integrations."""
        print("\n🔒 Testing Security System Integration...")
        
        integration = SecuritySystemIntegration()
        
        # Test SIEM integration
        analysis = AnalysisResult(
            result_id="test",
            target_id="test",
            data_ids=[],
            sentiment_score=0.0,
            threat_level=ThreatLevel.MEDIUM,
            key_findings=[],
            recommendations=[]
        )
        
        siem_result = await integration.send_to_siem(analysis)
        assert siem_result == True, "SIEM integration should succeed"
        
        # Test SOAR integration
        soar_result = await integration.trigger_soar_playbook(
            ThreatLevel.HIGH, 
            {'name': 'Test Target'}
        )
        assert soar_result == True, "SOAR playbook should trigger for high threat"
        
        # Test threat intelligence
        target = OSINTTarget(
            target_id="test",
            name="Test User",
            email="test@example.com"
        )
        
        threat_data = await integration.enrich_with_threat_intel(target)
        assert 'threat_indicators' in threat_data, "Missing threat indicators"
        assert 'known_associations' in threat_data, "Missing known associations"
        assert 'risk_score' in threat_data, "Missing risk score"
        
        print("   ✓ Security system integrations working correctly")
        return True
    
    async def test_complete_workflow(self) -> bool:
        """Test complete OSINT workflow."""
        print("\n🔄 Testing Complete Workflow...")
        
        # Step 1: Add target
        target_id = await self.agent.add_target(
            name="Workflow Test",
            email="workflow@example.com",
            company="Workflow Corp",
            social_profiles={
                'twitter': '@workflowtest',
                'linkedin': 'workflow-test'
            }
        )
        
        # Step 2: Collect data
        collected = await self.agent.collect_data(target_id)
        assert len(collected) > 0, "No data collected in workflow"
        
        # Step 3: Analyze target
        analysis = await self.agent.analyze_target(target_id)
        assert analysis is not None, "Analysis failed in workflow"
        assert analysis.threat_level in ThreatLevel, "Invalid threat level"
        
        # Step 4: Run OSINT tools
        tool_results = await self.agent.run_osint_tools("workflowtest.com")
        assert len(tool_results) > 0, "No tool results in workflow"
        
        # Step 5: Generate reports
        summary_report = await self.agent.generate_report(target_id, 'summary')
        detailed_report = await self.agent.generate_report(target_id, 'detailed')
        
        assert summary_report is not None, "Summary report failed"
        assert detailed_report is not None, "Detailed report failed"
        
        # Step 6: Get final summary
        final_summary = await self.agent.get_target_summary(target_id)
        assert final_summary['analysis_complete'] == True, "Analysis not marked complete"
        assert final_summary['data_count'] > 0, "No data in final summary"
        
        self.test_targets.append(target_id)
        
        print(f"   ✓ Complete workflow executed successfully with {len(collected)} data items")
        return True
    
    async def test_error_handling(self) -> bool:
        """Test error handling and edge cases."""
        print("\n🚨 Testing Error Handling...")
        
        # Test invalid target ID
        try:
            await self.agent.get_target_summary("invalid_target")
            assert False, "Should raise error for invalid target"
        except ValueError:
            pass  # Expected
        
        # Test empty data collection
        empty_target_id = await self.agent.add_target(name="Empty Target")
        try:
            await self.agent.analyze_target(empty_target_id)
            assert False, "Should raise error for no data"
        except ValueError:
            pass  # Expected
        
        # Test invalid report type
        if self.test_targets:
            try:
                await self.agent.generate_report(self.test_targets[0], 'invalid_type')
                assert False, "Should raise error for invalid report type"
            except ValueError:
                pass  # Expected
        
        # Test invalid OSINT tool
        tool_result = await self.agent.run_osint_tools("example.com", ['invalid_tool'])
        assert 'invalid_tool' in tool_result, "Should handle invalid tool gracefully"
        assert tool_result['invalid_tool']['success'] == False, "Invalid tool should fail"
        
        # Clean up
        await self.agent.remove_target(empty_target_id)
        
        print("   ✓ Error handling working correctly")
        return True
    
    async def cleanup(self):
        """Clean up test data."""
        print("\n🧹 Cleaning up test data...")
        
        for target_id in self.test_targets:
            try:
                await self.agent.remove_target(target_id)
            except Exception as e:
                logger.warning(f"Error cleaning up target {target_id}: {e}")
        
        print("   ✓ Cleanup completed")


async def main():
    """Main test execution function."""
    test_suite = SocialOSINTAgentTestSuite()
    
    try:
        success = await test_suite.run_all_tests()
        
        # Generate test report
        report = {
            'test_suite': 'SocialOSINTAgent',
            'timestamp': datetime.now().isoformat(),
            'total_tests': len(test_suite.test_results),
            'passed_tests': sum(1 for r in test_suite.test_results if r['passed']),
            'failed_tests': sum(1 for r in test_suite.test_results if not r['passed']),
            'results': test_suite.test_results
        }
        
        # Save test report
        with open('test_social_osint_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📋 Test report saved to: test_social_osint_report.json")
        
        return success
        
    finally:
        await test_suite.cleanup()


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
