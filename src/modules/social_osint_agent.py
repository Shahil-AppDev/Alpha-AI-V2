"""
Social and OSINT Engineering Agent

This module implements a specialized agent for social engineering and OSINT tasks,
including data collection, analysis, password cracking, and reporting capabilities.
"""

import asyncio
import json
import logging
import re
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DataSource(Enum):
    """Data sources for OSINT collection."""
    SOCIAL_MEDIA = "social_media"
    FORUMS = "forums"
    BLOGS = "blogs"
    NEWS = "news"
    PUBLIC_RECORDS = "public_records"
    DARK_WEB = "dark_web"
    JOB_SITES = "job_sites"
    PROFESSIONAL_NETWORKS = "professional_networks"


class DataStatus(Enum):
    """Status of collected data."""
    COLLECTING = "collecting"
    PROCESSED = "processed"
    ANALYZED = "analyzed"
    FAILED = "failed"


class ThreatLevel(Enum):
    """Threat assessment levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class OSINTTarget:
    """Represents an OSINT target."""
    target_id: str
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    social_profiles: Dict[str, str] = field(default_factory=dict)
    company: Optional[str] = None
    job_title: Optional[str] = None
    location: Optional[str] = None
    additional_info: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class CollectedData:
    """Represents collected OSINT data."""
    data_id: str
    target_id: str
    source: DataSource
    raw_data: Dict[str, Any]
    processed_data: Dict[str, Any] = field(default_factory=dict)
    status: DataStatus = DataStatus.COLLECTING
    collected_at: datetime = field(default_factory=datetime.now)
    confidence_score: float = 0.0


@dataclass
class AnalysisResult:
    """Represents analysis results."""
    result_id: str
    target_id: str
    data_ids: List[str]
    sentiment_score: float
    threat_level: ThreatLevel
    key_findings: List[str]
    recommendations: List[str]
    created_at: datetime = field(default_factory=datetime.now)


class DataCollector(ABC):
    """Abstract base class for data collectors."""
    
    @abstractmethod
    async def collect(self, target: OSINTTarget) -> List[CollectedData]:
        """Collect data for a target."""
        pass


class SocialMediaCollector(DataCollector):
    """Collects data from social media platforms."""
    
    def __init__(self):
        self.platforms = {
            'twitter': self._collect_twitter,
            'linkedin': self._collect_linkedin,
            'facebook': self._collect_facebook,
            'instagram': self._collect_instagram
        }
    
    async def collect(self, target: OSINTTarget) -> List[CollectedData]:
        """Collect social media data."""
        results = []
        
        for platform, collector in self.platforms.items():
            try:
                data = await collector(target)
                if data:
                    results.append(data)
            except Exception as e:
                logger.error(f"Error collecting from {platform}: {e}")
        
        return results
    
    async def _collect_twitter(self, target: OSINTTarget) -> Optional[CollectedData]:
        """Simulate Twitter data collection."""
        await asyncio.sleep(0.1)  # Simulate API delay
        
        if 'twitter' not in target.social_profiles:
            return None
        
        data = {
            'platform': 'twitter',
            'username': target.social_profiles['twitter'],
            'followers': 1250,
            'following': 340,
            'tweets': 892,
            'verified': False,
            'recent_tweets': [
                "Working on a new project...",
                "Great conference yesterday!",
                "Looking forward to the weekend"
            ],
            'bio': "Software Engineer | Tech Enthusiast"
        }
        
        return CollectedData(
            data_id=str(uuid.uuid4()),
            target_id=target.target_id,
            source=DataSource.SOCIAL_MEDIA,
            raw_data=data,
            confidence_score=0.85
        )
    
    async def _collect_linkedin(self, target: OSINTTarget) -> Optional[CollectedData]:
        """Simulate LinkedIn data collection."""
        await asyncio.sleep(0.1)
        
        if 'linkedin' not in target.social_profiles:
            return None
        
        data = {
            'platform': 'linkedin',
            'profile_url': target.social_profiles['linkedin'],
            'current_position': target.job_title or "Software Engineer",
            'company': target.company or "Tech Corp",
            'experience': 5,
            'connections': 342,
            'skills': ['Python', 'JavaScript', 'React', 'Node.js'],
            'education': "BS Computer Science"
        }
        
        return CollectedData(
            data_id=str(uuid.uuid4()),
            target_id=target.target_id,
            source=DataSource.PROFESSIONAL_NETWORKS,
            raw_data=data,
            confidence_score=0.90
        )
    
    async def _collect_facebook(self, target: OSINTTarget) -> Optional[CollectedData]:
        """Simulate Facebook data collection."""
        await asyncio.sleep(0.1)
        return None  # Privacy restrictions
    
    async def _collect_instagram(self, target: OSINTTarget) -> Optional[CollectedData]:
        """Simulate Instagram data collection."""
        await asyncio.sleep(0.1)
        return None  # Privacy restrictions


class PublicRecordsCollector(DataCollector):
    """Collects data from public records."""
    
    async def collect(self, target: OSINTTarget) -> List[CollectedData]:
        """Collect public records data."""
        await asyncio.sleep(0.2)
        
        data = {
            'property_records': {
                'owns_property': False,
                'estimated_value': 0
            },
            'business_registrations': [],
            'court_records': {
                'civil_cases': 0,
                'criminal_cases': 0
            },
            'voter_registration': {
                'registered': True,
                'party': 'Independent'
            }
        }
        
        return [CollectedData(
            data_id=str(uuid.uuid4()),
            target_id=target.target_id,
            source=DataSource.PUBLIC_RECORDS,
            raw_data=data,
            confidence_score=0.75
        )]


class DataProcessor:
    """Processes collected OSINT data."""
    
    def __init__(self):
        self.nlp_models = {
            'sentiment': self._analyze_sentiment,
            'entities': self._extract_entities,
            'keywords': self._extract_keywords
        }
    
    async def process_data(self, data: CollectedData) -> CollectedData:
        """Process collected data."""
        processed = {}
        
        # Extract text content
        text_content = self._extract_text_content(data.raw_data)
        
        # Apply NLP models
        for model_name, model_func in self.nlp_models.items():
            try:
                processed[model_name] = model_func(text_content)
            except Exception as e:
                logger.error(f"Error in {model_name}: {e}")
                processed[model_name] = {}
        
        data.processed_data = processed
        data.status = DataStatus.PROCESSED
        
        return data
    
    def _extract_text_content(self, raw_data: Dict[str, Any]) -> str:
        """Extract text content from raw data."""
        texts = []
        
        def extract_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if isinstance(value, str) and len(value) > 10:
                        texts.append(value)
                    else:
                        extract_recursive(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    if isinstance(item, str) and len(item) > 10:
                        texts.append(item)
                    else:
                        extract_recursive(item, f"{path}[{i}]")
        
        extract_recursive(raw_data)
        return " ".join(texts)
    
    def _analyze_sentiment(self, text: str) -> Dict[str, float]:
        """Analyze sentiment of text."""
        # Simple sentiment analysis simulation
        positive_words = ['great', 'excellent', 'amazing', 'love', 'fantastic', 'good']
        negative_words = ['bad', 'terrible', 'hate', 'awful', 'horrible', 'worst']
        
        words = text.lower().split()
        positive_count = sum(1 for word in words if word in positive_words)
        negative_count = sum(1 for word in words if word in negative_words)
        
        if positive_count + negative_count == 0:
            return {'sentiment': 0.0, 'confidence': 0.0}
        
        sentiment = (positive_count - negative_count) / (positive_count + negative_count)
        confidence = min((positive_count + negative_count) / len(words), 1.0)
        
        return {
            'sentiment': sentiment,
            'confidence': confidence,
            'positive_words': positive_count,
            'negative_words': negative_count
        }
    
    def _extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract named entities from text."""
        # Simple entity extraction simulation
        entities = {
            'persons': [],
            'organizations': [],
            'locations': [],
            'emails': [],
            'phones': []
        }
        
        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        entities['emails'] = re.findall(email_pattern, text)
        
        # Phone pattern (simplified)
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        entities['phones'] = re.findall(phone_pattern, text)
        
        return entities
    
    def _extract_keywords(self, text: str) -> Dict[str, Any]:
        """Extract keywords from text."""
        words = text.lower().split()
        word_freq = {}
        
        for word in words:
            if len(word) > 3 and word.isalpha():
                word_freq[word] = word_freq.get(word, 0) + 1
        
        # Get top keywords
        top_keywords = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'keywords': dict(top_keywords),
            'total_words': len(words),
            'unique_words': len(set(words))
        }


class PasswordCracker:
    """Handles password cracking operations."""
    
    def __init__(self):
        self.tools = {
            'hashcat': self._crack_with_hashcat,
            'john': self._crack_with_john,
            'hydra': self._crack_with_hydra
        }
        self.wordlists = [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt'
        ]
    
    async def crack_password(self, hash_value: str, hash_type: str = 'md5', 
                           method: str = 'dictionary') -> Dict[str, Any]:
        """Attempt to crack password hash."""
        results = {
            'success': False,
            'password': None,
            'method': method,
            'tool': None,
            'time_taken': 0,
            'attempts': 0
        }
        
        start_time = time.time()
        
        for tool_name, tool_func in self.tools.items():
            try:
                result = await tool_func(hash_value, hash_type, method)
                if result['success']:
                    results.update(result)
                    results['tool'] = tool_name
                    break
            except Exception as e:
                logger.error(f"Error with {tool_name}: {e}")
        
        results['time_taken'] = time.time() - start_time
        return results
    
    async def _crack_with_hashcat(self, hash_value: str, hash_type: str, 
                                method: str) -> Dict[str, Any]:
        """Simulate Hashcat cracking."""
        await asyncio.sleep(0.5)
        
        # Simulate successful crack for demo
        if hash_value == '5f4dcc3b5aa765d61d8327deb882cf99':  # 'password'
            return {
                'success': True,
                'password': 'password',
                'attempts': 1000
            }
        
        return {'success': False, 'attempts': 1000}
    
    async def _crack_with_john(self, hash_value: str, hash_type: str, 
                             method: str) -> Dict[str, Any]:
        """Simulate John the Ripper cracking."""
        await asyncio.sleep(0.3)
        return {'success': False, 'attempts': 500}
    
    async def _crack_with_hydra(self, hash_value: str, hash_type: str, 
                              method: str) -> Dict[str, Any]:
        """Simulate Hydra cracking (for online services)."""
        await asyncio.sleep(1.0)
        return {'success': False, 'attempts': 100}


class OSINTToolManager:
    """Manages OSINT tool integrations."""
    
    def __init__(self):
        self.tools = {
            'the_harvester': self._run_the_harvester,
            'maltego': self._run_maltego,
            'recon-ng': self._run_recon_ng,
            'spiderfoot': self._run_spiderfoot,
            'sherlock': self._run_sherlock
        }
    
    async def run_tool(self, tool_name: str, target: str, 
                      options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run an OSINT tool."""
        if tool_name not in self.tools:
            return {'success': False, 'error': f'Tool {tool_name} not found'}
        
        try:
            return await self.tools[tool_name](target, options or {})
        except Exception as e:
            logger.error(f"Error running {tool_name}: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _run_the_harvester(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate theHarvester execution."""
        await asyncio.sleep(0.5)
        
        return {
            'success': True,
            'results': {
                'emails': [f'contact@{target}', f'info@{target}'],
                'hosts': [f'www.{target}', f'mail.{target}'],
                'subdomains': [f'api.{target}', f'blog.{target}']
            }
        }
    
    async def _run_maltego(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate Maltego execution."""
        await asyncio.sleep(1.0)
        return {'success': True, 'results': {'entities': []}}
    
    async def _run_recon_ng(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate Recon-ng execution."""
        await asyncio.sleep(0.8)
        return {'success': True, 'results': {'contacts': []}}
    
    async def _run_spiderfoot(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate SpiderFoot execution."""
        await asyncio.sleep(1.5)
        return {'success': True, 'results': {'indicators': []}}
    
    async def _run_sherlock(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate Sherlock execution."""
        await asyncio.sleep(0.3)
        
        platforms = ['twitter', 'linkedin', 'github', 'instagram']
        found = {platform: f'https://{platform}.com/{target}' for platform in platforms}
        
        return {
            'success': True,
            'results': {
                'username': target,
                'found_accounts': found
            }
        }


class ReportGenerator:
    """Generates OSINT reports."""
    
    def __init__(self):
        self.report_templates = {
            'summary': self._generate_summary_report,
            'detailed': self._generate_detailed_report,
            'threat': self._generate_threat_report
        }
    
    async def generate_report(self, target: OSINTTarget, 
                            collected_data: List[CollectedData],
                            analysis: Optional[AnalysisResult] = None,
                            report_type: str = 'summary') -> Dict[str, Any]:
        """Generate OSINT report."""
        if report_type not in self.report_templates:
            raise ValueError(f"Unknown report type: {report_type}")
        
        return await self.report_templates[report_type](target, collected_data, analysis)
    
    async def _generate_summary_report(self, target: OSINTTarget, 
                                     collected_data: List[CollectedData],
                                     analysis: Optional[AnalysisResult]) -> Dict[str, Any]:
        """Generate summary report."""
        return {
            'report_type': 'summary',
            'target': {
                'name': target.name,
                'email': target.email,
                'company': target.company
            },
            'data_summary': {
                'total_sources': len(collected_data),
                'sources': [data.source.value for data in collected_data],
                'collection_date': datetime.now().isoformat()
            },
            'key_findings': analysis.key_findings if analysis else [],
            'threat_level': analysis.threat_level.value if analysis else 'unknown'
        }
    
    async def _generate_detailed_report(self, target: OSINTTarget, 
                                      collected_data: List[CollectedData],
                                      analysis: Optional[AnalysisResult]) -> Dict[str, Any]:
        """Generate detailed report."""
        return {
            'report_type': 'detailed',
            'target': {
                'name': target.name,
                'email': target.email,
                'phone': target.phone,
                'company': target.company,
                'job_title': target.job_title,
                'location': target.location,
                'social_profiles': target.social_profiles
            },
            'collected_data': [
                {
                    'source': data.source.value,
                    'status': data.status.value,
                    'confidence': data.confidence_score,
                    'raw_data': data.raw_data,
                    'processed_data': data.processed_data
                }
                for data in collected_data
            ],
            'analysis': {
                'sentiment_score': analysis.sentiment_score if analysis else 0,
                'threat_level': analysis.threat_level.value if analysis else 'unknown',
                'key_findings': analysis.key_findings if analysis else [],
                'recommendations': analysis.recommendations if analysis else []
            }
        }
    
    async def _generate_threat_report(self, target: OSINTTarget, 
                                    collected_data: List[CollectedData],
                                    analysis: Optional[AnalysisResult]) -> Dict[str, Any]:
        """Generate threat assessment report."""
        return {
            'report_type': 'threat',
            'target': {
                'name': target.name,
                'email': target.email,
                'company': target.company
            },
            'threat_assessment': {
                'level': analysis.threat_level.value if analysis else 'unknown',
                'score': analysis.sentiment_score if analysis else 0,
                'indicators': [],
                'risk_factors': []
            },
            'recommendations': analysis.recommendations if analysis else [],
            'mitigation_steps': []
        }


class SocialOSINTAgent:
    """Main Social and OSINT Engineering Agent."""
    
    def __init__(self):
        self.collectors = {
            'social_media': SocialMediaCollector(),
            'public_records': PublicRecordsCollector()
        }
        self.processor = DataProcessor()
        self.password_cracker = PasswordCracker()
        self.tool_manager = OSINTToolManager()
        self.report_generator = ReportGenerator()
        
        self.targets: Dict[str, OSINTTarget] = {}
        self.collected_data: Dict[str, List[CollectedData]] = {}
        self.analyses: Dict[str, AnalysisResult] = {}
        
        logger.info("SocialOSINTAgent initialized")
    
    async def add_target(self, name: str, email: Optional[str] = None,
                        social_profiles: Dict[str, str] = None,
                        **kwargs) -> str:
        """Add a new OSINT target."""
        target = OSINTTarget(
            target_id=str(uuid.uuid4()),
            name=name,
            email=email,
            social_profiles=social_profiles or {},
            **kwargs
        )
        
        self.targets[target.target_id] = target
        self.collected_data[target.target_id] = []
        
        logger.info(f"Added target: {name} (ID: {target.target_id})")
        return target.target_id
    
    async def collect_data(self, target_id: str, 
                          sources: List[str] = None) -> List[CollectedData]:
        """Collect OSINT data for a target."""
        if target_id not in self.targets:
            raise ValueError(f"Target {target_id} not found")
        
        target = self.targets[target_id]
        collected = []
        
        # Use all collectors if none specified
        collectors_to_use = sources or list(self.collectors.keys())
        
        for collector_name in collectors_to_use:
            if collector_name in self.collectors:
                try:
                    data = await self.collectors[collector_name].collect(target)
                    collected.extend(data)
                    logger.info(f"Collected {len(data)} items from {collector_name}")
                except Exception as e:
                    logger.error(f"Error collecting from {collector_name}: {e}")
        
        # Process collected data
        for data in collected:
            await self.processor.process_data(data)
        
        self.collected_data[target_id].extend(collected)
        return collected
    
    async def analyze_target(self, target_id: str) -> AnalysisResult:
        """Analyze collected data for a target."""
        if target_id not in self.targets:
            raise ValueError(f"Target {target_id} not found")
        
        data = self.collected_data.get(target_id, [])
        if not data:
            raise ValueError(f"No data collected for target {target_id}")
        
        # Aggregate analysis results
        total_sentiment = 0
        sentiment_count = 0
        key_findings = []
        
        for item in data:
            if 'sentiment' in item.processed_data:
                total_sentiment += item.processed_data['sentiment'].get('sentiment', 0)
                sentiment_count += 1
            
            # Extract key findings
            if 'entities' in item.processed_data:
                entities = item.processed_data['entities']
                if entities.get('emails'):
                    key_findings.append(f"Found {len(entities['emails'])} email addresses")
                if entities.get('phones'):
                    key_findings.append(f"Found {len(entities['phones'])} phone numbers")
        
        # Calculate overall sentiment
        avg_sentiment = total_sentiment / sentiment_count if sentiment_count > 0 else 0
        
        # Determine threat level
        threat_level = self._assess_threat_level(avg_sentiment, data)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threat_level, data)
        
        analysis = AnalysisResult(
            result_id=str(uuid.uuid4()),
            target_id=target_id,
            data_ids=[d.data_id for d in data],
            sentiment_score=avg_sentiment,
            threat_level=threat_level,
            key_findings=key_findings,
            recommendations=recommendations
        )
        
        self.analyses[target_id] = analysis
        return analysis
    
    def _assess_threat_level(self, sentiment_score: float, 
                           data: List[CollectedData]) -> ThreatLevel:
        """Assess threat level based on analysis."""
        # Simple threat assessment logic
        if sentiment_score < -0.5:
            return ThreatLevel.HIGH
        elif sentiment_score < -0.2:
            return ThreatLevel.MEDIUM
        elif sentiment_score > 0.5:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.LOW
    
    def _generate_recommendations(self, threat_level: ThreatLevel, 
                                data: List[CollectedData]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            recommendations.extend([
                "Implement additional monitoring",
                "Review access controls",
                "Conduct security awareness training"
            ])
        
        # Check for exposed personal information
        for item in data:
            if 'entities' in item.processed_data:
                entities = item.processed_data['entities']
                if entities.get('emails') or entities.get('phones'):
                    recommendations.append("Review exposed personal information")
                    break
        
        return recommendations
    
    async def crack_passwords(self, target_id: str, 
                            password_hashes: List[str]) -> List[Dict[str, Any]]:
        """Attempt to crack password hashes."""
        if target_id not in self.targets:
            raise ValueError(f"Target {target_id} not found")
        
        results = []
        
        for hash_value in password_hashes:
            result = await self.password_cracker.crack_password(hash_value)
            results.append(result)
            
            if result['success']:
                logger.info(f"Successfully cracked password: {result['password']}")
        
        return results
    
    async def run_osint_tools(self, target: str, 
                            tools: List[str] = None) -> Dict[str, Any]:
        """Run OSINT tools against a target."""
        tools_to_run = tools or list(self.tool_manager.tools.keys())
        results = {}
        
        for tool in tools_to_run:
            try:
                result = await self.tool_manager.run_tool(tool, target)
                results[tool] = result
                logger.info(f"Ran {tool} against {target}")
            except Exception as e:
                logger.error(f"Error running {tool}: {e}")
                results[tool] = {'success': False, 'error': str(e)}
        
        return results
    
    async def generate_report(self, target_id: str, 
                            report_type: str = 'summary') -> Dict[str, Any]:
        """Generate OSINT report for a target."""
        if target_id not in self.targets:
            raise ValueError(f"Target {target_id} not found")
        
        target = self.targets[target_id]
        data = self.collected_data.get(target_id, [])
        analysis = self.analyses.get(target_id)
        
        return await self.report_generator.generate_report(
            target, data, analysis, report_type
        )
    
    async def get_target_summary(self, target_id: str) -> Dict[str, Any]:
        """Get summary of target and collected data."""
        if target_id not in self.targets:
            raise ValueError(f"Target {target_id} not found")
        
        target = self.targets[target_id]
        data = self.collected_data.get(target_id, [])
        analysis = self.analyses.get(target_id)
        
        return {
            'target': {
                'id': target_id,
                'name': target.name,
                'email': target.email,
                'company': target.company
            },
            'data_count': len(data),
            'sources': list(set(d.source.value for d in data)),
            'analysis_complete': analysis is not None,
            'threat_level': analysis.threat_level.value if analysis else 'unknown'
        }
    
    def list_targets(self) -> List[Dict[str, Any]]:
        """List all targets."""
        return [
            {
                'id': target_id,
                'name': target.name,
                'email': target.email,
                'company': target.company,
                'created_at': target.created_at.isoformat()
            }
            for target_id, target in self.targets.items()
        ]
    
    async def remove_target(self, target_id: str) -> bool:
        """Remove a target and all associated data."""
        if target_id not in self.targets:
            return False
        
        del self.targets[target_id]
        if target_id in self.collected_data:
            del self.collected_data[target_id]
        if target_id in self.analyses:
            del self.analyses[target_id]
        
        logger.info(f"Removed target {target_id}")
        return True


# Ethical and privacy compliance
class EthicalCompliance:
    """Ensures ethical and privacy compliance."""
    
    def __init__(self):
        self.consent_required = True
        self.data_retention_days = 30
        self.minimize_data = True
    
    def validate_collection(self, target: OSINTTarget, 
                          sources: List[DataSource]) -> bool:
        """Validate if data collection is compliant."""
        # Check if we have consent
        if self.consent_required and not self._has_consent(target):
            logger.warning(f"No consent for target {target.name}")
            return False
        
        # Check if sources are public
        for source in sources:
            if not self._is_public_source(source):
                logger.warning(f"Non-public source: {source}")
                return False
        
        return True
    
    def _has_consent(self, target: OSINTTarget) -> bool:
        """Check if we have consent for the target."""
        # In a real implementation, this would check consent records
        return False  # Default to no consent for safety
    
    def _is_public_source(self, source: DataSource) -> bool:
        """Check if a data source is public."""
        private_sources = {DataSource.DARK_WEB}
        return source not in private_sources
    
    def should_retain_data(self, data: CollectedData) -> bool:
        """Check if data should be retained."""
        age = datetime.now() - data.collected_at
        return age.days < self.data_retention_days
    
    def minimize_data_collection(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Minimize collected data to essential information."""
        if not self.minimize_data:
            return raw_data
        
        # Remove sensitive fields
        minimized = raw_data.copy()
        sensitive_fields = ['ssn', 'credit_card', 'medical_record']
        
        def remove_sensitive(obj):
            if isinstance(obj, dict):
                for key in list(obj.keys()):
                    if any(sensitive in key.lower() for sensitive in sensitive_fields):
                        del obj[key]
                    else:
                        remove_sensitive(obj[key])
            elif isinstance(obj, list):
                for item in obj:
                    remove_sensitive(item)
        
        remove_sensitive(minimized)
        return minimized


# Integration with external systems
class SecuritySystemIntegration:
    """Integrates with SIEM, SOAR, and other security systems."""
    
    def __init__(self):
        self.siem_config = {}
        self.soar_config = {}
        self.threat_intel_feeds = []
    
    async def send_to_siem(self, analysis: AnalysisResult) -> bool:
        """Send analysis results to SIEM."""
        # Simulate SIEM integration
        await asyncio.sleep(0.1)
        logger.info(f"Sent analysis {analysis.result_id} to SIEM")
        return True
    
    async def trigger_soar_playbook(self, threat_level: ThreatLevel, 
                                  target_info: Dict[str, Any]) -> bool:
        """Trigger SOAR playbook based on threat level."""
        # Simulate SOAR integration
        await asyncio.sleep(0.2)
        
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            logger.info("Triggered incident response playbook")
            return True
        
        return False
    
    async def enrich_with_threat_intel(self, target: OSINTTarget) -> Dict[str, Any]:
        """Enrich target data with threat intelligence."""
        # Simulate threat intelligence enrichment
        await asyncio.sleep(0.5)
        
        return {
            'threat_indicators': [],
            'known_associations': [],
            'risk_score': 0.3
        }


# Main execution function
async def main():
    """Example usage of the SocialOSINTAgent."""
    agent = SocialOSINTAgent()
    
    # Add a target
    target_id = await agent.add_target(
        name="John Doe",
        email="john.doe@example.com",
        company="Tech Corp",
        social_profiles={
            'twitter': '@johndoe',
            'linkedin': 'john-doe'
        }
    )
    
    # Collect data
    print("Collecting OSINT data...")
    collected = await agent.collect_data(target_id)
    print(f"Collected {len(collected)} data items")
    
    # Analyze target
    print("Analyzing target...")
    analysis = await agent.analyze_target(target_id)
    print(f"Threat level: {analysis.threat_level.value}")
    
    # Generate report
    print("Generating report...")
    report = await agent.generate_report(target_id, 'summary')
    print(f"Report generated: {report['report_type']}")
    
    # Run OSINT tools
    print("Running OSINT tools...")
    tool_results = await agent.run_osint_tools("example.com", ['the_harvester', 'sherlock'])
    print(f"Tool results: {list(tool_results.keys())}")
    
    # Get target summary
    summary = await agent.get_target_summary(target_id)
    print(f"Target summary: {summary}")


if __name__ == "__main__":
    asyncio.run(main())
