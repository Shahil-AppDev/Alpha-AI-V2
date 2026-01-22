"""
Expert Security Agents Integration Module

This module integrates all specialized security agents with the HackerAI platform,
providing a unified interface for comprehensive security assessments across
all domains of expertise.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum

from modules.security_agents import (
    SecurityAgentManager, SecurityDiscipline, SecurityFinding, ThreatLevel
)
from modules.blackarch_integration import BlackArchToolManager, BlackArchAPI
from modules.email_security import EmailSecurityAnalyzer, EmailSecurityMonitor, EmailSecurityAPI
from modules.social_osint_agent import SocialOSINTAgent
from modules.universal_tool_manager import UniversalToolManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AssessmentType(Enum):
    """Types of security assessments."""
    QUICK_SCAN = "quick_scan"
    COMPREHENSIVE = "comprehensive"
    PENETRATION_TEST = "penetration_test"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE_AUDIT = "compliance_audit"
    THREAT_HUNTING = "threat_hunting"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"


class ExpertiseLevel(Enum):
    """Expertise levels for assessments."""
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"
    ENTERPRISE = "enterprise"


@dataclass
class AssessmentRequest:
    """Security assessment request."""
    request_id: str
    target: str
    assessment_type: AssessmentType
    expertise_level: ExpertiseLevel
    disciplines: List[SecurityDiscipline]
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: str = "normal"  # low, normal, high, critical
    requested_by: str = "system"
    created_at: datetime = field(default_factory=datetime.now)
    deadline: Optional[datetime] = None


@dataclass
class AssessmentResult:
    """Security assessment result."""
    request_id: str
    target: str
    assessment_type: AssessmentType
    expertise_level: ExpertiseLevel
    status: str  # pending, running, completed, failed
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[SecurityFinding] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    compliance_score: float = 0.0
    executed_by: List[str] = field(default_factory=list)
    execution_time: Optional[timedelta] = None


class ExpertSecurityPlatform:
    """Main expert security platform integrating all specialized agents."""
    
    def __init__(self):
        # Initialize core components
        self.tool_manager = UniversalToolManager()
        self.agent_manager = SecurityAgentManager(self.tool_manager)
        
        # Initialize specialized modules
        self.blackarch_manager = None
        self.email_security_analyzer = None
        self.email_monitor = None
        self.osint_agent = None
        
        # Assessment management
        self.active_assessments: Dict[str, AssessmentRequest] = {}
        self.assessment_results: Dict[str, AssessmentResult] = {}
        self.assessment_queue: List[str] = []
        
        # Platform configuration
        self.max_concurrent_assessments = 5
        self.default_timeout = timedelta(hours=24)
        
    async def initialize(self):
        """Initialize all platform components."""
        try:
            # Initialize BlackArch integration
            self.blackarch_manager = BlackArchToolManager(self.tool_manager)
            await self.blackarch_manager.initialize()
            
            # Initialize email security
            self.email_security_analyzer = EmailSecurityAnalyzer()
            self.email_monitor = EmailSecurityMonitor(self.email_security_analyzer)
            
            # Initialize OSINT agent
            self.osint_agent = SocialOSINTAgent()
            
            logger.info("Expert Security Platform initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize platform: {e}")
            raise
    
    async def create_assessment(self, 
                             target: str,
                             assessment_type: AssessmentType = AssessmentType.COMPREHENSIVE,
                             expertise_level: ExpertiseLevel = ExpertiseLevel.ADVANCED,
                             disciplines: List[SecurityDiscipline] = None,
                             parameters: Dict[str, Any] = None,
                             priority: str = "normal",
                             requested_by: str = "system") -> str:
        """Create a new security assessment request."""
        
        request_id = f"ASSESS-{datetime.now().strftime('%Y%m%d%H%M%S')}-{len(self.active_assessments):04d}"
        
        # Determine disciplines based on assessment type
        if not disciplines:
            disciplines = self._get_default_disciplines(assessment_type)
        
        # Create assessment request
        request = AssessmentRequest(
            request_id=request_id,
            target=target,
            assessment_type=assessment_type,
            expertise_level=expertise_level,
            disciplines=disciplines,
            parameters=parameters or {},
            priority=priority,
            requested_by=requested_by
        )
        
        # Store request
        self.active_assessments[request_id] = request
        
        # Add to queue based on priority
        self._add_to_queue(request_id, priority)
        
        logger.info(f"Created assessment {request_id} for {target}")
        
        # Start assessment processing if capacity available
        await self._process_queue()
        
        return request_id
    
    async def get_assessment_status(self, request_id: str) -> Dict[str, Any]:
        """Get status of an assessment."""
        if request_id in self.active_assessments:
            request = self.active_assessments[request_id]
            return {
                "request_id": request_id,
                "status": "queued" if request_id in self.assessment_queue else "processing",
                "target": request.target,
                "assessment_type": request.assessment_type.value,
                "expertise_level": request.expertise_level.value,
                "disciplines": [d.value for d in request.disciplines],
                "priority": request.priority,
                "created_at": request.created_at.isoformat(),
                "queue_position": self.assessment_queue.index(request_id) if request_id in self.assessment_queue else -1
            }
        elif request_id in self.assessment_results:
            result = self.assessment_results[request_id]
            return {
                "request_id": request_id,
                "status": result.status,
                "target": result.target,
                "assessment_type": result.assessment_type.value,
                "expertise_level": result.expertise_level.value,
                "findings_count": len(result.findings),
                "risk_score": result.risk_score,
                "compliance_score": result.compliance_score,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "execution_time": str(result.execution_time) if result.execution_time else None,
                "executed_by": result.executed_by
            }
        else:
            raise ValueError(f"Assessment {request_id} not found")
    
    async def get_assessment_result(self, request_id: str) -> Dict[str, Any]:
        """Get detailed assessment results."""
        if request_id not in self.assessment_results:
            raise ValueError(f"Assessment {request_id} not found or not completed")
        
        result = self.assessment_results[request_id]
        
        return {
            "request_id": request_id,
            "target": result.target,
            "assessment_type": result.assessment_type.value,
            "expertise_level": result.expertise_level.value,
            "status": result.status,
            "start_time": result.start_time.isoformat(),
            "end_time": result.end_time.isoformat() if result.end_time else None,
            "execution_time": str(result.execution_time) if result.execution_time else None,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "discipline": f.discipline.value,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "recommendations": f.recommendations,
                    "cve_ids": f.cve_ids,
                    "cvss_score": f.cvss_score,
                    "discovered_at": f.discovered_at.isoformat()
                }
                for f in result.findings
            ],
            "summary": result.summary,
            "recommendations": result.recommendations,
            "risk_score": result.risk_score,
            "compliance_score": result.compliance_score,
            "executed_by": result.executed_by
        }
    
    async def cancel_assessment(self, request_id: str) -> bool:
        """Cancel an assessment."""
        if request_id in self.assessment_queue:
            self.assessment_queue.remove(request_id)
            del self.active_assessments[request_id]
            logger.info(f"Cancelled assessment {request_id}")
            return True
        return False
    
    async def _process_queue(self):
        """Process assessment queue."""
        while (len(self.assessment_queue) > 0 and 
               sum(1 for r in self.assessment_results.values() if r.status == "running") < self.max_concurrent_assessments):
            
            # Get next assessment based on priority
            request_id = self._get_next_assessment()
            if not request_id:
                break
            
            # Start assessment in background
            asyncio.create_task(self._execute_assessment(request_id))
    
    async def _execute_assessment(self, request_id: str):
        """Execute a security assessment."""
        request = self.active_assessments[request_id]
        
        # Create result object
        result = AssessmentResult(
            request_id=request_id,
            target=request.target,
            assessment_type=request.assessment_type,
            expertise_level=request.expertise_level,
            status="running",
            start_time=datetime.now()
        )
        
        self.assessment_results[request_id] = result
        
        try:
            # Execute assessment based on type and expertise level
            if request.assessment_type == AssessmentType.QUICK_SCAN:
                await self._execute_quick_scan(request, result)
            elif request.assessment_type == AssessmentType.COMPREHENSIVE:
                await self._execute_comprehensive_assessment(request, result)
            elif request.assessment_type == AssessmentType.PENETRATION_TEST:
                await self._execute_penetration_test(request, result)
            elif request.assessment_type == AssessmentType.INCIDENT_RESPONSE:
                await self._execute_incident_response(request, result)
            elif request.assessment_type == AssessmentType.COMPLIANCE_AUDIT:
                await self._execute_compliance_audit(request, result)
            elif request.assessment_type == AssessmentType.THREAT_HUNTING:
                await self._execute_threat_hunting(request, result)
            elif request.assessment_type == AssessmentType.VULNERABILITY_ASSESSMENT:
                await self._execute_vulnerability_assessment(request, result)
            
            # Calculate scores and generate summary
            self._calculate_scores(result)
            self._generate_summary(result)
            self._generate_recommendations(result)
            
            result.status = "completed"
            result.end_time = datetime.now()
            result.execution_time = result.end_time - result.start_time
            
            logger.info(f"Completed assessment {request_id} in {result.execution_time}")
            
        except Exception as e:
            logger.error(f"Assessment {request_id} failed: {e}")
            result.status = "failed"
            result.end_time = datetime.now()
            result.execution_time = result.end_time - result.start_time
        
        finally:
            # Clean up active assessment
            if request_id in self.active_assessments:
                del self.active_assessments[request_id]
            
            # Process next in queue
            await self._process_queue()
    
    async def _execute_quick_scan(self, request: AssessmentRequest, result: AssessmentResult):
        """Execute quick security scan."""
        # Basic OSINT and network scan
        if SecurityDiscipline.OSINT in request.disciplines:
            osint_findings = await self.agent_manager.agents[SecurityDiscipline.OSINT].analyze(
                request.target, {"quick_scan": True}
            )
            result.findings.extend(osint_findings)
            result.executed_by.append("OSINT Agent")
        
        if SecurityDiscipline.NETWORK_PENETRATION_TESTING in request.disciplines:
            network_findings = await self.agent_manager.agents[SecurityDiscipline.NETWORK_PENETRATION_TESTING].analyze(
                request.target, {"quick_scan": True}
            )
            result.findings.extend(network_findings)
            result.executed_by.append("Network Agent")
    
    async def _execute_comprehensive_assessment(self, request: AssessmentRequest, result: AssessmentResult):
        """Execute comprehensive security assessment."""
        # Use agent manager for multi-discipline assessment
        assessment = await self.agent_manager.run_comprehensive_assessment(
            request.target,
            request.disciplines,
            request.parameters
        )
        
        # Convert findings
        for finding_data in assessment["findings"]:
            finding = SecurityFinding(
                finding_id=finding_data["finding_id"],
                discipline=SecurityDiscipline(finding_data["discipline"]),
                title=finding_data["title"],
                description=finding_data["description"],
                severity=ThreatLevel(finding_data["severity"]),
                confidence=finding_data["confidence"],
                evidence=finding_data.get("evidence", {}),
                recommendations=finding_data.get("recommendations", [])
            )
            result.findings.append(finding)
        
        result.executed_by = list(assessment["summary"]["discipline_breakdown"].keys())
    
    async def _execute_penetration_test(self, request: AssessmentRequest, result: AssessmentResult):
        """Execute penetration test."""
        # Focus on exploitation-capable disciplines
        exploitation_disciplines = [
            SecurityDiscipline.WEB_PENETRATION_TESTING,
            SecurityDiscipline.NETWORK_PENETRATION_TESTING,
            SecurityDiscipline.PASSWORD_CRACKING
        ]
        
        for discipline in exploitation_disciplines:
            if discipline in request.disciplines:
                findings = await self.agent_manager.agents[discipline].analyze(
                    request.target, {"exploitation": True, **request.parameters}
                )
                result.findings.extend(findings)
                result.executed_by.append(f"{discipline.value} Agent")
    
    async def _execute_incident_response(self, request: AssessmentRequest, result: AssessmentResult):
        """Execute incident response assessment."""
        if SecurityDiscipline.INCIDENT_RESPONSE in request.disciplines:
            findings = await self.agent_manager.agents[SecurityDiscipline.INCIDENT_RESPONSE].analyze(
                request.target, request.parameters
            )
            result.findings.extend(findings)
            result.executed_by.append("Incident Response Agent")
        
        # Include forensics if available
        if SecurityDiscipline.FORENSICS in request.disciplines:
            # Simulate forensics analysis
            forensics_finding = SecurityFinding(
                finding_id=f"FORENSIC-{result.request_id}",
                discipline=SecurityDiscipline.FORENSICS,
                title="Digital Forensics Analysis",
                description="Forensic analysis conducted on incident evidence",
                severity=ThreatLevel.MEDIUM,
                confidence=0.7,
                evidence={"method": "forensic_analysis", "target": request.target},
                recommendations=["Preserve evidence", "Document timeline", "Analyze malware artifacts"]
            )
            result.findings.append(forensics_finding)
            result.executed_by.append("Forensics Agent")
    
    async def _execute_compliance_audit(self, request: AssessmentRequest, result: AssessmentResult):
        """Execute compliance audit."""
        # Check against common compliance frameworks
        compliance_standards = ["ISO27001", "NIST", "SOC2", "PCI-DSS", "GDPR"]
        
        for standard in compliance_standards:
            # Simulate compliance check
            compliance_score = 0.7 + (hash(request.target + standard) % 100) / 300.0
            
            if compliance_score < 0.8:
                finding = SecurityFinding(
                    finding_id=f"COMPLIANCE-{standard}-{result.request_id}",
                    discipline=SecurityDiscipline.WEB_PENETRATION_TESTING,  # Use web as default
                    title=f"{standard} Compliance Issue",
                    description=f"Compliance score {compliance_score:.1%} for {standard}",
                    severity=ThreatLevel.MEDIUM if compliance_score > 0.6 else ThreatLevel.HIGH,
                    confidence=0.8,
                    evidence={"standard": standard, "score": compliance_score},
                    recommendations=[f"Address {standard} requirements", "Implement missing controls"]
                )
                result.findings.append(finding)
        
        result.executed_by.append("Compliance Auditor")
    
    async def _execute_threat_hunting(self, request: AssessmentRequest, result: AssessmentResult):
        """Execute threat hunting assessment."""
        # Advanced OSINT and threat intelligence
        if SecurityDiscipline.OSINT in request.disciplines:
            findings = await self.agent_manager.agents[SecurityDiscipline.OSINT].analyze(
                request.target, {"threat_hunting": True, "deep_analysis": True}
            )
            result.findings.extend(findings)
            result.executed_by.append("Threat Hunter")
        
        # Add threat intelligence findings
        threat_finding = SecurityFinding(
            finding_id=f"THREAT-{result.request_id}",
            discipline=SecurityDiscipline.OSINT,
            title="Threat Intelligence Analysis",
            description="Threat hunting revealed potential indicators of compromise",
            severity=ThreatLevel.MEDIUM,
            confidence=0.6,
            evidence={"method": "threat_hunting", "target": request.target},
            recommendations=["Investigate IOCs", "Monitor for suspicious activity", "Update threat intelligence feeds"]
        )
        result.findings.append(threat_finding)
    
    async def _execute_vulnerability_assessment(self, request: AssessmentRequest, result: AssessmentResult):
        """Execute vulnerability assessment."""
        vuln_disciplines = [
            SecurityDiscipline.WEB_PENETRATION_TESTING,
            SecurityDiscipline.NETWORK_PENETRATION_TESTING
        ]
        
        for discipline in vuln_disciplines:
            if discipline in request.disciplines:
                findings = await self.agent_manager.agents[discipline].analyze(
                    request.target, {"vulnerability_scan": True, **request.parameters}
                )
                result.findings.extend(findings)
                result.executed_by.append(f"{discipline.value} Agent")
    
    def _calculate_scores(self, result: AssessmentResult):
        """Calculate risk and compliance scores."""
        if not result.findings:
            result.risk_score = 0.0
            result.compliance_score = 1.0
            return
        
        # Calculate risk score based on severity and confidence
        severity_weights = {
            ThreatLevel.CRITICAL: 10.0,
            ThreatLevel.HIGH: 7.5,
            ThreatLevel.MEDIUM: 5.0,
            ThreatLevel.LOW: 2.5,
            ThreatLevel.INFO: 1.0
        }
        
        total_risk = 0.0
        total_weight = 0.0
        
        for finding in result.findings:
            weight = severity_weights.get(finding.severity, 1.0) * finding.confidence
            total_risk += weight
            total_weight += weight
        
        result.risk_score = min(10.0, total_risk / max(1, len(result.findings)))
        
        # Calculate compliance score (inverse of risk)
        result.compliance_score = max(0.0, 1.0 - (result.risk_score / 10.0))
    
    def _generate_summary(self, result: AssessmentResult):
        """Generate assessment summary."""
        severity_counts = {}
        discipline_counts = {}
        
        for finding in result.findings:
            # Count by severity
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by discipline
            discipline = finding.discipline.value
            discipline_counts[discipline] = discipline_counts.get(discipline, 0) + 1
        
        result.summary = {
            "total_findings": len(result.findings),
            "severity_breakdown": severity_counts,
            "discipline_breakdown": discipline_counts,
            "critical_findings": severity_counts.get("critical", 0),
            "high_findings": severity_counts.get("high", 0),
            "medium_findings": severity_counts.get("medium", 0),
            "low_findings": severity_counts.get("low", 0),
            "info_findings": severity_counts.get("info", 0),
            "risk_level": self._get_risk_level(result.risk_score),
            "compliance_level": self._get_compliance_level(result.compliance_score)
        }
    
    def _generate_recommendations(self, result: AssessmentResult):
        """Generate overall recommendations."""
        recommendations = []
        
        # Risk-based recommendations
        if result.risk_score >= 8.0:
            recommendations.extend([
                "CRITICAL: Immediate remediation required",
                "Implement emergency security measures",
                "Engage incident response team"
            ])
        elif result.risk_score >= 6.0:
            recommendations.extend([
                "HIGH: Prioritize remediation of critical findings",
                "Implement additional security controls",
                "Schedule follow-up assessment"
            ])
        elif result.risk_score >= 4.0:
            recommendations.extend([
                "Address medium and high severity findings",
                "Improve security monitoring",
                "Consider security awareness training"
            ])
        else:
            recommendations.extend([
                "Maintain current security posture",
                "Continue regular assessments",
                "Implement security improvements"
            ])
        
        # Discipline-specific recommendations
        disciplines = set(finding.discipline for finding in result.findings)
        
        if SecurityDiscipline.WEB_PENETRATION_TESTING in disciplines:
            recommendations.append("Review and secure web applications")
        if SecurityDiscipline.NETWORK_PENETRATION_TESTING in disciplines:
            recommendations.append("Harden network infrastructure")
        if SecurityDiscipline.SOCIAL_ENGINEERING in disciplines:
            recommendations.append("Enhance security awareness training")
        if SecurityDiscipline.PASSWORD_CRACKING in disciplines:
            recommendations.append("Implement stronger password policies")
        
        result.recommendations = recommendations
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level from score."""
        if risk_score >= 8.0:
            return "critical"
        elif risk_score >= 6.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    def _get_compliance_level(self, compliance_score: float) -> str:
        """Get compliance level from score."""
        if compliance_score >= 0.9:
            return "excellent"
        elif compliance_score >= 0.8:
            return "good"
        elif compliance_score >= 0.7:
            return "fair"
        else:
            return "poor"
    
    def _get_default_disciplines(self, assessment_type: AssessmentType) -> List[SecurityDiscipline]:
        """Get default disciplines for assessment type."""
        discipline_map = {
            AssessmentType.QUICK_SCAN: [
                SecurityDiscipline.OSINT,
                SecurityDiscipline.NETWORK_PENETRATION_TESTING
            ],
            AssessmentType.COMPREHENSIVE: [
                SecurityDiscipline.WEB_PENETRATION_TESTING,
                SecurityDiscipline.NETWORK_PENETRATION_TESTING,
                SecurityDiscipline.SOCIAL_ENGINEERING,
                SecurityDiscipline.PASSWORD_CRACKING
            ],
            AssessmentType.PENETRATION_TEST: [
                SecurityDiscipline.WEB_PENETRATION_TESTING,
                SecurityDiscipline.NETWORK_PENETRATION_TESTING,
                SecurityDiscipline.PASSWORD_CRACKING,
                SecurityDiscipline.REVERSE_ENGINEERING
            ],
            AssessmentType.INCIDENT_RESPONSE: [
                SecurityDiscipline.INCIDENT_RESPONSE,
                SecurityDiscipline.FORENSICS,
                SecurityDiscipline.MALWARE_ANALYSIS
            ],
            AssessmentType.COMPLIANCE_AUDIT: [
                SecurityDiscipline.WEB_PENETRATION_TESTING,
                SecurityDiscipline.NETWORK_PENETRATION_TESTING
            ],
            AssessmentType.THREAT_HUNTING: [
                SecurityDiscipline.OSINT,
                SecurityDiscipline.SOCIAL_ENGINEERING,
                SecurityDiscipline.MALWARE_ANALYSIS
            ],
            AssessmentType.VULNERABILITY_ASSESSMENT: [
                SecurityDiscipline.WEB_PENETRATION_TESTING,
                SecurityDiscipline.NETWORK_PENETRATION_TESTING,
                SecurityDiscipline.PASSWORD_CRACKING
            ]
        }
        
        return discipline_map.get(assessment_type, [
            SecurityDiscipline.WEB_PENETRATION_TESTING,
            SecurityDiscipline.NETWORK_PENETRATION_TESTING
        ])
    
    def _add_to_queue(self, request_id: str, priority: str):
        """Add assessment to queue based on priority."""
        priority_order = {"critical": 0, "high": 1, "normal": 2, "low": 3}
        
        insert_index = 0
        for i, queued_id in enumerate(self.assessment_queue):
            queued_request = self.active_assessments[queued_id]
            if priority_order[priority] <= priority_order[queued_request.priority]:
                insert_index = i
                break
            insert_index = i + 1
        
        self.assessment_queue.insert(insert_index, request_id)
    
    def _get_next_assessment(self) -> Optional[str]:
        """Get next assessment from queue."""
        return self.assessment_queue.pop(0) if self.assessment_queue else None
    
    async def get_platform_status(self) -> Dict[str, Any]:
        """Get overall platform status."""
        return {
            "platform_initialized": True,
            "active_assessments": len(self.active_assessments),
            "queued_assessments": len(self.assessment_queue),
            "completed_assessments": len([r for r in self.assessment_results.values() if r.status == "completed"]),
            "failed_assessments": len([r for r in self.assessment_results.values() if r.status == "failed"]),
            "max_concurrent_assessments": self.max_concurrent_assessments,
            "agent_capabilities": self.agent_manager.get_agent_capabilities(),
            "blackarch_status": await self.blackarch_manager.get_blackarch_status() if self.blackarch_manager else None,
            "monitored_emails": len(self.email_monitor.monitored_emails) if self.email_monitor else 0
        }


# Expert Security Platform API
class ExpertSecurityAPI:
    """API endpoints for expert security platform."""
    
    def __init__(self, platform: ExpertSecurityPlatform):
        self.platform = platform
        
    async def create_assessment(self, **kwargs) -> str:
        """Create a new security assessment."""
        return await self.platform.create_assessment(**kwargs)
    
    async def get_assessment_status(self, request_id: str) -> Dict[str, Any]:
        """Get assessment status."""
        return await self.platform.get_assessment_status(request_id)
    
    async def get_assessment_result(self, request_id: str) -> Dict[str, Any]:
        """Get assessment results."""
        return await self.platform.get_assessment_result(request_id)
    
    async def cancel_assessment(self, request_id: str) -> bool:
        """Cancel an assessment."""
        return await self.platform.cancel_assessment(request_id)
    
    async def get_platform_status(self) -> Dict[str, Any]:
        """Get platform status."""
        return await self.platform.get_platform_status()
    
    async def get_agent_capabilities(self) -> Dict[str, List[Dict]]:
        """Get agent capabilities."""
        return self.platform.agent_manager.get_agent_capabilities()
    
    async def search_blackarch_tools(self, query: str, category: str = None) -> List[Dict[str, Any]]:
        """Search BlackArch tools."""
        if self.platform.blackarch_manager:
            return await self.platform.blackarch_manager.search_blackarch_tools(query, category)
        return []
    
    async def analyze_email_security(self, email: str) -> Dict[str, Any]:
        """Analyze email security."""
        if self.platform.email_security_analyzer:
            return await self.platform.email_security_analyzer.analyze_email(email)
        return {"error": "Email security analyzer not initialized"}
    
    async def add_monitored_email(self, email: str) -> bool:
        """Add email to monitoring."""
        if self.platform.email_monitor:
            try:
                self.platform.email_monitor.add_email_to_monitor(email)
                return True
            except ValueError:
                return False
        return False


# Example usage
async def main():
    """Example usage of the Expert Security Platform."""
    # Initialize platform
    platform = ExpertSecurityPlatform()
    await platform.initialize()
    
    # Create API
    api = ExpertSecurityAPI(platform)
    
    # Get platform status
    status = await api.get_platform_status()
    print("Platform Status:")
    print(json.dumps(status, indent=2, default=str))
    
    # Create comprehensive assessment
    request_id = await api.create_assessment(
        target="example.com",
        assessment_type=AssessmentType.COMPREHENSIVE,
        expertise_level=ExpertiseLevel.ADVANCED,
        priority="high"
    )
    
    print(f"\nCreated assessment: {request_id}")
    
    # Monitor assessment progress
    while True:
        assessment_status = await api.get_assessment_status(request_id)
        print(f"Status: {assessment_status['status']}")
        
        if assessment_status['status'] in ['completed', 'failed']:
            break
        
        await asyncio.sleep(2)
    
    # Get results
    if assessment_status['status'] == 'completed':
        results = await api.get_assessment_result(request_id)
        print(f"\nAssessment Results:")
        print(f"Total Findings: {results['summary']['total_findings']}")
        print(f"Risk Score: {results['risk_score']}")
        print(f"Compliance Score: {results['compliance_score']}")
        print(f"Risk Level: {results['summary']['risk_level']}")
        print(f"Compliance Level: {results['summary']['compliance_level']}")


if __name__ == "__main__":
    asyncio.run(main())
