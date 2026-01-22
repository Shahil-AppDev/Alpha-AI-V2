"""
Specialized Security Agents for HackerAI Platform

This module defines expert agents for each security discipline with deep
domain knowledge and specialized tool integration.
"""

import asyncio
import json
import logging
import re
import subprocess
import tempfile
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Callable
import aiohttp
import aiofiles
import hashlib
import base64

from modules.universal_tool_manager import UniversalToolManager, ToolCategory, ExecutionMode

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityDiscipline(Enum):
    """Security disciplines for specialized agents."""
    WEB_PENETRATION_TESTING = "web_penetration_testing"
    NETWORK_PENETRATION_TESTING = "network_penetration_testing"
    SOCIAL_ENGINEERING = "social_engineering"
    OSINT = "osint"
    PASSWORD_CRACKING = "password_cracking"
    REVERSE_ENGINEERING = "reverse_engineering"
    MALWARE_ANALYSIS = "malware_analysis"
    EXPLOIT_DEVELOPMENT = "exploit_development"
    INCIDENT_RESPONSE = "incident_response"
    FORENSICS = "forensics"
    EMAIL_SECURITY = "email_security"


class ThreatLevel(Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityFinding:
    """Security finding from analysis."""
    finding_id: str
    discipline: SecurityDiscipline
    title: str
    description: str
    severity: ThreatLevel
    confidence: float
    evidence: Dict[str, Any]
    recommendations: List[str]
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class AgentCapability:
    """Agent capability definition."""
    name: str
    description: str
    tools: List[str]
    techniques: List[str]
    certifications: List[str]
    experience_years: int


class SecurityAgent(ABC):
    """Base class for specialized security agents."""
    
    def __init__(self, tool_manager: UniversalToolManager):
        self.tool_manager = tool_manager
        self.agent_id = str(uuid.uuid4())
        self.capabilities = self._define_capabilities()
        self.findings: List[SecurityFinding] = []
        self.active_tasks: Dict[str, Dict] = {}
        
    @abstractmethod
    def _define_capabilities(self) -> List[AgentCapability]:
        """Define agent's specific capabilities."""
        pass
    
    @abstractmethod
    async def analyze(self, target: str, parameters: Dict[str, Any] = None) -> List[SecurityFinding]:
        """Perform security analysis."""
        pass
    
    async def execute_tool_chain(self, tool_chain: List[Dict], target: str) -> Dict[str, Any]:
        """Execute a chain of tools for comprehensive analysis."""
        results = {}
        
        for tool_config in tool_chain:
            tool_name = tool_config["tool"]
            tool_params = tool_config.get("parameters", {})
            
            try:
                execution = await self.tool_manager.execute_tool(
                    tool_name, target, tool_params
                )
                
                results[tool_name] = {
                    "status": execution.status,
                    "output": execution.output,
                    "error": execution.error,
                    "execution_id": execution.execution_id
                }
                
                # Stop chain if critical tool fails
                if execution.status == "failed" and tool_config.get("critical", False):
                    logger.error(f"Critical tool {tool_name} failed, stopping chain")
                    break
                    
            except Exception as e:
                logger.error(f"Error executing {tool_name}: {e}")
                results[tool_name] = {
                    "status": "failed",
                    "error": str(e)
                }
        
        return results


class WebPenetrationTester(SecurityAgent):
    """Specialized web application penetration testing agent."""
    
    def _define_capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="OWASP Top 10 Testing",
                description="Comprehensive testing for OWASP Top 10 vulnerabilities",
                tools=["burpsuite", "zaproxy", "sqlmap", "nikto", "dirb", "gobuster"],
                techniques=["SQL Injection", "XSS", "CSRF", "Authentication Bypass", "Privilege Escalation"],
                certifications=["OSWE", "OSCP", "GWAPT"],
                experience_years=8
            ),
            AgentCapability(
                name="API Security Testing",
                description="REST/GraphQL API security assessment",
                tools=["burpsuite", "postman", "owasp-zap-api", "jwt-cracker"],
                techniques=["JWT Attacks", "Rate Limiting Bypass", "API Enumeration", "BOLA Testing"],
                certifications=["OSWE", "CRTP"],
                experience_years=6
            ),
            AgentCapability(
                name="Business Logic Testing",
                description="Complex business logic vulnerability assessment",
                tools=["burpsuite", "intruder", "sequencer", "decoder"],
                techniques=["Race Conditions", "Logic Flaws", "Workflow Bypass", "Parameter Pollution"],
                certifications=["OSWE", "OSCP"],
                experience_years=7
            )
        ]
    
    async def analyze(self, target: str, parameters: Dict[str, Any] = None) -> List[SecurityFinding]:
        """Perform comprehensive web application security analysis."""
        findings = []
        params = parameters or {}
        
        # Phase 1: Reconnaissance and Mapping
        recon_tools = [
            {"tool": "nikto", "parameters": {"host": target, "port": params.get("port", 80)}},
            {"tool": "gobuster", "parameters": {"url": target, "wordlist": "/usr/share/wordlists/common.txt"}},
            {"tool": "dirb", "parameters": {"target": target, "wordlist": "/usr/share/dirb/wordlists/common.txt"}}
        ]
        
        recon_results = await self.execute_tool_chain(recon_tools, target)
        
        # Analyze reconnaissance results
        for tool_name, result in recon_results.items():
            if result["status"] == "completed":
                findings.extend(self._analyze_recon_output(tool_name, result["output"], target))
        
        # Phase 2: Vulnerability Scanning
        vuln_tools = [
            {"tool": "sqlmap", "parameters": {"url": target, "batch": True, "level": 1}, "critical": True},
            {"tool": "zaproxy", "parameters": {"target": target, "quick": True}}
        ]
        
        vuln_results = await self.execute_tool_chain(vuln_tools, target)
        
        # Analyze vulnerability results
        for tool_name, result in vuln_results.items():
            if result["status"] == "completed":
                findings.extend(self._analyze_vuln_output(tool_name, result["output"], target))
        
        # Phase 3: Manual Testing (simulated)
        if params.get("deep_analysis", False):
            manual_findings = await self._perform_manual_testing(target)
            findings.extend(manual_findings)
        
        return findings
    
    def _analyze_recon_output(self, tool: str, output: str, target: str) -> List[SecurityFinding]:
        """Analyze reconnaissance tool output for security findings."""
        findings = []
        
        if tool == "nikto":
            # Parse Nikto output for vulnerabilities
            vuln_pattern = r"OSVDB-(\d+):\s+(.+)"
            matches = re.findall(vuln_pattern, output)
            
            for osvdb_id, description in matches:
                severity = self._assess_nikto_severity(description)
                
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    discipline=SecurityDiscipline.WEB_PENETRATION_TESTING,
                    title=f"Web Server Vulnerability (OSVDB-{osvdb_id})",
                    description=description.strip(),
                    severity=severity,
                    confidence=0.8,
                    evidence={"tool": "nikto", "osvdb_id": osvdb_id, "output": description},
                    recommendations=["Update web server software", "Review server configuration"]
                )
                findings.append(finding)
        
        elif tool in ["gobuster", "dirb"]:
            # Analyze discovered directories/files
            interesting_patterns = [
                r"admin", r"backup", r"config", r"database", r"logs",
                r"test", r"dev", r"staging", r".git", r".env"
            ]
            
            lines = output.split('\n')
            for line in lines:
                for pattern in interesting_patterns:
                    if pattern in line.lower():
                        finding = SecurityFinding(
                            finding_id=str(uuid.uuid4()),
                            discipline=SecurityDiscipline.WEB_PENETRATION_TESTING,
                            title=f"Potentially Sensitive Directory/File Found",
                            description=f"Discovered potentially sensitive path: {line.strip()}",
                            severity=ThreatLevel.MEDIUM,
                            confidence=0.7,
                            evidence={"tool": tool, "path": line.strip()},
                            recommendations=["Verify if the path should be accessible", "Implement proper access controls"]
                        )
                        findings.append(finding)
                        break
        
        return findings
    
    def _analyze_vuln_output(self, tool: str, output: str, target: str) -> List[SecurityFinding]:
        """Analyze vulnerability scanning tool output."""
        findings = []
        
        if tool == "sqlmap":
            # Parse SQLMap results
            if "is vulnerable" in output.lower():
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    discipline=SecurityDiscipline.WEB_PENETRATION_TESTING,
                    title="SQL Injection Vulnerability Detected",
                    description="SQL injection vulnerability identified in target application",
                    severity=ThreatLevel.HIGH,
                    confidence=0.9,
                    evidence={"tool": "sqlmap", "output": output},
                    recommendations=["Implement parameterized queries", "Use prepared statements", "Input validation"]
                )
                findings.append(finding)
        
        elif tool == "zaproxy":
            # Parse OWASP ZAP results
            if "High" in output or "Critical" in output:
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    discipline=SecurityDiscipline.WEB_PENETRATION_TESTING,
                    title="High-Severity Web Application Vulnerability",
                    description="OWASP ZAP identified high-severity vulnerabilities",
                    severity=ThreatLevel.HIGH,
                    confidence=0.8,
                    evidence={"tool": "zaproxy", "output": output},
                    recommendations=["Review ZAP report for detailed findings", "Prioritize remediation based on risk"]
                )
                findings.append(finding)
        
        return findings
    
    def _assess_nikto_severity(self, description: str) -> ThreatLevel:
        """Assess severity of Nikto findings."""
        description_lower = description.lower()
        
        if any(term in description_lower for term in ["remote", "code execution", "privilege escalation"]):
            return ThreatLevel.CRITICAL
        elif any(term in description_lower for term in ["sql injection", "xss", "csrf"]):
            return ThreatLevel.HIGH
        elif any(term in description_lower for term in ["information disclosure", "directory listing"]):
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    async def _perform_manual_testing(self, target: str) -> List[SecurityFinding]:
        """Simulate manual web application testing."""
        findings = []
        
        # Simulate business logic testing
        finding = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            discipline=SecurityDiscipline.WEB_PENETRATION_TESTING,
            title="Business Logic Vulnerability Assessment",
            description="Manual testing revealed potential business logic flaws requiring further investigation",
            severity=ThreatLevel.MEDIUM,
            confidence=0.6,
            evidence={"method": "manual_testing", "target": target},
            recommendations=["Conduct thorough business logic review", "Test workflow bypasses", "Review authorization controls"]
        )
        findings.append(finding)
        
        return findings


class NetworkPenetrationTester(SecurityAgent):
    """Specialized network penetration testing agent."""
    
    def _define_capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="Network Enumeration",
                description="Comprehensive network discovery and mapping",
                tools=["nmap", "masscan", "unicornscan", "netdiscover"],
                techniques=["Port Scanning", "Service Enumeration", "OS Fingerprinting", "Network Mapping"],
                certifications=["OSCP", "OSCE", "PNPT"],
                experience_years=10
            ),
            AgentCapability(
                name="Network Exploitation",
                description="Network service exploitation and post-exploitation",
                tools=["metasploit", "hydra", "medusa", "ncrack"],
                techniques=["Service Exploitation", "Password Attacks", "Lateral Movement", "Privilege Escalation"],
                certifications=["OSCE", "OSED", "CRTP"],
                experience_years=8
            ),
            AgentCapability(
                name="Wireless Security",
                description="Wireless network security assessment",
                tools=["aircrack-ng", "bettercap", "kismet", "wifite"],
                techniques=["WiFi Cracking", "Evil Twin Attacks", "Deauthentication", "WPS Attacks"],
                certifications=["OSWP", "CWNA"],
                experience_years=6
            )
        ]
    
    async def analyze(self, target: str, parameters: Dict[str, Any] = None) -> List[SecurityFinding]:
        """Perform comprehensive network security analysis."""
        findings = []
        params = parameters or {}
        
        # Phase 1: Network Discovery
        discovery_tools = [
            {"tool": "nmap", "parameters": {"target": target, "scan_type": "-sS -sV -O"}},
            {"tool": "masscan", "parameters": {"target": target, "ports": "1-65535", "rate": "1000"}}
        ]
        
        discovery_results = await self.execute_tool_chain(discovery_tools, target)
        
        # Analyze discovery results
        for tool_name, result in discovery_results.items():
            if result["status"] == "completed":
                findings.extend(self._analyze_network_output(tool_name, result["output"], target))
        
        # Phase 2: Service Enumeration
        if params.get("deep_scan", False):
            enum_tools = [
                {"tool": "nmap", "parameters": {"target": target, "scan_type": "-sC -sV --script=default,safe"}}
            ]
            
            enum_results = await self.execute_tool_chain(enum_tools, target)
            
            for tool_name, result in enum_results.items():
                if result["status"] == "completed":
                    findings.extend(self._analyze_service_output(tool_name, result["output"], target))
        
        # Phase 3: Vulnerability Assessment
        vuln_tools = [
            {"tool": "nikto", "parameters": {"host": target, "port": params.get("web_ports", "80,443,8080")}}
        ]
        
        vuln_results = await self.execute_tool_chain(vuln_tools, target)
        
        for tool_name, result in vuln_results.items():
            if result["status"] == "completed":
                findings.extend(self._analyze_vuln_output(tool_name, result["output"], target))
        
        return findings
    
    def _analyze_network_output(self, tool: str, output: str, target: str) -> List[SecurityFinding]:
        """Analyze network scanning tool output."""
        findings = []
        
        if tool == "nmap":
            # Parse Nmap output for open ports and services
            port_pattern = r"(\d+)/tcp\s+open\s+([^\s]+)"
            matches = re.findall(port_pattern, output)
            
            for port, service in matches:
                # Check for commonly vulnerable services
                vulnerable_services = {
                    "telnet": ThreatLevel.HIGH,
                    "ftp": ThreatLevel.MEDIUM,
                    "smtp": ThreatLevel.LOW,
                    "dns": ThreatLevel.LOW,
                    "snmp": ThreatLevel.MEDIUM
                }
                
                if service in vulnerable_services:
                    finding = SecurityFinding(
                        finding_id=str(uuid.uuid4()),
                        discipline=SecurityDiscipline.NETWORK_PENETRATION_TESTING,
                        title=f"Potentially Vulnerable Service: {service}",
                        description=f"Service {service} running on port {port} may have known vulnerabilities",
                        severity=vulnerable_services[service],
                        confidence=0.8,
                        evidence={"tool": "nmap", "port": port, "service": service},
                        recommendations=[f"Review {service} configuration", "Check for available patches", "Consider disabling if not needed"]
                    )
                    findings.append(finding)
        
        elif tool == "masscan":
            # Analyze masscan results for exposed services
            if "open" in output:
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    discipline=SecurityDiscipline.NETWORK_PENETRATION_TESTING,
                    title="Network Exposure Detected",
                    description="Masscan discovered exposed services on the network",
                    severity=ThreatLevel.MEDIUM,
                    confidence=0.7,
                    evidence={"tool": "masscan", "output": output},
                    recommendations=["Review exposed services", "Implement network segmentation", "Apply firewall rules"]
                )
                findings.append(finding)
        
        return findings
    
    def _analyze_service_output(self, tool: str, output: str, target: str) -> List[SecurityFinding]:
        """Analyze service enumeration output."""
        findings = []
        
        # Look for default credentials or weak configurations
        weak_indicators = [
            "default", "admin", "password", "guest", "test", "demo"
        ]
        
        for indicator in weak_indicators:
            if indicator.lower() in output.lower():
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    discipline=SecurityDiscipline.NETWORK_PENETRATION_TESTING,
                    title="Potential Default Credentials Detected",
                    description=f"Service enumeration revealed potential default credentials or weak configuration",
                    severity=ThreatLevel.HIGH,
                    confidence=0.6,
                    evidence={"tool": tool, "indicator": indicator},
                    recommendations=["Change default credentials", "Review service configuration", "Implement strong authentication"]
                )
                findings.append(finding)
                break
        
        return findings
    
    def _analyze_vuln_output(self, tool: str, output: str, target: str) -> List[SecurityFinding]:
        """Analyze network vulnerability scanning output."""
        findings = []
        
        if tool == "nikto" and "vulnerable" in output.lower():
            finding = SecurityFinding(
                finding_id=str(uuid.uuid4()),
                discipline=SecurityDiscipline.NETWORK_PENETRATION_TESTING,
                title="Network Service Vulnerability",
                description="Network service scanning identified security vulnerabilities",
                severity=ThreatLevel.HIGH,
                confidence=0.8,
                evidence={"tool": "nikto", "output": output},
                recommendations=["Update vulnerable services", "Apply security patches", "Review service configurations"]
            )
            findings.append(finding)
        
        return findings


class SocialEngineeringAgent(SecurityAgent):
    """Specialized social engineering and OSINT agent."""
    
    def _define_capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="OSINT Intelligence Gathering",
                description="Comprehensive open-source intelligence collection",
                tools=["theharvester", "sherlock", "recon-ng", "maltego", "spiderfoot"],
                techniques=["Email Harvesting", "Username Enumeration", "Domain Intelligence", "Social Media Analysis"],
                certifications=["OSINT", "GOSINT", "CDSA"],
                experience_years=7
            ),
            AgentCapability(
                name="Social Engineering Campaigns",
                description="Phishing and social engineering attack simulation",
                tools=["setoolkit", "beef", "ettercap", "bettercap"],
                techniques=["Phishing Campaigns", "Spear Phishing", "Vishing", "Physical Security Testing"],
                certifications=["Social Engineering", "CREST", "SANS SEC542"],
                experience_years=5
            ),
            AgentCapability(
                name="Human Intelligence (HUMINT)",
                description="Human intelligence gathering and analysis",
                tools=["maltego", "spiderfoot", "recon-ng"],
                techniques=["Target Profiling", "Behavioral Analysis", "Psychological Profiling", "Organization Mapping"],
                certifications=["HUMINT", "Behavioral Analysis"],
                experience_years=6
            )
        ]
    
    async def analyze(self, target: str, parameters: Dict[str, Any] = None) -> List[SecurityFinding]:
        """Perform comprehensive OSINT and social engineering analysis."""
        findings = []
        params = parameters or {}
        
        # Phase 1: OSINT Data Collection
        osint_tools = [
            {"tool": "theharvester", "parameters": {"domain": target, "source": "all"}},
            {"tool": "sherlock", "parameters": {"username": params.get("username", target)}},
            {"tool": "recon-ng", "parameters": {"module": "recon/domains-hosts/google_site_web"}}
        ]
        
        osint_results = await self.execute_tool_chain(osint_tools, target)
        
        # Analyze OSINT results
        for tool_name, result in osint_results.items():
            if result["status"] == "completed":
                findings.extend(self._analyze_osint_output(tool_name, result["output"], target))
        
        # Phase 2: Email Analysis
        if "@" in target:
            email_findings = await self._analyze_email_address(target)
            findings.extend(email_findings)
        
        # Phase 3: Organization Mapping
        if params.get("org_analysis", False):
            org_findings = await self._analyze_organization(target)
            findings.extend(org_findings)
        
        # Phase 4: Social Engineering Assessment
        if params.get("se_assessment", False):
            se_findings = await self._assess_social_engineering_risk(target)
            findings.extend(se_findings)
        
        return findings
    
    def _analyze_osint_output(self, tool: str, output: str, target: str) -> List[SecurityFinding]:
        """Analyze OSINT tool output for security findings."""
        findings = []
        
        if tool == "theharvester":
            # Parse harvested emails and subdomains
            email_pattern = r"[\w\.-]+@[\w\.-]+\.\w+"
            emails = re.findall(email_pattern, output)
            
            if len(emails) > 10:
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    discipline=SecurityDiscipline.SOCIAL_ENGINEERING,
                    title="Extensive Email Exposure Detected",
                    description=f"Discovered {len(emails)} email addresses associated with {target}",
                    severity=ThreatLevel.MEDIUM,
                    confidence=0.9,
                    evidence={"tool": "theharvester", "email_count": len(emails), "sample": emails[:5]},
                    recommendations=["Implement email protection policies", "Monitor for email-based attacks", "Consider email address obfuscation"]
                )
                findings.append(finding)
        
        elif tool == "sherlock":
            # Analyze username findings
            if "found" in output.lower():
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    discipline=SecurityDiscipline.SOCIAL_ENGINEERING,
                    title="Social Media Footprint Detected",
                    description="Username found across multiple social media platforms",
                    severity=ThreatLevel.LOW,
                    confidence=0.8,
                    evidence={"tool": "sherlock", "output": output},
                    recommendations=["Review social media privacy settings", "Monitor for social engineering attacks", "Implement username variation policies"]
                )
                findings.append(finding)
        
        return findings
    
    async def _analyze_email_address(self, email: str) -> List[SecurityFinding]:
        """Analyze email address for breaches and exposure."""
        findings = []
        
        # Check against HaveIBeenPwned (simulated)
        breach_check = await self._check_breached_accounts(email)
        
        if breach_check["breached"]:
            finding = SecurityFinding(
                finding_id=str(uuid.uuid4()),
                discipline=SecurityDiscipline.SOCIAL_ENGINEERING,
                title="Email Address Found in Data Breaches",
                description=f"Email {email} appeared in {len(breach_check['breaches'])} known data breaches",
                severity=ThreatLevel.HIGH,
                confidence=0.9,
                evidence={"email": email, "breaches": breach_check["breaches"]},
                recommendations=["Change password immediately", "Enable multi-factor authentication", "Monitor for suspicious activity"]
            )
            findings.append(finding)
        
        return findings
    
    async def _analyze_organization(self, target: str) -> List[SecurityFinding]:
        """Analyze organization structure and hierarchy."""
        findings = []
        
        # Simulate organization mapping
        finding = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            discipline=SecurityDiscipline.SOCIAL_ENGINEERING,
            title="Organizational Structure Mapped",
            description=f"OSINT analysis revealed organizational structure and key personnel for {target}",
            severity=ThreatLevel.MEDIUM,
            confidence=0.7,
            evidence={"target": target, "method": "osint_mapping"},
            recommendations=["Review public information disclosure", "Implement employee privacy policies", "Monitor for executive targeting"]
        )
        findings.append(finding)
        
        return findings
    
    async def _assess_social_engineering_risk(self, target: str) -> List[SecurityFinding]:
        """Assess social engineering risk factors."""
        findings = []
        
        # Simulate risk assessment
        risk_factors = [
            "Public employee information available",
            "Weak security awareness program",
            "Excessive social media presence",
            "Lack of phishing training"
        ]
        
        finding = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            discipline=SecurityDiscipline.SOCIAL_ENGINEERING,
            title="Social Engineering Risk Assessment",
            description=f"Assessment identified {len(risk_factors)} social engineering risk factors",
            severity=ThreatLevel.MEDIUM,
            confidence=0.6,
            evidence={"target": target, "risk_factors": risk_factors},
            recommendations=["Implement security awareness training", "Conduct phishing simulations", "Review information disclosure policies"]
        )
        findings.append(finding)
        
        return findings
    
    async def _check_breached_accounts(self, email: str) -> Dict[str, Any]:
        """Check if email appears in known breaches (simulated)."""
        # Simulate breach check - in real implementation, use HaveIBeenPwned API
        breached_domains = ["linkedin.com", "adobe.com", "dropbox.com"]
        
        # Simulate finding breaches
        breaches_found = []
        for domain in breached_domains:
            if domain in email.lower() or hash(email) % 3 == 0:  # Simulate random matches
                breaches_found.append(f"{domain.title()} breach")
        
        return {
            "breached": len(breaches_found) > 0,
            "breaches": breaches_found
        }


class PasswordCrackingAgent(SecurityAgent):
    """Specialized password cracking and recovery agent."""
    
    def _define_capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="Hash Cracking",
                description="Advanced password hash cracking techniques",
                tools=["hashcat", "john", "ophcrack"],
                techniques=["Dictionary Attacks", "Brute Force", "Rainbow Tables", "Rule-based Attacks"],
                certifications=["Password Cracking", "Hashcat Certified"],
                experience_years=8
            ),
            AgentCapability(
                name="Online Password Attacks",
                description="Remote service password attacks",
                tools=["hydra", "medusa", "ncrack", "patator"],
                techniques=["Brute Force", "Dictionary Attacks", "Spray Attacks", "Credential Stuffing"],
                certifications=["OSCP", "Penetration Testing"],
                experience_years=6
            ),
            AgentCapability(
                name="Password Policy Analysis",
                description="Password policy and strength assessment",
                tools=["crunch", "maskprocessor", "princeprocessor"],
                techniques=["Policy Analysis", "Strength Assessment", "Pattern Analysis"],
                certifications=["Security Policy", "Password Security"],
                experience_years=5
            )
        ]
    
    async def analyze(self, target: str, parameters: Dict[str, Any] = None) -> List[SecurityFinding]:
        """Perform password security analysis."""
        findings = []
        params = parameters or {}
        
        # Phase 1: Hash Cracking
        if params.get("hashes"):
            crack_results = await self._crack_hashes(params["hashes"], params.get("wordlist", "rockyou.txt"))
            
            if crack_results["cracked_count"] > 0:
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    discipline=SecurityDiscipline.PASSWORD_CRACKING,
                    title="Password Hashes Successfully Cracked",
                    description=f"Successfully cracked {crack_results['cracked_count']} out of {len(params['hashes'])} password hashes",
                    severity=ThreatLevel.CRITICAL,
                    confidence=1.0,
                    evidence={"cracked_count": crack_results["cracked_count"], "method": crack_results["method"]},
                    recommendations=["Enforce stronger password policies", "Implement multi-factor authentication", "Consider passwordless authentication"]
                )
                findings.append(finding)
        
        # Phase 2: Online Service Testing
        if params.get("services"):
            service_results = await self._test_online_services(target, params["services"])
            
            if service_results["weak_credentials_found"]:
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4()),
                    discipline=SecurityDiscipline.PASSWORD_CRACKING,
                    title="Weak Online Service Credentials Detected",
                    description=f"Discovered weak or default credentials on {len(service_results['vulnerable_services'])} services",
                    severity=ThreatLevel.HIGH,
                    confidence=0.9,
                    evidence={"services": service_results["vulnerable_services"]},
                    recommendations=["Change default passwords", "Implement account lockout policies", "Use strong unique passwords"]
                )
                findings.append(finding)
        
        # Phase 3: Password Policy Assessment
        if params.get("policy_assessment", False):
            policy_findings = await self._assess_password_policies(target)
            findings.extend(policy_findings)
        
        return findings
    
    async def _crack_hashes(self, hashes: List[str], wordlist: str) -> Dict[str, Any]:
        """Crack password hashes using multiple techniques."""
        results = {"cracked_count": 0, "method": "dictionary"}
        
        # Try Hashcat first
        try:
            execution = await self.tool_manager.execute_tool(
                "hashcat", 
                hashes[0],  # Use first hash as target
                {"hash_type": "0", "wordlist": f"/usr/share/wordlists/{wordlist}"}
            )
            
            if execution.status == "completed" and "Recovered" in execution.output:
                results["cracked_count"] = execution.output.count("Recovered")
                results["method"] = "hashcat_dictionary"
            
        except Exception as e:
            logger.error(f"Hashcat cracking failed: {e}")
        
        # Fallback to John the Ripper
        if results["cracked_count"] == 0:
            try:
                execution = await self.tool_manager.execute_tool(
                    "john",
                    hashes[0],
                    {"wordlist": f"/usr/share/wordlists/{wordlist}"}
                )
                
                if execution.status == "completed":
                    results["cracked_count"] = execution.output.count("password")
                    results["method"] = "john_dictionary"
                    
            except Exception as e:
                logger.error(f"John the Ripper cracking failed: {e}")
        
        return results
    
    async def _test_online_services(self, target: str, services: List[str]) -> Dict[str, Any]:
        """Test online services for weak credentials."""
        results = {"weak_credentials_found": False, "vulnerable_services": []}
        
        for service in services:
            try:
                execution = await self.tool_manager.execute_tool(
                    "hydra",
                    target,
                    {
                        "service": service,
                        "username": "admin",
                        "password_file": "/usr/share/wordlists/rockyou.txt"
                    }
                )
                
                if execution.status == "completed" and "login:" in execution.output:
                    results["weak_credentials_found"] = True
                    results["vulnerable_services"].append(service)
                    
            except Exception as e:
                logger.error(f"Service testing failed for {service}: {e}")
        
        return results
    
    async def _assess_password_policies(self, target: str) -> List[SecurityFinding]:
        """Assess password policies and strength."""
        findings = []
        
        # Simulate password policy assessment
        weak_policies = [
            "No minimum length requirement",
            "No complexity requirements",
            "No password history enforcement",
            "No account lockout policy"
        ]
        
        finding = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            discipline=SecurityDiscipline.PASSWORD_CRACKING,
            title="Weak Password Policies Detected",
            description=f"Assessment identified {len(weak_policies)} weak password policy configurations",
            severity=ThreatLevel.MEDIUM,
            confidence=0.7,
            evidence={"target": target, "weak_policies": weak_policies},
            recommendations=["Implement strong password policies", "Enforce complexity requirements", "Set minimum password length"]
        )
        findings.append(finding)
        
        return findings


class ReverseEngineeringAgent(SecurityAgent):
    """Specialized reverse engineering and malware analysis agent."""
    
    def _define_capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="Binary Reverse Engineering",
                description="Advanced binary reverse engineering techniques",
                tools=["ghidra", "radare2", "ida", "objdump", "gdb"],
                techniques=["Static Analysis", "Dynamic Analysis", "Disassembly", "Decompilation"],
                certifications=["GREM", "CREST", "OSCE"],
                experience_years=10
            ),
            AgentCapability(
                name="Malware Analysis",
                description="Comprehensive malware analysis and reverse engineering",
                tools=["cuckoo", "malware-analysis", "yara", "volatility"],
                techniques=["Static Analysis", "Dynamic Analysis", "Memory Forensics", "Behavioral Analysis"],
                certifications=["GREM", "GCIH", "CTIA"],
                experience_years=8
            ),
            AgentCapability(
                name="Firmware Analysis",
                description="Embedded system and firmware reverse engineering",
                tools=["binwalk", "firmware-mod-kit", "ghidra"],
                techniques=["Firmware Extraction", "File System Analysis", "Hardware Analysis"],
                certifications=["Embedded Security", "Hardware Reverse Engineering"],
                experience_years=6
            )
        ]
    
    async def analyze(self, target: str, parameters: Dict[str, Any] = None) -> List[SecurityFinding]:
        """Perform reverse engineering analysis."""
        findings = []
        params = parameters or {}
        
        # Phase 1: Static Analysis
        if params.get("file_path"):
            static_findings = await self._perform_static_analysis(params["file_path"])
            findings.extend(static_findings)
        
        # Phase 2: Dynamic Analysis
        if params.get("dynamic_analysis", False):
            dynamic_findings = await self._perform_dynamic_analysis(params.get("file_path", target))
            findings.extend(dynamic_findings)
        
        # Phase 3: Vulnerability Assessment
        vuln_findings = await self._assess_binary_vulnerabilities(params.get("file_path", target))
        findings.extend(vuln_findings)
        
        return findings
    
    async def _perform_static_analysis(self, file_path: str) -> List[SecurityFinding]:
        """Perform static binary analysis."""
        findings = []
        
        # Simulate static analysis
        vulnerabilities = [
            "Buffer overflow vulnerability detected",
            "Hardcoded credentials found",
            "Weak encryption implementation",
            "Insecure random number generation"
        ]
        
        for vuln in vulnerabilities:
            finding = SecurityFinding(
                finding_id=str(uuid.uuid4()),
                discipline=SecurityDiscipline.REVERSE_ENGINEERING,
                title=f"Static Analysis Finding: {vuln}",
                description=f"Static analysis revealed: {vuln}",
                severity=ThreatLevel.HIGH,
                confidence=0.8,
                evidence={"file": file_path, "method": "static_analysis"},
                recommendations=["Review code implementation", "Apply secure coding practices", "Implement proper input validation"]
            )
            findings.append(finding)
        
        return findings
    
    async def _perform_dynamic_analysis(self, target: str) -> List[SecurityFinding]:
        """Perform dynamic analysis of binary."""
        findings = []
        
        # Simulate dynamic analysis in sandbox
        finding = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            discipline=SecurityDiscipline.REVERSE_ENGINEERING,
            title="Dynamic Analysis Behavior Detected",
            description="Dynamic analysis revealed suspicious runtime behavior",
            severity=ThreatLevel.MEDIUM,
            confidence=0.7,
            evidence={"target": target, "method": "dynamic_analysis"},
            recommendations=["Investigate runtime behavior", "Monitor for malicious activity", "Implement runtime protections"]
        )
        findings.append(finding)
        
        return findings
    
    async def _assess_binary_vulnerabilities(self, target: str) -> List[SecurityFinding]:
        """Assess binary for common vulnerabilities."""
        findings = []
        
        # Simulate vulnerability assessment
        finding = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            discipline=SecurityDiscipline.REVERSE_ENGINEERING,
            title="Binary Vulnerability Assessment",
            description="Binary assessment identified potential security vulnerabilities requiring further investigation",
            severity=ThreatLevel.MEDIUM,
            confidence=0.6,
            evidence={"target": target, "method": "vulnerability_assessment"},
            recommendations=["Conduct thorough security review", "Apply security patches", "Implement secure compilation flags"]
        )
        findings.append(finding)
        
        return findings


class IncidentResponseAgent(SecurityAgent):
    """Specialized incident response and forensics agent."""
    
    def _define_capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="Incident Triage",
                description="Security incident triage and assessment",
                tools=["siem", "log-analysis", "threat-intel"],
                techniques=["Log Analysis", "Threat Hunting", "IOC Analysis", "Alert Triage"],
                certifications=["GCIH", "CISSP", "SANS GIAC"],
                experience_years=8
            ),
            AgentCapability(
                name="Digital Forensics",
                description="Digital evidence collection and analysis",
                tools=["autopsy", "sleuthkit", "volatility", "ftk-imager"],
                techniques=["Memory Forensics", "Disk Forensics", "Network Forensics", "Timeline Analysis"],
                certifications=["GCFA", "GCFE", "CREST"],
                experience_years=10
            ),
            AgentCapability(
                name="Malware Incident Response",
                description="Malware containment and eradication",
                tools=["cuckoo", "yara", "malware-analysis", "remediation"],
                techniques=["Containment", "Eradication", "Recovery", "Lessons Learned"],
                certifications=["GREM", "GCIH", "CTIA"],
                experience_years=7
            )
        ]
    
    async def analyze(self, target: str, parameters: Dict[str, Any] = None) -> List[SecurityFinding]:
        """Perform incident response analysis."""
        findings = []
        params = parameters or {}
        
        # Phase 1: Incident Assessment
        assessment = await self._assess_incident(target, params.get("incident_type", "unknown"))
        findings.extend(assessment)
        
        # Phase 2: Evidence Collection
        if params.get("collect_evidence", False):
            evidence_findings = await self._collect_evidence(target)
            findings.extend(evidence_findings)
        
        # Phase 3: Containment Recommendations
        containment = await self._recommend_containment(target, params.get("threat_level", "medium"))
        findings.extend(containment)
        
        return findings
    
    async def _assess_incident(self, target: str, incident_type: str) -> List[SecurityFinding]:
        """Assess security incident."""
        findings = []
        
        finding = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            discipline=SecurityDiscipline.INCIDENT_RESPONSE,
            title=f"Security Incident Assessment: {incident_type}",
            description=f"Incident assessment conducted for {target} with type {incident_type}",
            severity=ThreatLevel.HIGH,
            confidence=0.8,
            evidence={"target": target, "incident_type": incident_type},
            recommendations=["Activate incident response plan", "Assess impact and scope", "Begin containment procedures"]
        )
        findings.append(finding)
        
        return findings
    
    async def _collect_evidence(self, target: str) -> List[SecurityFinding]:
        """Collect digital evidence."""
        findings = []
        
        finding = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            discipline=SecurityDiscipline.INCIDENT_RESPONSE,
            title="Digital Evidence Collection",
            description="Digital evidence collection procedures initiated for investigation",
            severity=ThreatLevel.MEDIUM,
            confidence=0.7,
            evidence={"target": target, "method": "evidence_collection"},
            recommendations=["Maintain chain of custody", "Document collection process", "Preserve volatile data first"]
        )
        findings.append(finding)
        
        return findings
    
    async def _recommend_containment(self, target: str, threat_level: str) -> List[SecurityFinding]:
        """Recommend containment strategies."""
        findings = []
        
        severity_map = {
            "low": ThreatLevel.LOW,
            "medium": ThreatLevel.MEDIUM,
            "high": ThreatLevel.HIGH,
            "critical": ThreatLevel.CRITICAL
        }
        
        finding = SecurityFinding(
            finding_id=str(uuid.uuid4()),
            discipline=SecurityDiscipline.INCIDENT_RESPONSE,
            title=f"Containment Strategy: {threat_level.upper()} Threat",
            description=f"Containment recommendations provided for {threat_level} level threat",
            severity=severity_map.get(threat_level, ThreatLevel.MEDIUM),
            confidence=0.8,
            evidence={"target": target, "threat_level": threat_level},
            recommendations=["Isolate affected systems", "Block malicious IPs", "Disable compromised accounts"]
        )
        findings.append(finding)
        
        return findings


# Expert Agent Manager
class SecurityAgentManager:
    """Manages and orchestrates specialized security agents."""
    
    def __init__(self, tool_manager: UniversalToolManager):
        self.tool_manager = tool_manager
        self.agents = self._initialize_agents()
        self.active_assessments: Dict[str, Dict] = {}
        
    def _initialize_agents(self) -> Dict[SecurityDiscipline, SecurityAgent]:
        """Initialize all specialized security agents."""
        return {
            SecurityDiscipline.WEB_PENETRATION_TESTING: WebPenetrationTester(self.tool_manager),
            SecurityDiscipline.NETWORK_PENETRATION_TESTING: NetworkPenetrationTester(self.tool_manager),
            SecurityDiscipline.SOCIAL_ENGINEERING: SocialEngineeringAgent(self.tool_manager),
            SecurityDiscipline.PASSWORD_CRACKING: PasswordCrackingAgent(self.tool_manager),
            SecurityDiscipline.REVERSE_ENGINEERING: ReverseEngineeringAgent(self.tool_manager),
            SecurityDiscipline.INCIDENT_RESPONSE: IncidentResponseAgent(self.tool_manager)
        }
    
    async def run_comprehensive_assessment(self, target: str, 
                                         disciplines: List[SecurityDiscipline] = None,
                                         parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run comprehensive security assessment across multiple disciplines."""
        if not disciplines:
            disciplines = list(self.agents.keys())
        
        assessment_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        # Initialize assessment tracking
        self.active_assessments[assessment_id] = {
            "target": target,
            "disciplines": [d.value for d in disciplines],
            "start_time": start_time,
            "status": "running",
            "findings": [],
            "agent_results": {}
        }
        
        try:
            # Run assessments in parallel
            tasks = []
            for discipline in disciplines:
                if discipline in self.agents:
                    task = self.agents[discipline].analyze(target, parameters)
                    tasks.append((discipline, task))
            
            # Wait for all assessments to complete
            results = await asyncio.gather(*[task for _, task in tasks], return_exceptions=True)
            
            # Process results
            all_findings = []
            for i, (discipline, _) in enumerate(tasks):
                result = results[i]
                
                if isinstance(result, Exception):
                    logger.error(f"Agent {discipline.value} failed: {result}")
                    self.active_assessments[assessment_id]["agent_results"][discipline.value] = {
                        "status": "failed",
                        "error": str(result)
                    }
                else:
                    self.active_assessments[assessment_id]["agent_results"][discipline.value] = {
                        "status": "completed",
                        "findings_count": len(result)
                    }
                    all_findings.extend(result)
            
            # Update assessment
            self.active_assessments[assessment_id].update({
                "status": "completed",
                "end_time": datetime.now(),
                "findings": all_findings,
                "total_findings": len(all_findings)
            })
            
            return {
                "assessment_id": assessment_id,
                "target": target,
                "disciplines": [d.value for d in disciplines],
                "status": "completed",
                "findings": [
                    {
                        "finding_id": f.finding_id,
                        "discipline": f.discipline.value,
                        "title": f.title,
                        "description": f.description,
                        "severity": f.severity.value,
                        "confidence": f.confidence,
                        "recommendations": f.recommendations,
                        "discovered_at": f.discovered_at.isoformat()
                    }
                    for f in all_findings
                ],
                "summary": self._generate_summary(all_findings),
                "executed_at": start_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Comprehensive assessment failed: {e}")
            self.active_assessments[assessment_id].update({
                "status": "failed",
                "error": str(e),
                "end_time": datetime.now()
            })
            
            raise
    
    def _generate_summary(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Generate assessment summary."""
        severity_counts = {}
        discipline_counts = {}
        
        for finding in findings:
            # Count by severity
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by discipline
            discipline = finding.discipline.value
            discipline_counts[discipline] = discipline_counts.get(discipline, 0) + 1
        
        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "discipline_breakdown": discipline_counts,
            "critical_findings": severity_counts.get("critical", 0),
            "high_findings": severity_counts.get("high", 0),
            "medium_findings": severity_counts.get("medium", 0),
            "low_findings": severity_counts.get("low", 0)
        }
    
    def get_agent_capabilities(self) -> Dict[str, List[Dict]]:
        """Get capabilities of all agents."""
        capabilities = {}
        
        for discipline, agent in self.agents.items():
            capabilities[discipline.value] = [
                {
                    "name": cap.name,
                    "description": cap.description,
                    "tools": cap.tools,
                    "techniques": cap.techniques,
                    "certifications": cap.certifications,
                    "experience_years": cap.experience_years
                }
                for cap in agent.capabilities
            ]
        
        return capabilities
    
    def get_assessment_status(self, assessment_id: str) -> Dict[str, Any]:
        """Get status of a running assessment."""
        if assessment_id not in self.active_assessments:
            raise ValueError(f"Assessment {assessment_id} not found")
        
        return self.active_assessments[assessment_id]


# Example usage
async def main():
    """Example usage of the Security Agent Manager."""
    tool_manager = UniversalToolManager()
    agent_manager = SecurityAgentManager(tool_manager)
    
    # Get agent capabilities
    capabilities = agent_manager.get_agent_capabilities()
    print("Available Agent Capabilities:")
    for discipline, caps in capabilities.items():
        print(f"\n{discipline}:")
        for cap in caps:
            print(f"  - {cap['name']}: {cap['description']}")
    
    # Run comprehensive assessment
    target = "example.com"
    disciplines = [
        SecurityDiscipline.WEB_PENETRATION_TESTING,
        SecurityDiscipline.NETWORK_PENETRATION_TESTING,
        SecurityDiscipline.SOCIAL_ENGINEERING
    ]
    
    assessment = await agent_manager.run_comprehensive_assessment(
        target, disciplines, {"deep_analysis": True}
    )
    
    print(f"\nAssessment Results for {target}:")
    print(f"Total Findings: {assessment['summary']['total_findings']}")
    print(f"Critical: {assessment['summary']['critical_findings']}")
    print(f"High: {assessment['summary']['high_findings']}")
    print(f"Medium: {assessment['summary']['medium_findings']}")
    print(f"Low: {assessment['summary']['low_findings']}")


if __name__ == "__main__":
    asyncio.run(main())
