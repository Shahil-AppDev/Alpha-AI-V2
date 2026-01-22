"""
Email Security and Breach Detection Module

This module provides comprehensive email security analysis, breach detection,
and credential monitoring capabilities using services like HaveIBeenPwned,
DeHashed, and commercial threat intelligence providers.
"""

import asyncio
import aiohttp
import hashlib
import json
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
import base64
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import dns.resolver
import spfcheck
import dkim

from modules.universal_tool_manager import UniversalToolManager, ToolCategory

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BreachDataSource:
    """Base class for breach data sources."""
    
    def __init__(self, name: str, api_key: Optional[str] = None):
        self.name = name
        self.api_key = api_key
        self.rate_limit = 0  # requests per minute
        self.last_request = 0
        
    async def check_email(self, email: str) -> Dict[str, Any]:
        """Check if email appears in breaches."""
        raise NotImplementedError
    
    async def check_password(self, password_hash: str) -> Dict[str, Any]:
        """Check if password appears in breaches."""
        raise NotImplementedError
    
    async def _rate_limit(self):
        """Implement rate limiting."""
        if self.rate_limit > 0:
            current_time = time.time()
            time_since_last = current_time - self.last_request
            min_interval = 60.0 / self.rate_limit
            
            if time_since_last < min_interval:
                await asyncio.sleep(min_interval - time_since_last)
            
            self.last_request = time.time()


class HaveIBeenPwnedAPI(BreachDataSource):
    """HaveIBeenPwned.com API integration."""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("HaveIBeenPwned", api_key)
        self.base_url = "https://haveibeenpwned.com/api/v3"
        self.rate_limit = 1500  # requests per minute for paid API
        
    async def check_email(self, email: str) -> Dict[str, Any]:
        """Check email against HaveIBeenPwned database."""
        await self._rate_limit()
        
        headers = {}
        if self.api_key:
            headers["hibp-api-key"] = self.api_key
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/breachedaccount/{email}"
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        breaches = await response.json()
                        return {
                            "source": self.name,
                            "breached": True,
                            "breaches": [
                                {
                                    "name": breach["Name"],
                                    "title": breach["Title"],
                                    "date": breach["BreachDate"],
                                    "data_classes": breach["DataClasses"],
                                    "verified": breach["IsVerified"],
                                    "fabricated": breach["IsFabricated"],
                                    "sensitive": breach["IsSensitive"]
                                }
                                for breach in breaches
                            ],
                            "total_breaches": len(breaches)
                        }
                    elif response.status == 404:
                        return {
                            "source": self.name,
                            "breached": False,
                            "breaches": [],
                            "total_breaches": 0
                        }
                    else:
                        return {
                            "source": self.name,
                            "error": f"API error: {response.status}",
                            "breached": False
                        }
                        
        except Exception as e:
            logger.error(f"Error checking email with HaveIBeenPwned: {e}")
            return {
                "source": self.name,
                "error": str(e),
                "breached": False
            }
    
    async def check_password(self, password_hash: str) -> Dict[str, Any]:
        """Check password hash against HaveIBeenPwned Pwned Passwords."""
        await self._rate_limit()
        
        try:
            # Use first 5 characters of hash for k-anonymity
            hash_prefix = password_hash[:5]
            hash_suffix = password_hash[5:].upper()
            
            async with aiohttp.ClientSession() as session:
                url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"
                async with session.get(url) as response:
                    if response.status == 200:
                        hashes = await response.text()
                        
                        # Check if our hash suffix is in the response
                        for line in hashes.split('\n'):
                            if line.startswith(hash_suffix):
                                count = int(line.split(':')[1])
                                return {
                                    "source": self.name,
                                    "found": True,
                                    "occurrences": count,
                                    "severity": "high" if count > 1000 else "medium" if count > 100 else "low"
                                }
                        
                        return {
                            "source": self.name,
                            "found": False,
                            "occurrences": 0,
                            "severity": "safe"
                        }
                    else:
                        return {
                            "source": self.name,
                            "error": f"API error: {response.status}",
                            "found": False
                        }
                        
        except Exception as e:
            logger.error(f"Error checking password with HaveIBeenPwned: {e}")
            return {
                "source": self.name,
                "error": str(e),
                "found": False
            }


class DeHashedAPI(BreachDataSource):
    """DeHashed commercial breach database API."""
    
    def __init__(self, api_key: str, email: str):
        super().__init__("DeHashed", api_key)
        self.base_url = "https://dehashed.com/search"
        self.email = email
        self.rate_limit = 100  # requests per minute
        
    async def check_email(self, email: str) -> Dict[str, Any]:
        """Check email against DeHashed database."""
        await self._rate_limit()
        
        headers = {
            "Accept": "application/json",
            "Authorization": f"Basic {base64.b64encode(f'{self.email}:{self.api_key}'.encode()).decode()}"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    "query": f"email:{email}",
                    "size": 100
                }
                
                async with session.post(self.base_url, headers=headers, json=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        entries = result.get("entries", [])
                        
                        return {
                            "source": self.name,
                            "breached": len(entries) > 0,
                            "entries": entries,
                            "total_entries": len(entries),
                            "sources": list(set(entry.get("source", "") for entry in entries))
                        }
                    else:
                        return {
                            "source": self.name,
                            "error": f"API error: {response.status}",
                            "breached": False
                        }
                        
        except Exception as e:
            logger.error(f"Error checking email with DeHashed: {e}")
            return {
                "source": self.name,
                "error": str(e),
                "breached": False
            }
    
    async def check_password(self, password_hash: str) -> Dict[str, Any]:
        """Check password hash against DeHashed database."""
        await self._rate_limit()
        
        headers = {
            "Accept": "application/json",
            "Authorization": f"Basic {base64.b64encode(f'{self.email}:{self.api_key}'.encode()).decode()}"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    "query": f"hash:{password_hash}",
                    "size": 100
                }
                
                async with session.post(self.base_url, headers=headers, json=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        entries = result.get("entries", [])
                        
                        return {
                            "source": self.name,
                            "found": len(entries) > 0,
                            "entries": entries,
                            "total_entries": len(entries)
                        }
                    else:
                        return {
                            "source": self.name,
                            "error": f"API error: {response.status}",
                            "found": False
                        }
                        
        except Exception as e:
            logger.error(f"Error checking password with DeHashed: {e}")
            return {
                "source": self.name,
                "error": str(e),
                "found": False
            }


class IntelXAPI(BreachDataSource):
    """Intel X-Force threat intelligence API."""
    
    def __init__(self, api_key: str):
        super().__init__("IntelX", api_key)
        self.base_url = "https://api.xforce.ibmcloud.com"
        self.rate_limit = 200
        
    async def check_email(self, email: str) -> Dict[str, Any]:
        """Check email against Intel X-Force database."""
        await self._rate_limit()
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/api/email/simple/{email}"
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        return {
                            "source": self.name,
                            "breached": data.get("score", 0) > 0,
                            "risk_score": data.get("score", 0),
                            "categories": data.get("categories", []),
                            "malicious": data.get("malicious", False)
                        }
                    else:
                        return {
                            "source": self.name,
                            "error": f"API error: {response.status}",
                            "breached": False
                        }
                        
        except Exception as e:
            logger.error(f"Error checking email with IntelX: {e}")
            return {
                "source": self.name,
                "error": str(e),
                "breached": False
            }
    
    async def check_password(self, password_hash: str) -> Dict[str, Any]:
        """IntelX doesn't provide password hash checking."""
        return {
            "source": self.name,
            "error": "Password hash checking not supported",
            "found": False
        }


class EmailSecurityAnalyzer:
    """Comprehensive email security analysis."""
    
    def __init__(self, breach_sources: List[BreachDataSource] = None):
        self.breach_sources = breach_sources or []
        self.analysis_cache = {}
        
    def add_breach_source(self, source: BreachDataSource):
        """Add a breach data source."""
        self.breach_sources.append(source)
        
    async def analyze_email(self, email: str, include_passwords: bool = False) -> Dict[str, Any]:
        """Perform comprehensive email security analysis."""
        if not self._is_valid_email(email):
            return {
                "error": "Invalid email address",
                "valid": False
            }
        
        # Check cache first
        cache_key = f"email_{email}_{include_passwords}"
        if cache_key in self.analysis_cache:
            cached_result = self.analysis_cache[cache_key]
            # Use cached result if less than 1 hour old
            if datetime.now() - cached_result["timestamp"] < timedelta(hours=1):
                return cached_result["result"]
        
        analysis = {
            "email": email,
            "valid": True,
            "timestamp": datetime.now().isoformat(),
            "breach_analysis": {},
            "security_analysis": {},
            "recommendations": []
        }
        
        # Check against breach sources
        breach_results = []
        for source in self.breach_sources:
            try:
                result = await source.check_email(email)
                breach_results.append(result)
            except Exception as e:
                logger.error(f"Error checking {source.name}: {e}")
                breach_results.append({
                    "source": source.name,
                    "error": str(e),
                    "breached": False
                })
        
        analysis["breach_analysis"] = {
            "sources_checked": len(self.breach_sources),
            "sources_with_breaches": sum(1 for r in breach_results if r.get("breached", False)),
            "total_breaches": sum(r.get("total_breaches", 0) for r in breach_results),
            "detailed_results": breach_results
        }
        
        # Perform email security analysis
        security_analysis = await self._analyze_email_security(email)
        analysis["security_analysis"] = security_analysis
        
        # Generate recommendations
        recommendations = self._generate_recommendations(analysis)
        analysis["recommendations"] = recommendations
        
        # Cache result
        self.analysis_cache[cache_key] = {
            "timestamp": datetime.now(),
            "result": analysis
        }
        
        return analysis
    
    async def analyze_password(self, password: str) -> Dict[str, Any]:
        """Analyze password against breach databases."""
        password_hash = self._hash_password(password)
        
        analysis = {
            "password_hash": password_hash,
            "timestamp": datetime.now().isoformat(),
            "breach_analysis": {},
            "strength_analysis": {},
            "recommendations": []
        }
        
        # Check against breach sources
        breach_results = []
        for source in self.breach_sources:
            try:
                result = await source.check_password(password_hash)
                breach_results.append(result)
            except Exception as e:
                logger.error(f"Error checking password with {source.name}: {e}")
                breach_results.append({
                    "source": source.name,
                    "error": str(e),
                    "found": False
                })
        
        analysis["breach_analysis"] = {
            "sources_checked": len(self.breach_sources),
            "sources_found": sum(1 for r in breach_results if r.get("found", False)),
            "total_occurrences": sum(r.get("occurrences", 0) for r in breach_results),
            "detailed_results": breach_results
        }
        
        # Analyze password strength
        strength_analysis = self._analyze_password_strength(password)
        analysis["strength_analysis"] = strength_analysis
        
        # Generate recommendations
        recommendations = self._generate_password_recommendations(analysis)
        analysis["recommendations"] = recommendations
        
        return analysis
    
    async def _analyze_email_security(self, email: str) -> Dict[str, Any]:
        """Analyze email security configuration."""
        analysis = {
            "domain_analysis": {},
            "mx_records": [],
            "spf_record": None,
            "dmarc_record": None,
            "dkim_enabled": False,
            "security_score": 0
        }
        
        try:
            # Extract domain
            domain = email.split('@')[1]
            
            # Check MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                analysis["mx_records"] = [str(mx) for mx in mx_records]
                analysis["security_score"] += 10
            except:
                analysis["security_score"] -= 10
            
            # Check SPF record
            try:
                spf_record = dns.resolver.resolve(domain, 'TXT')
                for txt in spf_record:
                    if 'v=spf1' in str(txt):
                        analysis["spf_record"] = str(txt)
                        analysis["security_score"] += 15
                        break
            except:
                analysis["security_score"] -= 15
            
            # Check DMARC record
            try:
                dmarc_record = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for txt in dmarc_record:
                    if 'v=DMARC1' in str(txt):
                        analysis["dmarc_record"] = str(txt)
                        analysis["security_score"] += 15
                        break
            except:
                analysis["security_score"] -= 15
            
            # Domain analysis
            analysis["domain_analysis"] = {
                "domain": domain,
                "age_days": self._get_domain_age(domain),
                "reputation": self._check_domain_reputation(domain)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing email security: {e}")
            analysis["error"] = str(e)
        
        return analysis
    
    def _analyze_password_strength(self, password: str) -> Dict[str, Any]:
        """Analyze password strength."""
        analysis = {
            "length": len(password),
            "has_uppercase": any(c.isupper() for c in password),
            "has_lowercase": any(c.islower() for c in password),
            "has_numbers": any(c.isdigit() for c in password),
            "has_special": any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password),
            "entropy": self._calculate_entropy(password),
            "common_patterns": self._check_common_patterns(password),
            "strength_score": 0
        }
        
        # Calculate strength score
        score = 0
        if analysis["length"] >= 12:
            score += 25
        elif analysis["length"] >= 8:
            score += 15
        
        if analysis["has_uppercase"]:
            score += 15
        if analysis["has_lowercase"]:
            score += 15
        if analysis["has_numbers"]:
            score += 15
        if analysis["has_special"]:
            score += 15
        
        if analysis["entropy"] > 50:
            score += 10
        
        analysis["strength_score"] = min(100, score)
        
        # Determine strength level
        if analysis["strength_score"] >= 80:
            analysis["strength_level"] = "strong"
        elif analysis["strength_score"] >= 60:
            analysis["strength_level"] = "medium"
        else:
            analysis["strength_level"] = "weak"
        
        return analysis
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # Breach-based recommendations
        if analysis["breach_analysis"]["sources_with_breaches"] > 0:
            recommendations.append("IMMEDIATE: Change password for this email account")
            recommendations.append("Enable multi-factor authentication (MFA)")
            recommendations.append("Review account activity for unauthorized access")
        
        # Security-based recommendations
        security = analysis.get("security_analysis", {})
        if not security.get("spf_record"):
            recommendations.append("Configure SPF record for email domain")
        if not security.get("dmarc_record"):
            recommendations.append("Configure DMARC record for email domain")
        
        if security.get("security_score", 0) < 50:
            recommendations.append("Improve email domain security configuration")
        
        # General recommendations
        recommendations.extend([
            "Use unique passwords for each account",
            "Enable email forwarding to backup address",
            "Regularly monitor account activity",
            "Use a password manager for strong, unique passwords"
        ])
        
        return recommendations
    
    def _generate_password_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate password recommendations."""
        recommendations = []
        
        # Breach-based recommendations
        if analysis["breach_analysis"]["sources_found"] > 0:
            recommendations.append("IMMEDIATE: Do not use this password - it's been compromised")
            recommendations.append("Change this password on all accounts where it's used")
        
        # Strength-based recommendations
        strength = analysis.get("strength_analysis", {})
        if strength.get("strength_score", 0) < 60:
            recommendations.append("Use a longer password (12+ characters)")
            if not strength.get("has_uppercase"):
                recommendations.append("Include uppercase letters")
            if not strength.get("has_lowercase"):
                recommendations.append("Include lowercase letters")
            if not strength.get("has_numbers"):
                recommendations.append("Include numbers")
            if not strength.get("has_special"):
                recommendations.append("Include special characters")
        
        # Pattern-based recommendations
        if strength.get("common_patterns"):
            recommendations.append("Avoid common patterns and dictionary words")
        
        recommendations.extend([
            "Use a password manager to generate and store strong passwords",
            "Enable multi-factor authentication where available",
            "Never reuse passwords across different accounts"
        ])
        
        return recommendations
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email address format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _hash_password(self, password: str) -> str:
        """Hash password for breach checking (SHA-1)."""
        return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy."""
        if not password:
            return 0
        
        char_set_size = 0
        if any(c.islower() for c in password):
            char_set_size += 26
        if any(c.isupper() for c in password):
            char_set_size += 26
        if any(c.isdigit() for c in password):
            char_set_size += 10
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            char_set_size += 25
        
        import math
        entropy = len(password) * math.log2(char_set_size) if char_set_size > 0 else 0
        return entropy
    
    def _check_common_patterns(self, password: str) -> List[str]:
        """Check for common password patterns."""
        patterns = []
        
        # Check for common sequences
        if "123" in password or "abc" in password.lower():
            patterns.append("sequential_characters")
        
        # Check for repeated characters
        if any(password.count(c) > 2 for c in set(password)):
            patterns.append("repeated_characters")
        
        # Check for common words
        common_words = ["password", "admin", "user", "login", "welcome"]
        if any(word in password.lower() for word in common_words):
            patterns.append("dictionary_words")
        
        # Check for keyboard patterns
        keyboard_patterns = ["qwerty", "asdf", "zxcv"]
        if any(pattern in password.lower() for pattern in keyboard_patterns):
            patterns.append("keyboard_patterns")
        
        return patterns
    
    def _get_domain_age(self, domain: str) -> int:
        """Get domain age in days (simulated)."""
        # In real implementation, use WHOIS API
        import random
        return random.randint(30, 3650)
    
    def _check_domain_reputation(self, domain: str) -> str:
        """Check domain reputation (simulated)."""
        # In real implementation, use threat intelligence APIs
        import random
        return random.choice(["good", "neutral", "suspicious"])


class EmailSecurityMonitor:
    """Continuous email security monitoring."""
    
    def __init__(self, analyzer: EmailSecurityAnalyzer):
        self.analyzer = analyzer
        self.monitored_emails: Set[str] = set()
        self.alert_thresholds = {
            "breach_count": 1,
            "security_score": 30
        }
        
    def add_email_to_monitor(self, email: str):
        """Add email to monitoring list."""
        if self.analyzer._is_valid_email(email):
            self.monitored_emails.add(email)
            logger.info(f"Added {email} to monitoring list")
        else:
            raise ValueError(f"Invalid email address: {email}")
    
    def remove_email_from_monitor(self, email: str):
        """Remove email from monitoring list."""
        self.monitored_emails.discard(email)
        logger.info(f"Removed {email} from monitoring list")
    
    async def scan_all_emails(self) -> Dict[str, Any]:
        """Scan all monitored emails for security issues."""
        results = {}
        alerts = []
        
        for email in self.monitored_emails:
            try:
                analysis = await self.analyzer.analyze_email(email)
                results[email] = analysis
                
                # Check for alerts
                email_alerts = self._check_alerts(email, analysis)
                alerts.extend(email_alerts)
                
            except Exception as e:
                logger.error(f"Error scanning {email}: {e}")
                results[email] = {"error": str(e)}
        
        return {
            "scanned_emails": len(self.monitored_emails),
            "results": results,
            "alerts": alerts,
            "timestamp": datetime.now().isoformat()
        }
    
    def _check_alerts(self, email: str, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for security alerts."""
        alerts = []
        
        # Breach alerts
        breach_analysis = analysis.get("breach_analysis", {})
        if breach_analysis.get("sources_with_breaches", 0) >= self.alert_thresholds["breach_count"]:
            alerts.append({
                "type": "breach_detected",
                "email": email,
                "severity": "critical",
                "message": f"Email found in {breach_analysis['sources_with_breaches']} breach sources",
                "timestamp": datetime.now().isoformat()
            })
        
        # Security score alerts
        security_analysis = analysis.get("security_analysis", {})
        if security_analysis.get("security_score", 100) < self.alert_thresholds["security_score"]:
            alerts.append({
                "type": "poor_security",
                "email": email,
                "severity": "warning",
                "message": f"Email domain security score: {security_analysis.get('security_score')}",
                "timestamp": datetime.now().isoformat()
            })
        
        return alerts
    
    def set_alert_threshold(self, breach_count: int = None, security_score: int = None):
        """Set alert thresholds."""
        if breach_count is not None:
            self.alert_thresholds["breach_count"] = breach_count
        if security_score is not None:
            self.alert_thresholds["security_score"] = security_score


# Email Security API Integration
class EmailSecurityAPI:
    """API endpoints for email security services."""
    
    def __init__(self, analyzer: EmailSecurityAnalyzer, monitor: EmailSecurityMonitor = None):
        self.analyzer = analyzer
        self.monitor = monitor or EmailSecurityMonitor(analyzer)
        
    async def analyze_email(self, email: str, include_passwords: bool = False) -> Dict[str, Any]:
        """Analyze email security."""
        return await self.analyzer.analyze_email(email, include_passwords)
    
    async def analyze_password(self, password: str) -> Dict[str, Any]:
        """Analyze password security."""
        return await self.analyzer.analyze_password(password)
    
    async def scan_monitored_emails(self) -> Dict[str, Any]:
        """Scan all monitored emails."""
        return await self.monitor.scan_all_emails()
    
    def add_monitored_email(self, email: str) -> bool:
        """Add email to monitoring list."""
        try:
            self.monitor.add_email_to_monitor(email)
            return True
        except ValueError:
            return False
    
    def remove_monitored_email(self, email: str) -> bool:
        """Remove email from monitoring list."""
        self.monitor.remove_email_from_monitor(email)
        return True
    
    def get_monitored_emails(self) -> List[str]:
        """Get list of monitored emails."""
        return list(self.monitor.monitored_emails)
    
    def set_alert_thresholds(self, breach_count: int = None, security_score: int = None):
        """Set alert thresholds."""
        self.monitor.set_alert_threshold(breach_count, security_score)


# Example usage
async def main():
    """Example usage of email security module."""
    # Initialize breach sources
    hibp = HaveibeenPwnedAPI()  # Free tier, limited requests
    
    # For commercial sources, you'd need API keys:
    # dehashed = DeHashedAPI("your-api-key", "your-email")
    # intelx = IntelXAPI("your-api-key")
    
    # Create analyzer
    analyzer = EmailSecurityAnalyzer([hibp])
    
    # Analyze an email
    email_to_check = "test@example.com"
    result = await analyzer.analyze_email(email_to_check)
    
    print(f"Email Analysis for {email_to_check}:")
    print(json.dumps(result, indent=2, default=str))
    
    # Analyze a password
    password_to_check = "password123"
    password_result = await analyzer.analyze_password(password_to_check)
    
    print(f"\nPassword Analysis:")
    print(json.dumps(password_result, indent=2, default=str))
    
    # Set up monitoring
    monitor = EmailSecurityMonitor(analyzer)
    monitor.add_email_to_monitor(email_to_check)
    
    # Scan monitored emails
    scan_result = await monitor.scan_all_emails()
    print(f"\nMonitoring Results:")
    print(json.dumps(scan_result, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
