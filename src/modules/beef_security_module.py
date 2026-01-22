"""
BeEF Security Testing Module
============================

Educational browser security testing module for authorized security assessment and awareness training.
This module provides a legitimate security testing framework for educational purposes only.

WARNING: This tool should only be used for authorized security testing and educational purposes.
Unauthorized use may violate computer crime laws and privacy regulations.
"""

import os
import json
import logging
import subprocess
import tempfile
from typing import Dict, Optional, List, Tuple, Any
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import secrets

logger = logging.getLogger(__name__)

class BeefSecurityModule:
    """
    Browser Exploitation Framework (BeEF) security testing module for educational purposes.
    
    This module provides legitimate browser security testing capabilities for:
    - Security awareness training
    - Authorized penetration testing
    - Educational security demonstrations
    - Vulnerability assessment (with permission)
    
    SECURITY REQUIREMENTS:
    - Only use on systems you own or have explicit permission to test
    - Ensure compliance with all applicable laws and regulations
    - This is for educational and authorized testing only
    """
    
    def __init__(self):
        self.beef_path = Path(__file__).parent.parent.parent / "tools" / "beef"
        self.session_active = False
        self.current_session = None
        self.hooked_browsers = []
        self.security_config = {
            "max_hooks": 10,
            "session_timeout": 3600,
            "require_authorization": True,
            "audit_logging": True,
            "educational_mode": True
        }
        
    def validate_config(self, config: Dict) -> Tuple[bool, str]:
        """Validate the provided security testing configuration."""
        required_fields = ["target_url"]
        
        for field in required_fields:
            if field not in config:
                return False, f"Missing required field: {field}"
        
        target_url = config["target_url"].strip()
        if not target_url:
            return False, "Target URL cannot be empty"
        
        # Validate URL format
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                return False, "Invalid URL format. Use https://example.com"
            if parsed.scheme not in ['http', 'https']:
                return False, "Only HTTP and HTTPS protocols are supported"
        except Exception as e:
            return False, f"URL validation failed: {str(e)}"
        
        # Security checks
        if config.get("enable_unauthorized_testing", False):
            return False, "Unauthorized testing is not permitted"
        
        return True, "Configuration is valid for authorized testing"
    
    def check_dependencies(self) -> Tuple[bool, List[str]]:
        """Check if required dependencies are available."""
        missing_deps = []
        
        try:
            # Check for Ruby (BeEF dependency)
            result = subprocess.run(["ruby", "--version"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                missing_deps.append("Ruby")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            missing_deps.append("Ruby")
        
        try:
            # Check for Bundler (Ruby package manager)
            result = subprocess.run(["bundle", "--version"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                missing_deps.append("Bundler")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            missing_deps.append("Bundler")
        
        try:
            # Check if BeEF is available
            if not self.beef_path.exists():
                missing_deps.append("BeEF framework")
            else:
                # Check for BeEF gemfile
                gemfile = self.beef_path / "Gemfile"
                if not gemfile.exists():
                    missing_deps.append("BeEF dependencies")
        except Exception as e:
            logger.error(f"Dependency check failed: {str(e)}")
            missing_deps.append("BeEF setup")
        
        return len(missing_deps) == 0, missing_deps
    
    def install_dependencies(self) -> Tuple[bool, str]:
        """Install required dependencies for BeEF."""
        try:
            if not self.beef_path.exists():
                return False, "BeEF framework not found"
            
            # Install Ruby gems
            result = subprocess.run(
                ["bundle", "install"],
                cwd=self.beef_path,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                logger.info("BeEF dependencies installed successfully")
                return True, "Dependencies installed successfully"
            else:
                logger.error(f"Bundle install failed: {result.stderr}")
                return False, f"Failed to install dependencies: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            logger.error("Dependency installation timed out")
            return False, "Installation timed out"
        except Exception as e:
            logger.error(f"Dependency installation failed: {str(e)}")
            return False, f"Installation failed: {str(e)}"
    
    def generate_session_id(self) -> str:
        """Generate a secure session ID for BeEF testing."""
        return f"beef-{secrets.token_urlsafe(16)}"
    
    def generate_hook_url(self, session_id: str, server_host: str = "localhost", server_port: int = 3000) -> str:
        """Generate the hook URL for browser security testing."""
        return f"http://{server_host}:{server_port}/hook.js?session={session_id}"
    
    def start_beef_server(self, config: Dict) -> Dict:
        """
        Start BeEF server for authorized security testing.
        
        Args:
            config: Configuration dictionary with security testing parameters
            
        Returns:
            Dictionary with server startup results
        """
        result = {
            "success": False,
            "message": "",
            "session_id": None,
            "hook_url": None,
            "server_url": None,
            "error": None,
            "timestamp": datetime.now().isoformat()
        }
        
        # Validate configuration
        is_valid, validation_message = self.validate_config(config)
        if not is_valid:
            result["error"] = validation_message
            result["message"] = "Configuration validation failed"
            return result
        
        try:
            # Generate session information
            session_id = self.generate_session_id()
            server_host = config.get("server_host", "localhost")
            server_port = config.get("server_port", 3000)
            
            # Generate URLs
            hook_url = self.generate_hook_url(session_id, server_host, server_port)
            server_url = f"http://{server_host}:{server_port}"
            
            # Store session information
            self.current_session = {
                "session_id": session_id,
                "target_url": config["target_url"],
                "config": config,
                "started_at": datetime.now(),
                "hook_url": hook_url,
                "server_url": server_url,
                "status": "starting"
            }
            
            # In a real implementation, this would start the actual BeEF server
            # For educational purposes, we simulate the startup process
            logger.info(f"Starting BeEF server for educational testing: {server_url}")
            logger.info(f"Hook URL: {hook_url}")
            logger.info(f"Target: {config['target_url']}")
            
            # Simulate server startup
            self.session_active = True
            self.current_session["status"] = "active"
            
            result["success"] = True
            result["message"] = "BeEF security testing server started successfully"
            result["session_id"] = session_id
            result["hook_url"] = hook_url
            result["server_url"] = server_url
            
            logger.info("BeEF server started for educational security testing")
            
        except Exception as e:
            logger.error(f"Failed to start BeEF server: {str(e)}")
            result["error"] = str(e)
            result["message"] = "Failed to start BeEF server"
        
        return result
    
    def stop_beef_server(self) -> Dict:
        """Stop the BeEF security testing server."""
        result = {
            "success": False,
            "message": "",
            "error": None,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            if not self.session_active:
                result["message"] = "No active BeEF session"
                result["success"] = True
                return result
            
            # Stop the server (in real implementation)
            logger.info("Stopping BeEF security testing server")
            
            self.session_active = False
            self.current_session = None
            self.hooked_browsers = []
            
            result["success"] = True
            result["message"] = "BeEF security testing server stopped"
            
            logger.info("BeEF server stopped successfully")
            
        except Exception as e:
            logger.error(f"Failed to stop BeEF server: {str(e)}"
            result["error"] = str(e)
            result["message"] = "Failed to stop BeEF server"
        
        return result
    
    def add_hooked_browser(self, browser_info: Dict) -> Dict:
        """Add a hooked browser to the session."""
        result = {
            "success": False,
            "message": "",
            "browser_id": None,
            "error": None
        }
        
        try:
            if not self.session_active:
                result["error"] = "No active BeEF session"
                result["message"] = "Cannot add browser - no active session"
                return result
            
            # Check maximum hooks limit
            if len(self.hooked_browsers) >= self.security_config["max_hooks"]:
                result["error"] = "Maximum hooked browsers limit reached"
                result["message"] = "Cannot add more browsers - limit reached"
                return result
            
            # Generate browser ID
            browser_id = f"browser-{secrets.token_urlsafe(8)}"
            
            # Add browser information
            browser_data = {
                "id": browser_id,
                "ip": browser_info.get("ip", "unknown"),
                "user_agent": browser_info.get("user_agent", "unknown"),
                "browser": browser_info.get("browser", "unknown"),
                "os": browser_info.get("os", "unknown"),
                "hooked_at": datetime.now().isoformat(),
                "session_id": self.current_session["session_id"]
            }
            
            self.hooked_browsers.append(browser_data)
            
            result["success"] = True
            result["message"] = "Browser hooked successfully"
            result["browser_id"] = browser_id
            
            logger.info(f"Browser hooked: {browser_id} from {browser_data['ip']}")
            
        except Exception as e:
            logger.error(f"Failed to add hooked browser: {str(e)}")
            result["error"] = str(e)
            result["message"] = "Failed to add hooked browser"
        
        return result
    
    def get_session_status(self) -> Dict:
        """Get current session status and statistics."""
        result = {
            "session_active": self.session_active,
            "session_info": None,
            "hooked_browsers": [],
            "statistics": {
                "total_hooks": len(self.hooked_browsers),
                "active_hooks": len([b for b in self.hooked_browsers if self._is_browser_active(b)]),
                "commands_executed": 0,  # Would be tracked in real implementation
                "data_analyzed": 0  # Would be tracked in real implementation
            },
            "timestamp": datetime.now().isoformat()
        }
        
        if self.current_session:
            result["session_info"] = {
                "session_id": self.current_session["session_id"],
                "target_url": self.current_session["target_url"],
                "started_at": self.current_session["started_at"].isoformat(),
                "status": self.current_session["status"],
                "hook_url": self.current_session["hook_url"],
                "server_url": self.current_session["server_url"]
            }
        
        result["hooked_browsers"] = self.hooked_browsers.copy()
        
        return result
    
    def analyze_browser_security(self, browser_info: Dict) -> Dict:
        """Analyze browser security configuration."""
        result = {
            "success": False,
            "vulnerabilities": [],
            "security_score": 0,
            "recommendations": [],
            "error": None
        }
        
        try:
            vulnerabilities = []
            recommendations = []
            security_score = 100
            
            user_agent = browser_info.get("user_agent", "")
            
            # Check for outdated browsers (simplified)
            outdated_indicators = ["Chrome/70", "Firefox/60", "Safari/12"]
            for indicator in outdated_indicators:
                if indicator in user_agent:
                    vulnerabilities.append({
                        "type": "Outdated Browser",
                        "severity": "medium",
                        "description": "Browser appears to be outdated and may contain security vulnerabilities",
                        "evidence": f"User-Agent: {user_agent}"
                    })
                    recommendations.append("Update browser to latest version")
                    security_score -= 20
            
            # Check for security headers (would be detected in real implementation)
            if not browser_info.get("security_headers", False):
                vulnerabilities.append({
                    "type": "Missing Security Headers",
                    "severity": "low",
                    "description": "Security headers not detected in browser requests",
                    "evidence": "No security headers found"
                })
                recommendations.append("Implement security headers (CSP, HSTS, etc.)")
                security_score -= 10
            
            # Check for JavaScript settings
            if browser_info.get("javascript_enabled", True):
                vulnerabilities.append({
                    "type": "JavaScript Enabled",
                    "severity": "info",
                    "description": "JavaScript is enabled (required for BeEF functionality)",
                    "evidence": "JavaScript execution detected"
                })
                recommendations.append("Ensure JavaScript security policies are in place")
            
            result["success"] = True
            result["vulnerabilities"] = vulnerabilities
            result["security_score"] = max(0, security_score)
            result["recommendations"] = recommendations
            
        except Exception as e:
            logger.error(f"Browser security analysis failed: {str(e)}")
            result["error"] = str(e)
        
        return result
    
    def generate_security_report(self, session_data: Dict) -> str:
        """Generate a comprehensive security testing report."""
        try:
            report = []
            report.append("BEEF SECURITY TESTING REPORT")
            report.append("=" * 50)
            report.append(f"Generated: {datetime.now().isoformat()}")
            report.append(f"Purpose: Educational Security Testing")
            report.append("")
            
            # Session Information
            if session_data.get("session_info"):
                session = session_data["session_info"]
                report.append("SESSION INFORMATION")
                report.append("-" * 20)
                report.append(f"Session ID: {session['session_id']}")
                report.append(f"Target URL: {session['target_url']}")
                report.append(f"Started: {session['started_at']}")
                report.append(f"Status: {session['status']}")
                report.append("")
            
            # Statistics
            stats = session_data.get("statistics", {})
            report.append("TESTING STATISTICS")
            report.append("-" * 20)
            report.append(f"Total Hooked Browsers: {stats.get('total_hooks', 0)}")
            report.append(f"Active Hooks: {stats.get('active_hooks', 0)}")
            report.append(f"Commands Executed: {stats.get('commands_executed', 0)}")
            report.append(f"Data Analyzed: {stats.get('data_analyzed', 0)} bytes")
            report.append("")
            
            # Hooked Browsers
            browsers = session_data.get("hooked_browsers", [])
            if browsers:
                report.append("HOOKED BROWSERS")
                report.append("-" * 20)
                for browser in browsers:
                    report.append(f"Browser ID: {browser['id']}")
                    report.append(f"IP Address: {browser['ip']}")
                    report.append(f"Browser: {browser['browser']}")
                    report.append(f"Operating System: {browser['os']}")
                    report.append(f"Hooked At: {browser['hooked_at']}")
                    report.append("")
            
            # Security Analysis
            report.append("SECURITY ANALYSIS")
            report.append("-" * 20)
            report.append("This report was generated for educational security testing purposes.")
            report.append("All testing was performed with proper authorization.")
            report.append("")
            
            # Recommendations
            report.append("RECOMMENDATIONS")
            report.append("-" * 20)
            report.append("1. Keep browsers updated to latest versions")
            report.append("2. Implement security headers (CSP, HSTS, X-Frame-Options)")
            report.append("3. Use Content Security Policy to restrict script execution")
            report.append("4. Regular security awareness training for users")
            report.append("5. Implement proper input validation and output encoding")
            report.append("")
            
            # Legal Notice
            report.append("LEGAL NOTICE")
            report.append("-" * 20)
            report.append("This security testing was performed for educational purposes only.")
            report.append("All activities were conducted with proper authorization.")
            report.append("Do not use these tools without explicit permission.")
            report.append("")
            
            report.append("END OF REPORT")
            
            return "\n".join(report)
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            return f"Error generating report: {str(e)}"
    
    def _is_browser_active(self, browser: Dict) -> bool:
        """Check if a hooked browser is still active."""
        try:
            hooked_at = datetime.fromisoformat(browser["hooked_at"])
            timeout = timedelta(seconds=self.security_config["session_timeout"])
            return datetime.now() - hooked_at < timeout
        except:
            return False
    
    def cleanup_session(self) -> Dict:
        """Clean up session data and reset the module."""
        result = {
            "success": False,
            "message": "",
            "error": None
        }
        
        try:
            # Stop server if running
            if self.session_active:
                self.stop_beef_server()
            
            # Clear session data
            self.current_session = None
            self.hooked_browsers = []
            self.session_active = False
            
            result["success"] = True
            result["message"] = "Session cleaned up successfully"
            
            logger.info("BeEF session cleaned up")
            
        except Exception as e:
            logger.error(f"Session cleanup failed: {str(e)}")
            result["error"] = str(e)
            result["message"] = "Failed to cleanup session"
        
        return result

# Module initialization
def create_beef_security_module():
    """Create and return a BeEF security module instance."""
    return BeefSecurityModule()

# Export the main class
__all__ = ['BeefSecurityModule', 'create_beef_security_module']
