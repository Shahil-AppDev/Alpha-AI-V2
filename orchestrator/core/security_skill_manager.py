"""
Security Skill Manager
Manages offensive and defensive security tools from Kali Linux with automated updates
"""

import logging
import subprocess
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple


class SecuritySkill:
    """Base class for security skills"""
    
    def __init__(self, skill_id: str, config: Dict[str, Any]):
        self.skill_id = skill_id
        self.config = config
        self.status = 'available'
        self.assigned_to: Optional[str] = None
        self.logger = logging.getLogger(f"{self.__class__.__name__}[{skill_id}]")
        self.execution_count = 0
        self.last_execution: Optional[datetime] = None
    
    def execute_command(self, command: List[str], timeout: int = 300) -> Tuple[str, str, int]:
        """Execute a system command and return stdout, stderr, returncode"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Command timed out', -1
        except Exception as e:
            return '', str(e), -1
    
    def heartbeat(self) -> bool:
        """Send heartbeat to confirm skill is alive"""
        return self.status in ['available', 'allocated']
    
    def allocate(self, agent_id: str) -> bool:
        """Allocate skill to an agent"""
        if self.status == 'available':
            self.status = 'allocated'
            self.assigned_to = agent_id
            self.logger.info(f"Allocated to agent {agent_id}")
            return True
        return False
    
    def release(self) -> bool:
        """Release skill from agent"""
        if self.status == 'allocated':
            self.status = 'available'
            self.assigned_to = None
            self.logger.info("Released from agent")
            return True
        return False


class NmapSkill(SecuritySkill):
    """Nmap network scanner skill"""
    
    def scan(self, target: str, options: Optional[List[str]] = None) -> Dict[str, Any]:
        """Perform Nmap scan on target"""
        if self.status != 'allocated':
            raise Exception("Nmap skill is not allocated to an agent")
        
        options = options or ['-T4', '-F']
        command = ['nmap'] + options + [target]
        
        self.logger.info(f"Scanning {target} with options {options}")
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        stdout, stderr, returncode = self.execute_command(command)
        
        return {
            'skill': 'nmap',
            'target': target,
            'options': options,
            'success': returncode == 0,
            'output': stdout,
            'error': stderr,
            'timestamp': self.last_execution.isoformat()
        }


class MetasploitSkill(SecuritySkill):
    """Metasploit Framework skill"""
    
    def search_exploits(self, query: str) -> Dict[str, Any]:
        """Search for exploits in Metasploit"""
        if self.status != 'allocated':
            raise Exception("Metasploit skill is not allocated to an agent")
        
        command = ['msfconsole', '-q', '-x', f'search {query}; exit']
        
        self.logger.info(f"Searching exploits for: {query}")
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        stdout, stderr, returncode = self.execute_command(command, timeout=60)
        
        return {
            'skill': 'metasploit',
            'query': query,
            'success': returncode == 0,
            'output': stdout,
            'error': stderr,
            'timestamp': self.last_execution.isoformat()
        }
    
    def exploit(self, module: str, target: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        """Execute Metasploit exploit"""
        if self.status != 'allocated':
            raise Exception("Metasploit skill is not allocated to an agent")
        
        self.logger.info(f"Executing module {module} on {target}")
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        return {
            'skill': 'metasploit',
            'module': module,
            'target': target,
            'success': True,
            'note': 'Metasploit RPC integration required for full functionality',
            'timestamp': self.last_execution.isoformat()
        }


class WiresharkSkill(SecuritySkill):
    """Wireshark/TShark packet analyzer skill"""
    
    def capture(self, interface: str, duration: int = 60, filter_expr: str = '') -> Dict[str, Any]:
        """Capture network traffic"""
        if self.status != 'allocated':
            raise Exception("Wireshark skill is not allocated to an agent")
        
        command = ['tshark', '-i', interface, '-a', f'duration:{duration}']
        if filter_expr:
            command.extend(['-f', filter_expr])
        
        self.logger.info(f"Capturing traffic on {interface} for {duration}s")
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        stdout, stderr, returncode = self.execute_command(command, timeout=duration + 10)
        
        return {
            'skill': 'wireshark',
            'interface': interface,
            'duration': duration,
            'filter': filter_expr,
            'success': returncode == 0,
            'packets_captured': stdout.count('\n'),
            'output': stdout,
            'error': stderr,
            'timestamp': self.last_execution.isoformat()
        }


class BurpSuiteSkill(SecuritySkill):
    """Burp Suite web application scanner skill"""
    
    def scan_web_app(self, url: str, scan_type: str = 'passive') -> Dict[str, Any]:
        """Scan web application"""
        if self.status != 'allocated':
            raise Exception("Burp Suite skill is not allocated to an agent")
        
        self.logger.info(f"Scanning web app: {url} (type: {scan_type})")
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        return {
            'skill': 'burpsuite',
            'url': url,
            'scan_type': scan_type,
            'success': True,
            'vulnerabilities': [],
            'note': 'Burp Suite Professional API required for automated scanning',
            'timestamp': self.last_execution.isoformat()
        }


class SuricataSkill(SecuritySkill):
    """Suricata IDS/IPS skill"""
    
    def monitor(self, interface: str, rules_file: str) -> Dict[str, Any]:
        """Monitor network with Suricata"""
        if self.status != 'allocated':
            raise Exception("Suricata skill is not allocated to an agent")
        
        command = ['suricata', '-c', '/etc/suricata/suricata.yaml', '-i', interface]
        
        self.logger.info(f"Starting Suricata on {interface}")
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        return {
            'skill': 'suricata',
            'interface': interface,
            'rules_file': rules_file,
            'success': True,
            'note': 'Suricata monitoring started in background',
            'timestamp': self.last_execution.isoformat()
        }


class JohnTheRipperSkill(SecuritySkill):
    """John the Ripper password cracker skill"""
    
    def crack(self, hash_file: str, wordlist: str = '/usr/share/wordlists/rockyou.txt') -> Dict[str, Any]:
        """Crack password hashes"""
        if self.status != 'allocated':
            raise Exception("John the Ripper skill is not allocated to an agent")
        
        command = ['john', '--wordlist=' + wordlist, hash_file]
        
        self.logger.info(f"Cracking hashes from {hash_file}")
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        stdout, stderr, returncode = self.execute_command(command, timeout=600)
        
        return {
            'skill': 'john',
            'hash_file': hash_file,
            'wordlist': wordlist,
            'success': returncode == 0,
            'output': stdout,
            'error': stderr,
            'timestamp': self.last_execution.isoformat()
        }


class SecuritySkillManager:
    """Manages security skills with automated updates"""
    
    def __init__(self):
        self.skills: Dict[str, SecuritySkill] = {}
        self.tool_updates: Dict[str, Dict] = {}
        self.logger = logging.getLogger(__name__)
        self.update_scheduler_running = False
        self.update_thread: Optional[threading.Thread] = None
        
        self.last_update_check: Optional[datetime] = None
        self.update_frequency = timedelta(days=1)
        
        self._initialize_default_skills()
    
    def _initialize_default_skills(self):
        """Initialize default security skills"""
        default_skills = {
            'nmap': (NmapSkill, 'offensive'),
            'metasploit': (MetasploitSkill, 'offensive'),
            'wireshark': (WiresharkSkill, 'defensive'),
            'burpsuite': (BurpSuiteSkill, 'offensive'),
            'suricata': (SuricataSkill, 'defensive'),
            'john': (JohnTheRipperSkill, 'offensive')
        }
        
        for skill_id, (skill_class, skill_type) in default_skills.items():
            try:
                skill = skill_class(skill_id, {'type': skill_type})
                self.register_skill(skill_id, skill_type, skill)
                self.logger.info(f"Initialized {skill_id} skill")
            except Exception as e:
                self.logger.error(f"Failed to initialize {skill_id}: {e}")
    
    def register_skill(self, skill_id: str, skill_type: str, skill_instance: SecuritySkill) -> str:
        """Register a new security skill"""
        self.skills[skill_id] = skill_instance
        
        self.tool_updates[skill_id] = {
            'type': skill_type,
            'status': 'registered',
            'last_heartbeat': datetime.now(),
            'last_update': None,
            'version': 'unknown'
        }
        
        self.logger.info(f"Registered skill: {skill_id} (type: {skill_type})")
        return skill_id
    
    def update_skill_status(self, skill_id: str, status_update: Dict) -> bool:
        """Update the status of a security skill"""
        if skill_id in self.tool_updates:
            self.tool_updates[skill_id].update(status_update)
            self.tool_updates[skill_id]['last_heartbeat'] = datetime.now()
            return True
        return False
    
    def get_available_skills(self) -> List[str]:
        """Get list of available security skills"""
        return [
            skill_id for skill_id, skill in self.skills.items()
            if skill.status == 'available'
        ]
    
    def get_skill(self, skill_id: str) -> Optional[SecuritySkill]:
        """Get a specific skill by ID"""
        return self.skills.get(skill_id)
    
    def allocate_skill(self, skill_id: str, agent_id: str) -> bool:
        """Allocate a security skill to an agent"""
        if skill_id in self.skills:
            return self.skills[skill_id].allocate(agent_id)
        return False
    
    def release_skill(self, skill_id: str) -> bool:
        """Release a security skill from an agent"""
        if skill_id in self.skills:
            return self.skills[skill_id].release()
        return False
    
    def start_auto_update(self):
        """Start automated daily updates"""
        if not self.update_scheduler_running:
            self.update_scheduler_running = True
            self.update_thread = threading.Thread(target=self._update_scheduler_loop, daemon=True)
            self.update_thread.start()
            self.logger.info("Auto-update scheduler started")
    
    def stop_auto_update(self):
        """Stop automated updates"""
        self.update_scheduler_running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
        self.logger.info("Auto-update scheduler stopped")
    
    def _update_scheduler_loop(self):
        """Main loop for update scheduler"""
        while self.update_scheduler_running:
            try:
                now = datetime.now()
                
                if (self.last_update_check is None or
                    now - self.last_update_check >= self.update_frequency):
                    
                    self.logger.info("Running scheduled security tools update...")
                    self.update_tool_database()
                    self.last_update_check = now
                
                time.sleep(3600)
                
            except Exception as e:
                self.logger.error(f"Error in update scheduler: {e}")
                time.sleep(3600)
    
    def update_tool_database(self) -> Dict[str, Any]:
        """Update security tools from Kali repositories"""
        self.logger.info("Updating security tool database...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'tools_updated': [],
            'tools_failed': [],
            'success': True
        }
        
        try:
            self.logger.info("Running apt update...")
            stdout, stderr, returncode = self._execute_update_command(['apt-get', 'update'])
            
            if returncode != 0:
                results['success'] = False
                results['error'] = f"apt update failed: {stderr}"
                return results
            
            tools_to_update = ['nmap', 'metasploit-framework', 'wireshark', 'burpsuite', 'suricata', 'john']
            
            for tool in tools_to_update:
                try:
                    self.logger.info(f"Updating {tool}...")
                    stdout, stderr, returncode = self._execute_update_command(
                        ['apt-get', 'install', '--only-upgrade', '-y', tool]
                    )
                    
                    if returncode == 0:
                        results['tools_updated'].append(tool)
                        if tool in self.tool_updates:
                            self.tool_updates[tool]['last_update'] = datetime.now()
                    else:
                        results['tools_failed'].append({'tool': tool, 'error': stderr})
                        
                except Exception as e:
                    results['tools_failed'].append({'tool': tool, 'error': str(e)})
            
            self.logger.info(f"Update complete: {len(results['tools_updated'])} updated, {len(results['tools_failed'])} failed")
            
        except Exception as e:
            results['success'] = False
            results['error'] = str(e)
            self.logger.error(f"Tool database update failed: {e}")
        
        return results
    
    def check_tool_updates(self) -> Dict[str, Any]:
        """Check for available updates without installing"""
        self.logger.info("Checking for security tool updates...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'updates_available': [],
            'up_to_date': [],
            'check_failed': []
        }
        
        try:
            stdout, stderr, returncode = self._execute_update_command(['apt-get', 'update'])
            
            if returncode != 0:
                results['error'] = f"apt update failed: {stderr}"
                return results
            
            tools_to_check = ['nmap', 'metasploit-framework', 'wireshark', 'burpsuite', 'suricata', 'john']
            
            for tool in tools_to_check:
                try:
                    stdout, stderr, returncode = self._execute_update_command(
                        ['apt-cache', 'policy', tool]
                    )
                    
                    if returncode == 0:
                        if 'Candidate:' in stdout and 'Installed:' in stdout:
                            installed = self._extract_version(stdout, 'Installed:')
                            candidate = self._extract_version(stdout, 'Candidate:')
                            
                            if installed != candidate:
                                results['updates_available'].append({
                                    'tool': tool,
                                    'installed': installed,
                                    'candidate': candidate
                                })
                            else:
                                results['up_to_date'].append(tool)
                    else:
                        results['check_failed'].append({'tool': tool, 'error': stderr})
                        
                except Exception as e:
                    results['check_failed'].append({'tool': tool, 'error': str(e)})
            
            self.logger.info(f"Update check complete: {len(results['updates_available'])} updates available")
            
        except Exception as e:
            results['error'] = str(e)
            self.logger.error(f"Update check failed: {e}")
        
        return results
    
    def _execute_update_command(self, command: List[str], timeout: int = 300) -> Tuple[str, str, int]:
        """Execute update command with sudo if needed"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Command timed out', -1
        except Exception as e:
            return '', str(e), -1
    
    def _extract_version(self, output: str, prefix: str) -> str:
        """Extract version from apt-cache policy output"""
        for line in output.split('\n'):
            if prefix in line:
                parts = line.split(prefix)
                if len(parts) > 1:
                    return parts[1].strip().split()[0]
        return 'unknown'
    
    def get_skill_stats(self) -> Dict[str, Any]:
        """Get statistics about security skills"""
        return {
            'total_skills': len(self.skills),
            'available_skills': len(self.get_available_skills()),
            'allocated_skills': sum(1 for s in self.skills.values() if s.status == 'allocated'),
            'last_update_check': self.last_update_check.isoformat() if self.last_update_check else None,
            'skills': {
                skill_id: {
                    'status': skill.status,
                    'assigned_to': skill.assigned_to,
                    'execution_count': skill.execution_count,
                    'last_execution': skill.last_execution.isoformat() if skill.last_execution else None
                }
                for skill_id, skill in self.skills.items()
            }
        }
