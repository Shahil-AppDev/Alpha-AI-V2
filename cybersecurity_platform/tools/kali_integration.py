"""
Kali Linux Tools Integration
Integrates popular Kali tools: Nmap, Metasploit, Burp Suite, Wireshark, John the Ripper
"""

import logging
import subprocess
from typing import Dict, Any, Optional, List
from datetime import datetime


class BaseTool:
    """Base class for all Kali tools"""
    
    def __init__(self, platform, config: Dict[str, Any]):
        self.platform = platform
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.status = 'initialized'
        self.last_execution = None
        self.execution_count = 0
    
    def start(self):
        """Start the tool"""
        self.status = 'ready'
        self.logger.info(f"{self.__class__.__name__} started")
    
    def stop(self):
        """Stop the tool"""
        self.status = 'stopped'
        self.logger.info(f"{self.__class__.__name__} stopped")
    
    def execute_command(self, command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Execute a system command"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command timed out',
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'returncode': -1
            }


class NmapTool(BaseTool):
    """Nmap network scanner integration"""
    
    def scan(self, target: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        """Perform an Nmap scan"""
        self.logger.info(f"Starting Nmap scan on {target}")
        
        options = options or {}
        scan_type = options.get('scan_type', 'quick')
        
        command = ['nmap']
        
        if scan_type == 'quick':
            command.extend(['-T4', '-F'])
        elif scan_type == 'intense':
            command.extend(['-T4', '-A', '-v'])
        elif scan_type == 'stealth':
            command.extend(['-sS', '-T2'])
        elif scan_type == 'comprehensive':
            command.extend(['-p-', '-T4', '-A', '-v'])
        
        if options.get('os_detection'):
            command.append('-O')
        
        if options.get('service_version'):
            command.append('-sV')
        
        command.append(target)
        
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        result = self.execute_command(command)
        
        return {
            'tool': 'nmap',
            'target': target,
            'scan_type': scan_type,
            'timestamp': self.last_execution.isoformat(),
            'success': result['success'],
            'output': result.get('stdout', ''),
            'error': result.get('stderr', '') or result.get('error', '')
        }


class MetasploitTool(BaseTool):
    """Metasploit Framework integration"""
    
    def exploit(self, target: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        """Execute a Metasploit exploit"""
        self.logger.info(f"Starting Metasploit exploit on {target}")
        
        options = options or {}
        exploit_module = options.get('module', 'auxiliary/scanner/portscan/tcp')
        
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        return {
            'tool': 'metasploit',
            'target': target,
            'module': exploit_module,
            'timestamp': self.last_execution.isoformat(),
            'success': True,
            'output': f'Metasploit module {exploit_module} executed on {target}',
            'note': 'This is a simulation. Actual Metasploit integration requires msfconsole RPC'
        }
    
    def search_exploits(self, query: str) -> Dict[str, Any]:
        """Search for available exploits"""
        self.logger.info(f"Searching Metasploit exploits for: {query}")
        
        command = ['msfconsole', '-q', '-x', f'search {query}; exit']
        result = self.execute_command(command)
        
        return {
            'tool': 'metasploit',
            'query': query,
            'timestamp': datetime.now().isoformat(),
            'success': result['success'],
            'output': result.get('stdout', ''),
            'error': result.get('stderr', '') or result.get('error', '')
        }


class BurpSuiteTool(BaseTool):
    """Burp Suite web application security scanner"""
    
    def scan_web_app(self, target_url: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        """Scan a web application"""
        self.logger.info(f"Starting Burp Suite scan on {target_url}")
        
        options = options or {}
        scan_type = options.get('scan_type', 'passive')
        
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        return {
            'tool': 'burpsuite',
            'target': target_url,
            'scan_type': scan_type,
            'timestamp': self.last_execution.isoformat(),
            'success': True,
            'vulnerabilities_found': [],
            'note': 'Burp Suite integration requires Burp Suite Professional API'
        }


class WiresharkTool(BaseTool):
    """Wireshark network protocol analyzer"""
    
    def capture_traffic(self, interface: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        """Capture network traffic"""
        self.logger.info(f"Starting Wireshark capture on interface {interface}")
        
        options = options or {}
        duration = options.get('duration', 60)
        filter_expr = options.get('filter', '')
        
        command = ['tshark', '-i', interface, '-a', f'duration:{duration}']
        
        if filter_expr:
            command.extend(['-f', filter_expr])
        
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        result = self.execute_command(command, timeout=duration + 10)
        
        return {
            'tool': 'wireshark',
            'interface': interface,
            'duration': duration,
            'filter': filter_expr,
            'timestamp': self.last_execution.isoformat(),
            'success': result['success'],
            'packets_captured': result.get('stdout', '').count('\n'),
            'output': result.get('stdout', ''),
            'error': result.get('stderr', '') or result.get('error', '')
        }


class JohnTheRipperTool(BaseTool):
    """John the Ripper password cracker"""
    
    def crack_password(self, hash_file: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        """Crack password hashes"""
        self.logger.info(f"Starting John the Ripper on {hash_file}")
        
        options = options or {}
        wordlist = options.get('wordlist', '/usr/share/wordlists/rockyou.txt')
        hash_format = options.get('format', 'auto')
        
        command = ['john']
        
        if hash_format != 'auto':
            command.extend(['--format=' + hash_format])
        
        if wordlist:
            command.extend(['--wordlist=' + wordlist])
        
        command.append(hash_file)
        
        self.last_execution = datetime.now()
        self.execution_count += 1
        
        result = self.execute_command(command)
        
        return {
            'tool': 'john',
            'hash_file': hash_file,
            'wordlist': wordlist,
            'format': hash_format,
            'timestamp': self.last_execution.isoformat(),
            'success': result['success'],
            'output': result.get('stdout', ''),
            'error': result.get('stderr', '') or result.get('error', '')
        }


class KaliToolsIntegration:
    """Main integration class for all Kali tools"""
    
    def __init__(self, platform):
        self.platform = platform
        self.logger = logging.getLogger(__name__)
        self.tools: Dict[str, BaseTool] = {}
        self.tool_configs: Dict[str, Dict] = {}
        self.tool_status: Dict[str, Dict] = {}
    
    def initialize(self):
        """Initialize Kali tools integration"""
        self.logger.info("Initializing Kali tools integration...")
        
        self._load_tool_configurations()
        self._initialize_tools()
        
        self.logger.info(f"Initialized {len(self.tools)} Kali tools")
    
    def _load_tool_configurations(self):
        """Load tool configurations from platform config"""
        tool_config = self.platform.get_config('kali_tools', {})
        self.tool_configs = tool_config
        
        if 'default_category' not in self.tool_configs:
            self.tool_configs['default_category'] = 'network'
    
    def _initialize_tools(self):
        """Initialize all Kali tools"""
        self._initialize_nmap()
        self._initialize_metasploit()
        self._initialize_burpsuite()
        self._initialize_wireshark()
        self._initialize_john()
    
    def _initialize_nmap(self):
        """Initialize Nmap tool"""
        tool_config = self.tool_configs.get('nmap', {
            'category': 'network',
            'enabled': True,
            'version': 'latest'
        })
        
        if tool_config.get('enabled', True):
            try:
                self.tools['nmap'] = NmapTool(self.platform, tool_config)
                self.tool_status['nmap'] = {
                    'status': 'initialized',
                    'version': tool_config.get('version', 'unknown'),
                    'category': tool_config.get('category', 'network')
                }
                self.logger.info("Nmap tool initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Nmap: {e}")
    
    def _initialize_metasploit(self):
        """Initialize Metasploit tool"""
        tool_config = self.tool_configs.get('metasploit', {
            'category': 'exploitation',
            'enabled': True,
            'version': 'latest'
        })
        
        if tool_config.get('enabled', True):
            try:
                self.tools['metasploit'] = MetasploitTool(self.platform, tool_config)
                self.tool_status['metasploit'] = {
                    'status': 'initialized',
                    'version': tool_config.get('version', 'unknown'),
                    'category': tool_config.get('category', 'exploitation')
                }
                self.logger.info("Metasploit tool initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Metasploit: {e}")
    
    def _initialize_burpsuite(self):
        """Initialize Burp Suite tool"""
        tool_config = self.tool_configs.get('burpsuite', {
            'category': 'web',
            'enabled': True,
            'version': 'latest'
        })
        
        if tool_config.get('enabled', True):
            try:
                self.tools['burpsuite'] = BurpSuiteTool(self.platform, tool_config)
                self.tool_status['burpsuite'] = {
                    'status': 'initialized',
                    'version': tool_config.get('version', 'unknown'),
                    'category': tool_config.get('category', 'web')
                }
                self.logger.info("Burp Suite tool initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Burp Suite: {e}")
    
    def _initialize_wireshark(self):
        """Initialize Wireshark tool"""
        tool_config = self.tool_configs.get('wireshark', {
            'category': 'network',
            'enabled': True,
            'version': 'latest'
        })
        
        if tool_config.get('enabled', True):
            try:
                self.tools['wireshark'] = WiresharkTool(self.platform, tool_config)
                self.tool_status['wireshark'] = {
                    'status': 'initialized',
                    'version': tool_config.get('version', 'unknown'),
                    'category': tool_config.get('category', 'network')
                }
                self.logger.info("Wireshark tool initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Wireshark: {e}")
    
    def _initialize_john(self):
        """Initialize John the Ripper tool"""
        tool_config = self.tool_configs.get('john', {
            'category': 'password_cracking',
            'enabled': True,
            'version': 'latest'
        })
        
        if tool_config.get('enabled', True):
            try:
                self.tools['john'] = JohnTheRipperTool(self.platform, tool_config)
                self.tool_status['john'] = {
                    'status': 'initialized',
                    'version': tool_config.get('version', 'unknown'),
                    'category': tool_config.get('category', 'password_cracking')
                }
                self.logger.info("John the Ripper tool initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize John the Ripper: {e}")
    
    def get_tool(self, tool_name: str) -> Optional[BaseTool]:
        """Get a specific tool by name"""
        return self.tools.get(tool_name)
    
    def list_tools(self) -> List[str]:
        """List all available tools"""
        return list(self.tools.keys())
    
    def get_tool_status(self, tool_name: str) -> Optional[Dict]:
        """Get the status of a specific tool"""
        return self.tool_status.get(tool_name)
