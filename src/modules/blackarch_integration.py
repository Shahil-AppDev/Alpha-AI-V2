"""
BlackArch Linux Integration Module

This module provides comprehensive integration with BlackArch Linux and ArchStrike
repository for the HackerAI platform, including tool management, updates, and
specialized BlackArch tool execution.
"""

import asyncio
import json
import logging
import re
import subprocess
import tempfile
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import xml.etree.ElementTree as ET
import yaml

from modules.universal_tool_manager import UniversalToolManager, ToolDefinition, ToolCategory, ExecutionMode

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BlackArchRepository:
    """Manages BlackArch Linux repository integration."""
    
    def __init__(self):
        self.repo_url = "https://blackarch.org"
        self.archstrike_url = "https://archstrike.org"
        self.package_db_url = "https://mirrors.kernel.org/archlinux/blackarch/blackarch.db.tar.gz"
        self.installed_packages = set()
        self.available_packages = {}
        
    async def initialize(self):
        """Initialize BlackArch repository connection."""
        try:
            # Check if BlackArch is already configured
            await self._check_blackarch_installation()
            
            # Load available packages
            await self._load_package_database()
            
            logger.info("BlackArch repository initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize BlackArch repository: {e}")
            raise
    
    async def _check_blackarch_installation(self):
        """Check if BlackArch is installed and configured."""
        try:
            # Check for blackarch repo in pacman.conf
            result = await asyncio.create_subprocess_exec(
                "grep", "-q", "\\[blackarch\\]", "/etc/pacman.conf",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()
            
            if result.returncode != 0:
                logger.info("BlackArch repository not found, installing...")
                await self._install_blackarch()
            
            # Check for archstrike repo
            result = await asyncio.create_subprocess_exec(
                "grep", "-q", "\\[archstrike\\]", "/etc/pacman.conf",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()
            
            if result.returncode != 0:
                logger.info("ArchStrike repository not found, adding...")
                await self._add_archstrike_repo()
            
            # Update package databases
            await self._update_package_databases()
            
            # Get installed packages
            await self._get_installed_packages()
            
        except Exception as e:
            logger.error(f"Error checking BlackArch installation: {e}")
            raise
    
    async def _install_blackarch(self):
        """Install BlackArch repository."""
        try:
            # Download and execute BlackArch strap script
            strap_url = "https://blackarch.org/strap.sh"
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                # Download strap script
                with urllib.request.urlopen(strap_url) as response:
                    f.write(response.read().decode('utf-8'))
                
                strap_path = f.name
            
            # Make executable and run
            await asyncio.create_subprocess_exec("chmod", "+x", strap_path)
            result = await asyncio.create_subprocess_exec(
                "sudo", "bash", strap_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                raise Exception(f"BlackArch installation failed: {stderr.decode()}")
            
            # Clean up
            Path(strap_path).unlink()
            
            logger.info("BlackArch repository installed successfully")
            
        except Exception as e:
            logger.error(f"Failed to install BlackArch: {e}")
            raise
    
    async def _add_archstrike_repo(self):
        """Add ArchStrike repository to pacman.conf."""
        try:
            # Add ArchStrike repository to pacman.conf
            archstrike_repo = """
[archstrike]
Server = https://mirror.archstrike.org/$arch/$repo
"""
            
            # Backup original pacman.conf
            await asyncio.create_subprocess_exec(
                "sudo", "cp", "/etc/pacman.conf", "/etc/pacman.conf.backup"
            )
            
            # Append ArchStrike repo
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(archstrike_repo)
                temp_path = f.name
            
            await asyncio.create_subprocess_exec(
                "sudo", "tee", "-a", "/etc/pacman.conf",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            ).communicate(archstrike_repo.encode())
            
            Path(temp_path).unlink()
            
            logger.info("ArchStrike repository added successfully")
            
        except Exception as e:
            logger.error(f"Failed to add ArchStrike repository: {e}")
            raise
    
    async def _update_package_databases(self):
        """Update package databases."""
        try:
            result = await asyncio.create_subprocess_exec(
                "sudo", "pacman", "-Sy",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                raise Exception(f"Package database update failed: {stderr.decode()}")
            
            logger.info("Package databases updated successfully")
            
        except Exception as e:
            logger.error(f"Failed to update package databases: {e}")
            raise
    
    async def _get_installed_packages(self):
        """Get list of installed BlackArch packages."""
        try:
            result = await asyncio.create_subprocess_exec(
                "pacman", "-Q",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                packages = stdout.decode().strip().split('\n')
                self.installed_packages = set(pkg.split()[0] for pkg in packages if pkg.strip())
            
            logger.info(f"Found {len(self.installed_packages)} installed packages")
            
        except Exception as e:
            logger.error(f"Failed to get installed packages: {e}")
    
    async def _load_package_database(self):
        """Load BlackArch package database."""
        try:
            # Download package database
            with tempfile.NamedTemporaryFile(delete=False) as f:
                with urllib.request.urlopen(self.package_db_url) as response:
                    f.write(response.read())
                db_path = f.name
            
            # Extract and parse database
            import tarfile
            with tarfile.open(db_path, 'r:gz') as tar:
                tar.extractall(path=tempfile.gettempdir())
            
            # Parse package info
            desc_dir = Path(tempfile.gettempdir()) / "blackarch" / "desc"
            if desc_dir.exists():
                for desc_file in desc_dir.glob("*/desc"):
                    package_info = self._parse_package_desc(desc_file)
                    if package_info:
                        self.available_packages[package_info['name']] = package_info
            
            # Clean up
            Path(db_path).unlink()
            import shutil
            shutil.rmtree(Path(tempfile.gettempdir()) / "blackarch", ignore_errors=True)
            
            logger.info(f"Loaded {len(self.available_packages)} available packages")
            
        except Exception as e:
            logger.error(f"Failed to load package database: {e}")
    
    def _parse_package_desc(self, desc_file: Path) -> Optional[Dict[str, Any]]:
        """Parse package description file."""
        try:
            with open(desc_file, 'r') as f:
                content = f.read()
            
            package_info = {}
            current_field = None
            
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('%') and line.endswith('%'):
                    current_field = line[1:-1].lower()
                    package_info[current_field] = []
                elif current_field and line:
                    package_info[current_field].append(line)
            
            # Convert lists to strings where appropriate
            for key, value in package_info.items():
                if len(value) == 1:
                    package_info[key] = value[0]
                elif key in ['depends', 'optdepends', 'makedepends']:
                    package_info[key] = value
            
            package_info['installed'] = package_info.get('name', '') in self.installed_packages
            
            return package_info
            
        except Exception as e:
            logger.error(f"Failed to parse package desc {desc_file}: {e}")
            return None
    
    async def install_package(self, package_name: str) -> bool:
        """Install a BlackArch package."""
        try:
            if package_name not in self.available_packages:
                logger.error(f"Package {package_name} not found in BlackArch repository")
                return False
            
            result = await asyncio.create_subprocess_exec(
                "sudo", "pacman", "-S", "--noconfirm", package_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                self.installed_packages.add(package_name)
                self.available_packages[package_name]['installed'] = True
                logger.info(f"Successfully installed {package_name}")
                return True
            else:
                logger.error(f"Failed to install {package_name}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error installing package {package_name}: {e}")
            return False
    
    async def remove_package(self, package_name: str) -> bool:
        """Remove a BlackArch package."""
        try:
            result = await asyncio.create_subprocess_exec(
                "sudo", "pacman", "-R", "--noconfirm", package_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                self.installed_packages.discard(package_name)
                if package_name in self.available_packages:
                    self.available_packages[package_name]['installed'] = False
                logger.info(f"Successfully removed {package_name}")
                return True
            else:
                logger.error(f"Failed to remove {package_name}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error removing package {package_name}: {e}")
            return False
    
    async def update_package(self, package_name: str) -> bool:
        """Update a BlackArch package."""
        try:
            result = await asyncio.create_subprocess_exec(
                "sudo", "pacman", "-S", "--noconfirm", package_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                logger.info(f"Successfully updated {package_name}")
                return True
            else:
                logger.error(f"Failed to update {package_name}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating package {package_name}: {e}")
            return False
    
    async def search_packages(self, query: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search for packages in BlackArch repository."""
        results = []
        query_lower = query.lower()
        
        for name, info in self.available_packages.items():
            # Filter by category if specified
            if category and info.get('groups', []):
                if category.lower() not in ' '.join(info['groups']).lower():
                    continue
            
            # Search in name and description
            if (query_lower in name.lower() or 
                query_lower in info.get('desc', '').lower()):
                
                results.append({
                    'name': name,
                    'version': info.get('version', 'unknown'),
                    'description': info.get('desc', 'No description'),
                    'groups': info.get('groups', []),
                    'installed': info.get('installed', False),
                    'size': info.get('size', 'unknown')
                })
        
        return results
    
    def get_package_info(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a package."""
        return self.available_packages.get(package_name)
    
    def get_packages_by_category(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get packages grouped by category."""
        categorized = {}
        
        for name, info in self.available_packages.items():
            groups = info.get('groups', [])
            if groups:
                category = groups[0]  # Use first group as category
                if category not in categorized:
                    categorized[category] = []
                
                categorized[category].append({
                    'name': name,
                    'version': info.get('version', 'unknown'),
                    'description': info.get('desc', 'No description'),
                    'installed': info.get('installed', False)
                })
        
        return categorized


class BlackArchToolManager:
    """Enhanced tool manager with BlackArch integration."""
    
    def __init__(self, tool_manager: UniversalToolManager):
        self.tool_manager = tool_manager
        self.blackarch_repo = BlackArchRepository()
        self.blackarch_tools = {}
        
    async def initialize(self):
        """Initialize BlackArch tool manager."""
        await self.blackarch_repo.initialize()
        await self._register_blackarch_tools()
        
    async def _register_blackarch_tools(self):
        """Register BlackArch tools with the universal tool manager."""
        # Define key BlackArch tools to register
        blackarch_tools_config = [
            # OSINT Tools
            {
                'name': 'theharvester',
                'category': ToolCategory.OSINT,
                'description': 'Emails, subdomains and hosts harvester',
                'executable_path': '/usr/bin/theHarvester',
                'docker_image': 'blackarch/theharvester',
                'parameters': {
                    'domain': {'type': 'string', 'required': True},
                    'source': {'type': 'string', 'default': 'all'},
                    'limit': {'type': 'int', 'default': 500}
                }
            },
            {
                'name': 'sherlock',
                'category': ToolCategory.OSINT,
                'description': 'Find usernames across social networks',
                'executable_path': '/usr/bin/sherlock',
                'docker_image': 'blackarch/sherlock',
                'parameters': {
                    'username': {'type': 'string', 'required': True}
                }
            },
            {
                'name': 'recon-ng',
                'category': ToolCategory.OSINT,
                'description': 'Web reconnaissance framework',
                'executable_path': '/usr/bin/recon-ng',
                'docker_image': 'blackarch/recon-ng',
                'parameters': {
                    'workspace': {'type': 'string', 'default': 'default'},
                    'module': {'type': 'string', 'required': True}
                }
            },
            # Network Tools
            {
                'name': 'nmap',
                'category': ToolCategory.NETWORK_SCANNING,
                'description': 'Network discovery and security auditing',
                'executable_path': '/usr/bin/nmap',
                'docker_image': 'instrumentisto/nmap',
                'parameters': {
                    'target': {'type': 'string', 'required': True},
                    'ports': {'type': 'string', 'default': '1-1000'},
                    'scan_type': {'type': 'string', 'default': '-sS'}
                }
            },
            {
                'name': 'masscan',
                'category': ToolCategory.NETWORK_SCANNING,
                'description': 'Fast TCP port scanner',
                'executable_path': '/usr/bin/masscan',
                'docker_image': 'blackarch/masscan',
                'parameters': {
                    'target': {'type': 'string', 'required': True},
                    'ports': {'type': 'string', 'default': '0-65535'},
                    'rate': {'type': 'int', 'default': 1000}
                }
            },
            # Web Security Tools
            {
                'name': 'sqlmap',
                'category': ToolCategory.WEB_APPLICATION,
                'description': 'Automatic SQL injection tool',
                'executable_path': '/usr/bin/sqlmap',
                'docker_image': 'sqlmapproject/sqlmap',
                'parameters': {
                    'url': {'type': 'string', 'required': True},
                    'batch': {'type': 'bool', 'default': True},
                    'level': {'type': 'int', 'default': 1}
                }
            },
            {
                'name': 'nikto',
                'category': ToolCategory.VULNERABILITY_SCANNING,
                'description': 'Web server scanner',
                'executable_path': '/usr/bin/nikto',
                'docker_image': 'frapsoft/nikto',
                'parameters': {
                    'host': {'type': 'string', 'required': True},
                    'port': {'type': 'int', 'default': 80}
                }
            },
            # Password Cracking Tools
            {
                'name': 'hashcat',
                'category': ToolCategory.PASSWORD_CRACKING,
                'description': 'Advanced password recovery',
                'executable_path': '/usr/bin/hashcat',
                'docker_image': 'daisukehishimoto/hashcat',
                'parameters': {
                    'hash': {'type': 'string', 'required': True},
                    'hash_type': {'type': 'int', 'default': 0},
                    'wordlist': {'type': 'string', 'default': '/usr/share/wordlists/rockyou.txt'}
                }
            },
            {
                'name': 'john',
                'category': ToolCategory.PASSWORD_CRACKING,
                'description': 'Password cracker',
                'executable_path': '/usr/bin/john',
                'docker_image': 'blackarch/john',
                'parameters': {
                    'hash_file': {'type': 'string', 'required': True},
                    'wordlist': {'type': 'string', 'default': '/usr/share/wordlists/rockyou.txt'}
                }
            },
            {
                'name': 'hydra',
                'category': ToolCategory.PASSWORD_CRACKING,
                'description': 'Parallel login cracker',
                'executable_path': '/usr/bin/hydra',
                'docker_image': 'blackarch/hydra',
                'parameters': {
                    'target': {'type': 'string', 'required': True},
                    'service': {'type': 'string', 'required': True},
                    'username': {'type': 'string', 'required': True},
                    'password_file': {'type': 'string', 'default': '/usr/share/wordlists/rockyou.txt'}
                }
            },
            # Exploitation Tools
            {
                'name': 'metasploit',
                'category': ToolCategory.EXPLOITATION,
                'description': 'Metasploit Framework',
                'executable_path': '/usr/bin/msfconsole',
                'docker_image': 'metasploitframework/metasploit-framework',
                'parameters': {
                    'exploit': {'type': 'string', 'required': True},
                    'payload': {'type': 'string', 'required': True},
                    'target': {'type': 'string', 'required': True}
                }
            },
            # Wireless Tools
            {
                'name': 'aircrack-ng',
                'category': ToolCategory.WIRELESS,
                'description': 'WiFi security suite',
                'executable_path': '/usr/bin/aircrack-ng',
                'docker_image': 'aircrack-ng/aircrack-ng',
                'parameters': {
                    'capture_file': {'type': 'string', 'required': True},
                    'wordlist': {'type': 'string', 'default': '/usr/share/wordlists/rockyou.txt'}
                }
            },
            # Social Engineering Tools
            {
                'name': 'setoolkit',
                'category': ToolCategory.SOCIAL_ENGINEERING,
                'description': 'Social Engineer Toolkit',
                'executable_path': '/usr/bin/setoolkit',
                'docker_image': 'trustedsec/social-engineer-toolkit',
                'parameters': {
                    'attack_type': {'type': 'string', 'required': True},
                    'target': {'type': 'string', 'required': True}
                }
            },
            # Forensics Tools
            {
                'name': 'autopsy',
                'category': ToolCategory.FORENSICS,
                'description': 'Digital forensics platform',
                'executable_path': '/usr/bin/autopsy',
                'docker_image': 'slesinger/autopsy',
                'parameters': {
                    'case_name': {'type': 'string', 'required': True},
                    'evidence_path': {'type': 'string', 'required': True}
                }
            },
            # Reverse Engineering Tools
            {
                'name': 'radare2',
                'category': ToolCategory.EXPLOITATION,
                'description': 'Reverse engineering framework',
                'executable_path': '/usr/bin/r2',
                'docker_image': 'radareorg/radare2',
                'parameters': {
                    'binary': {'type': 'string', 'required': True},
                    'analysis_level': {'type': 'int', 'default': 2}
                }
            },
            # Malware Analysis Tools
            {
                'name': 'yara',
                'category': ToolCategory.MALWARE_ANALYSIS,
                'description': 'Malware identification tool',
                'executable_path': '/usr/bin/yara',
                'docker_image': 'virustotal/yara',
                'parameters': {
                    'rules_file': {'type': 'string', 'required': True},
                    'target': {'type': 'string', 'required': True}
                }
            }
        ]
        
        # Register each tool
        for tool_config in blackarch_tools_config:
            tool = ToolDefinition(
                name=tool_config['name'],
                category=tool_config['category'],
                description=tool_config['description'],
                version="latest",  # Will be updated from package info
                executable_path=tool_config['executable_path'],
                docker_image=tool_config['docker_image'],
                parameters=tool_config['parameters'],
                execution_mode=ExecutionMode.DOCKER,
                install_command=f"sudo pacman -S --noconfirm {tool_config['name']}",
                update_command=f"sudo pacman -S --noconfirm {tool_config['name']}"
            )
            
            self.tool_manager.register_tool(tool)
            self.blackarch_tools[tool_config['name']] = tool
            
        logger.info(f"Registered {len(self.blackarch_tools)} BlackArch tools")
    
    async def install_blackarch_tools(self, tool_names: List[str] = None) -> Dict[str, bool]:
        """Install BlackArch tools."""
        if not tool_names:
            # Install all essential BlackArch tools
            tool_names = list(self.blackarch_tools.keys())
        
        results = {}
        
        for tool_name in tool_names:
            if tool_name in self.blackarch_tools:
                success = await self.blackarch_repo.install_package(tool_name)
                results[tool_name] = success
                
                if success:
                    # Update tool status
                    tool = self.blackarch_tools[tool_name]
                    # Get package info for version
                    package_info = self.blackarch_repo.get_package_info(tool_name)
                    if package_info:
                        tool.version = package_info.get('version', 'latest')
            else:
                results[tool_name] = False
        
        return results
    
    async def update_blackarch_tools(self, tool_names: List[str] = None) -> Dict[str, bool]:
        """Update BlackArch tools."""
        if not tool_names:
            tool_names = list(self.blackarch_tools.keys())
        
        results = {}
        
        for tool_name in tool_names:
            if tool_name in self.blackarch_tools:
                success = await self.blackarch_repo.update_package(tool_name)
                results[tool_name] = success
            else:
                results[tool_name] = False
        
        return results
    
    async def search_blackarch_tools(self, query: str, category: str = None) -> List[Dict[str, Any]]:
        """Search for BlackArch tools."""
        packages = await self.blackarch_repo.search_packages(query, category)
        
        # Filter to only include registered tools
        registered_tools = set(self.blackarch_tools.keys())
        filtered_packages = [pkg for pkg in packages if pkg['name'] in registered_tools]
        
        return filtered_packages
    
    def get_blackarch_categories(self) -> Dict[str, List[str]]:
        """Get BlackArch tools by category."""
        categories = {}
        
        for tool_name, tool in self.blackarch_tools.items():
            category = tool.category.value
            if category not in categories:
                categories[category] = []
            categories[category].append(tool_name)
        
        return categories
    
    async def get_blackarch_status(self) -> Dict[str, Any]:
        """Get BlackArch integration status."""
        installed_tools = []
        available_tools = []
        
        for tool_name, tool in self.blackarch_tools.items():
            package_info = self.blackarch_repo.get_package_info(tool_name)
            if package_info and package_info.get('installed', False):
                installed_tools.append(tool_name)
            available_tools.append(tool_name)
        
        return {
            "repository_connected": True,
            "total_registered_tools": len(self.blackarch_tools),
            "installed_tools": len(installed_tools),
            "available_tools": len(available_tools),
            "categories": self.get_blackarch_categories(),
            "installed_tool_list": installed_tools,
            "last_update": datetime.now().isoformat()
        }


# BlackArch Integration API Endpoints
class BlackArchAPI:
    """API endpoints for BlackArch integration."""
    
    def __init__(self, blackarch_manager: BlackArchToolManager):
        self.blackarch_manager = blackarch_manager
    
    async def get_status(self) -> Dict[str, Any]:
        """Get BlackArch integration status."""
        return await self.blackarch_manager.get_blackarch_status()
    
    async def search_tools(self, query: str, category: str = None) -> List[Dict[str, Any]]:
        """Search for BlackArch tools."""
        return await self.blackarch_manager.search_blackarch_tools(query, category)
    
    async def install_tools(self, tool_names: List[str] = None) -> Dict[str, bool]:
        """Install BlackArch tools."""
        return await self.blackarch_manager.install_blackarch_tools(tool_names)
    
    async def update_tools(self, tool_names: List[str] = None) -> Dict[str, bool]:
        """Update BlackArch tools."""
        return await self.blackarch_manager.update_blackarch_tools(tool_names)
    
    def get_categories(self) -> Dict[str, List[str]]:
        """Get BlackArch tool categories."""
        return self.blackarch_manager.get_blackarch_categories()


# Example usage
async def main():
    """Example usage of BlackArch integration."""
    from modules.universal_tool_manager import UniversalToolManager
    
    # Initialize tool manager
    tool_manager = UniversalToolManager()
    
    # Initialize BlackArch integration
    blackarch_manager = BlackArchToolManager(tool_manager)
    await blackarch_manager.initialize()
    
    # Get status
    status = await blackarch_manager.get_blackarch_status()
    print("BlackArch Status:")
    print(json.dumps(status, indent=2, default=str))
    
    # Search for tools
    search_results = await blackarch_manager.search_blackarch_tools("nmap")
    print(f"\nFound {len(search_results)} nmap-related tools")
    
    # Get categories
    categories = blackarch_manager.get_blackarch_categories()
    print(f"\nAvailable categories: {list(categories.keys())}")
    
    # Install essential tools
    install_results = await blackarch_manager.install_blackarch_tools(["nmap", "sqlmap", "nikto"])
    print(f"\nInstallation results: {install_results}")


if __name__ == "__main__":
    asyncio.run(main())
