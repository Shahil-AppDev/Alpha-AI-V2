"""
BlackArch Tool Manager for AI Agent Orchestrator
Provides integration with BlackArch Linux penetration testing tools.
"""

import subprocess
import logging
import json
import uuid
import os
import shutil
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    """Enumeration for tool status states."""
    REGISTERED = "registered"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UPDATING = "updating"


class ToolCategory(Enum):
    """Enumeration for BlackArch tool categories."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    PASSWORD_ATTACKS = "password_attacks"
    WEB_APPLICATION = "web_application"
    NETWORK_SNIFFING = "network_sniffing"
    FORENSICS = "forensics"
    REVERSE_ENGINEERING = "reverse_engineering"
    WIRELESS_ATTACKS = "wireless_attacks"
    SOCIAL_ENGINEERING = "social_engineering"
    POST_EXPLOITATION = "post_exploitation"
    MISC = "miscellaneous"


@dataclass
class BlackArchTool:
    """Represents a BlackArch tool with metadata and status."""
    tool_id: str
    name: str
    category: ToolCategory
    description: str
    command: str
    config: Dict[str, Any]
    status: ToolStatus = ToolStatus.REGISTERED
    assigned_to: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    execution_history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def update_status(self, new_status: ToolStatus, metadata: Optional[Dict[str, Any]] = None):
        """Update tool status and timestamp."""
        self.status = new_status
        self.updated_at = datetime.now()
        if metadata:
            self.metadata.update(metadata)
    
    def add_execution_record(self, record: Dict[str, Any]):
        """Add an execution record to the tool's history."""
        self.execution_history.append({
            **record,
            "timestamp": datetime.now().isoformat()
        })
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert tool to dictionary representation."""
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "command": self.command,
            "config": self.config,
            "status": self.status.value,
            "assigned_to": self.assigned_to,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "execution_history": self.execution_history,
            "metadata": self.metadata
        }


class BlackArchToolManager:
    """
    Manages BlackArch Linux tools for the AI agent orchestrator.
    Provides tool registration, execution, and status tracking.
    """
    
    def __init__(self, blackarch_path: Optional[str] = None):
        """
        Initialize the BlackArch Tool Manager.
        
        Args:
            blackarch_path: Optional custom path to BlackArch installation
        """
        self.tools: Dict[str, BlackArchTool] = {}
        self.agent_assignments: Dict[str, List[str]] = {}  # agent_id -> list of tool_ids
        self.blackarch_path = blackarch_path or "/usr/bin"
        self._check_blackarch_installation()
        self._register_default_tools()
        logger.info("BlackArchToolManager initialized")
    
    def _check_blackarch_installation(self):
        """Check if BlackArch tools are available on the system."""
        try:
            # Check if common BlackArch tools are available
            test_tools = ["nmap", "nikto", "sqlmap", "hydra"]
            available_tools = []
            
            for tool in test_tools:
                if shutil.which(tool):
                    available_tools.append(tool)
            
            if available_tools:
                logger.info(f"BlackArch tools detected: {len(available_tools)} common tools available")
            else:
                logger.warning("No common BlackArch tools detected. Some features may not work.")
                
        except Exception as e:
            logger.error(f"Error checking BlackArch installation: {str(e)}")
    
    def _register_default_tools(self):
        """Register default BlackArch tools."""
        default_tools = [
            # Reconnaissance
            {
                "name": "nmap",
                "category": ToolCategory.SCANNING,
                "description": "Network exploration and security scanning",
                "command": "nmap",
                "config": {
                    "default_options": "-sS -sV",
                    "requires_target": True,
                    "common_options": ["-p", "-oX", "-oN"]
                }
            },
            {
                "name": "nikto",
                "category": ToolCategory.WEB_APPLICATION,
                "description": "Web server scanner",
                "command": "nikto",
                "config": {
                    "default_options": "-h",
                    "requires_target": True,
                    "common_options": ["-p", "-o", "-Format"]
                }
            },
            {
                "name": "sqlmap",
                "category": ToolCategory.WEB_APPLICATION,
                "description": "SQL injection and database takeover tool",
                "command": "sqlmap",
                "config": {
                    "default_options": "-u",
                    "requires_target": True,
                    "common_options": ["--dbs", "--tables", "--dump"]
                }
            },
            {
                "name": "hydra",
                "category": ToolCategory.PASSWORD_ATTACKS,
                "description": "Online password cracking tool",
                "command": "hydra",
                "config": {
                    "default_options": "",
                    "requires_target": True,
                    "common_options": ["-l", "-P", "-s", "-V"]
                }
            },
            {
                "name": "dirb",
                "category": ToolCategory.WEB_APPLICATION,
                "description": "Web content scanner",
                "command": "dirb",
                "config": {
                    "default_options": "",
                    "requires_target": True,
                    "common_options": ["-o", "-a", "-x"]
                }
            },
            {
                "name": "gobuster",
                "category": ToolCategory.WEB_APPLICATION,
                "description": "Directory/file, DNS and VHost busting tool",
                "command": "gobuster",
                "config": {
                    "default_options": "dir",
                    "requires_target": True,
                    "common_options": ["-u", "-w", "-o", "-x"]
                }
            },
            {
                "name": "wireshark",
                "category": ToolCategory.NETWORK_SNIFFING,
                "description": "Network protocol analyzer",
                "command": "tshark",  # CLI version of wireshark
                "config": {
                    "default_options": "-i",
                    "requires_target": False,
                    "common_options": ["-i", "-w", "-c"]
                }
            },
            {
                "name": "metasploit",
                "category": ToolCategory.EXPLOITATION,
                "description": "Metasploit framework",
                "command": "msfconsole",
                "config": {
                    "default_options": "-q",
                    "requires_target": False,
                    "common_options": ["-r", "-x", "-q"]
                }
            },
            {
                "name": "burpsuite",
                "category": ToolCategory.WEB_APPLICATION,
                "description": "Web application security testing platform",
                "command": "burpsuite",
                "config": {
                    "default_options": "",
                    "requires_target": False,
                    "common_options": ["--project-file=", "--headless"]
                }
            },
            {
                "name": "john",
                "category": ToolCategory.PASSWORD_ATTACKS,
                "description": "John the Ripper password cracker",
                "command": "john",
                "config": {
                    "default_options": "",
                    "requires_target": False,
                    "common_options": ["--wordlist", "--format", "--show"]
                }
            }
        ]
        
        for tool_info in default_tools:
            self.register_tool(
                tool_info["name"],
                tool_info["category"],
                tool_info["description"],
                tool_info["command"],
                tool_info["config"]
            )
    
    def register_tool(self, name: str, category: ToolCategory, description: str, 
                     command: str, config: Dict[str, Any], tool_id: Optional[str] = None) -> str:
        """
        Register a new BlackArch tool with the orchestrator.
        
        Args:
            name: Human-readable name of the tool
            category: Category of the tool
            description: Description of what the tool does
            command: Command to execute the tool
            config: Configuration dictionary for the tool
            tool_id: Optional custom tool ID (auto-generated if not provided)
            
        Returns:
            Tool ID of the registered tool
        """
        if tool_id is None:
            tool_id = f"tool_{uuid.uuid4().hex[:8]}"
        
        if tool_id in self.tools:
            logger.warning(f"Tool with ID '{tool_id}' already exists. Overwriting.")
        
        tool = BlackArchTool(
            tool_id=tool_id,
            name=name,
            category=category,
            description=description,
            command=command,
            config=config
        )
        
        self.tools[tool_id] = tool
        logger.info(f"Registered BlackArch tool '{name}' with ID '{tool_id}'")
        return tool_id
    
    def update_tool_status(self, tool_id: str, status: ToolStatus, 
                          metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update the status of a BlackArch tool.
        
        Args:
            tool_id: ID of the tool to update
            status: New status for the tool
            metadata: Optional metadata to include with the update
            
        Returns:
            True if update successful, False if tool not found
        """
        if tool_id not in self.tools:
            logger.error(f"Tool {tool_id} not found")
            return False
        
        self.tools[tool_id].update_status(status, metadata)
        logger.info(f"Updated tool {tool_id} status to {status.value}")
        return True
    
    def get_available_tools(self, category: Optional[ToolCategory] = None) -> List[str]:
        """
        Get a list of available BlackArch tools.
        
        Args:
            category: Optional filter for specific category
            
        Returns:
            List of tool IDs that are available for assignment
        """
        available_tools = []
        for tool_id, tool in self.tools.items():
            if tool.status == ToolStatus.REGISTERED:
                if category is None or tool.category == category:
                    available_tools.append(tool_id)
        
        return available_tools
    
    def assign_tool(self, tool_id: str, agent_id: str) -> bool:
        """
        Assign a BlackArch tool to an agent.
        
        Args:
            tool_id: ID of the tool to assign
            agent_id: ID of the agent to assign the tool to
            
        Returns:
            True if assignment successful, False otherwise
        """
        if tool_id not in self.tools:
            logger.error(f"Tool {tool_id} not found")
            return False
        
        tool = self.tools[tool_id]
        if tool.status != ToolStatus.REGISTERED:
            logger.error(f"Tool {tool_id} is not available for assignment (status: {tool.status.value})")
            return False
        
        # Update tool
        tool.assigned_to = agent_id
        tool.update_status(ToolStatus.ASSIGNED)
        
        # Update agent assignments
        if agent_id not in self.agent_assignments:
            self.agent_assignments[agent_id] = []
        self.agent_assignments[agent_id].append(tool_id)
        
        logger.info(f"Assigned tool {tool_id} to agent {agent_id}")
        return True
    
    def execute_tool(self, tool_id: str, target: Optional[str] = None, 
                    options: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
        """
        Execute a BlackArch tool on a target.
        
        Args:
            tool_id: ID of the tool to execute
            target: Target for the tool (IP, URL, etc.)
            options: Additional command line options
            timeout: Execution timeout in seconds
            
        Returns:
            Dictionary containing execution results
        """
        if tool_id not in self.tools:
            logger.error(f"Tool {tool_id} not found")
            return {
                "success": False,
                "error": f"Tool {tool_id} not found",
                "tool_id": tool_id
            }
        
        tool = self.tools[tool_id]
        if tool.status != ToolStatus.ASSIGNED:
            logger.error(f"Tool {tool_id} must be assigned before execution (status: {tool.status.value})")
            return {
                "success": False,
                "error": f"Tool {tool_id} is not assigned",
                "tool_id": tool_id
            }
        
        try:
            # Update tool status to running
            tool.update_status(ToolStatus.RUNNING)
            
            # Build command
            command = self._build_command(tool, target, options)
            
            # Execute the tool
            stdout, stderr, returncode = self._execute_command(command, timeout)
            
            # Create execution record
            execution_record = {
                "command": command,
                "target": target,
                "options": options,
                "returncode": returncode,
                "stdout": stdout,
                "stderr": stderr,
                "timeout": timeout,
                "success": returncode == 0
            }
            
            tool.add_execution_record(execution_record)
            
            # Update tool status
            if returncode == 0:
                tool.update_status(ToolStatus.COMPLETED)
                logger.info(f"Tool {tool_id} executed successfully")
            else:
                tool.update_status(ToolStatus.FAILED, {"error": stderr})
                logger.error(f"Tool {tool_id} execution failed with return code {returncode}")
            
            return {
                "success": returncode == 0,
                "tool_id": tool_id,
                "command": command,
                "target": target,
                "options": options,
                "returncode": returncode,
                "stdout": stdout,
                "stderr": stderr,
                "execution_time": datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            error_msg = f"Tool {tool_id} execution timed out after {timeout} seconds"
            logger.error(error_msg)
            tool.update_status(ToolStatus.FAILED, {"error": error_msg})
            return {
                "success": False,
                "error": error_msg,
                "tool_id": tool_id
            }
        except Exception as e:
            error_msg = f"Error executing tool {tool_id}: {str(e)}"
            logger.error(error_msg)
            tool.update_status(ToolStatus.FAILED, {"error": error_msg})
            return {
                "success": False,
                "error": error_msg,
                "tool_id": tool_id
            }
    
    def _build_command(self, tool: BlackArchTool, target: Optional[str], 
                      options: Optional[str]) -> List[str]:
        """Build the command list for tool execution."""
        command = [tool.command]
        
        # Add default options
        if tool.config.get("default_options"):
            default_opts = tool.config["default_options"].split()
            command.extend(default_opts)
        
        # Add custom options
        if options:
            custom_opts = options.split()
            command.extend(custom_opts)
        
        # Add target if required
        if target and tool.config.get("requires_target", False):
            command.append(target)
        
        return command
    
    def _execute_command(self, command: List[str], timeout: int) -> Tuple[str, str, int]:
        """Execute a command and return stdout, stderr, and return code."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            raise
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            return "", str(e), 1
    
    def get_tool_status(self, tool_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the status of a BlackArch tool.
        
        Args:
            tool_id: ID of the tool
            
        Returns:
            Tool dictionary or None if not found
        """
        if tool_id not in self.tools:
            return None
        
        return self.tools[tool_id].to_dict()
    
    def get_agent_tools(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Get all tools assigned to a specific agent.
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            List of tool dictionaries assigned to the agent
        """
        if agent_id not in self.agent_assignments:
            return []
        
        agent_tools = []
        for tool_id in self.agent_assignments[agent_id]:
            tool_status = self.get_tool_status(tool_id)
            if tool_status:
                agent_tools.append(tool_status)
        
        return agent_tools
    
    def list_tools(self, status_filter: Optional[ToolStatus] = None, 
                   category_filter: Optional[ToolCategory] = None) -> List[Dict[str, Any]]:
        """
        List all tools with optional filters.
        
        Args:
            status_filter: Optional status to filter by
            category_filter: Optional category to filter by
            
        Returns:
            List of tool dictionaries
        """
        tools = []
        for tool in self.tools.values():
            if status_filter and tool.status != status_filter:
                continue
            if category_filter and tool.category != category_filter:
                continue
            tools.append(tool.to_dict())
        
        return tools
    
    def get_tool_categories(self) -> Dict[str, List[str]]:
        """
        Get tools grouped by category.
        
        Returns:
            Dictionary mapping categories to lists of tool IDs
        """
        categories = {}
        for tool_id, tool in self.tools.items():
            category = tool.category.value
            if category not in categories:
                categories[category] = []
            categories[category].append(tool_id)
        return categories
    
    def update_blackarch_tools(self) -> Dict[str, Any]:
        """
        Update BlackArch tools using pacman package manager.
        
        Returns:
            Dictionary with update results
        """
        try:
            logger.info("Starting BlackArch tools update...")
            self._update_all_tools_status(ToolStatus.UPDATING)
            
            # Run pacman update command
            command = ["pacman", "-Syu", "--noconfirm"]
            stdout, stderr, returncode = self._execute_command(command, timeout=600)  # 10 minute timeout
            
            if returncode == 0:
                logger.info("BlackArch tools updated successfully")
                self._update_all_tools_status(ToolStatus.REGISTERED)
                return {
                    "success": True,
                    "message": "BlackArch tools updated successfully",
                    "stdout": stdout,
                    "stderr": stderr
                }
            else:
                logger.error(f"BlackArch tools update failed: {stderr}")
                self._update_all_tools_status(ToolStatus.REGISTERED)
                return {
                    "success": False,
                    "message": "BlackArch tools update failed",
                    "stdout": stdout,
                    "stderr": stderr
                }
                
        except Exception as e:
            logger.error(f"Error updating BlackArch tools: {str(e)}")
            self._update_all_tools_status(ToolStatus.REGISTERED)
            return {
                "success": False,
                "message": f"Error updating BlackArch tools: {str(e)}"
            }
    
    def _update_all_tools_status(self, status: ToolStatus):
        """Update all tools to a specific status."""
        for tool in self.tools.values():
            tool.update_status(status)
    
    def search_tools(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for tools by name or description.
        
        Args:
            query: Search query
            
        Returns:
            List of matching tools
        """
        query_lower = query.lower()
        matching_tools = []
        
        for tool in self.tools.values():
            if (query_lower in tool.name.lower() or 
                query_lower in tool.description.lower()):
                matching_tools.append(tool.to_dict())
        
        return matching_tools


# Example usage and testing
if __name__ == "__main__":
    # Create BlackArch Tool Manager
    tool_manager = BlackArchToolManager()
    
    # Test tool registration
    print("=== Testing BlackArch Tool Manager ===")
    
    # List available tools
    available_tools = tool_manager.get_available_tools()
    print(f"Available tools: {len(available_tools)}")
    
    # Show tool categories
    categories = tool_manager.get_tool_categories()
    print(f"Tool categories: {list(categories.keys())}")
    
    # Test tool assignment
    if available_tools:
        tool_id = available_tools[0]
        agent_id = "test_agent"
        
        if tool_manager.assign_tool(tool_id, agent_id):
            print(f"✓ Assigned tool {tool_id} to agent {agent_id}")
            
            # Test tool execution (dry run with echo command for safety)
            tool = tool_manager.tools[tool_id]
            print(f"Tool info: {tool.name} - {tool.description}")
            
            # Show tool status
            status = tool_manager.get_tool_status(tool_id)
            print(f"Tool status: {status['status']}")
    
    # Test tool search
    search_results = tool_manager.search_tools("scan")
    print(f"Search results for 'scan': {len(search_results)} tools")
    
    print("BlackArch Tool Manager test completed successfully!")
