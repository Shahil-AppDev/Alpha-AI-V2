"""
Tool Manager for AI-driven security operations.
Provides a registry system for security tools and their execution.
"""

import logging
from typing import Dict, Callable, Any, Optional
from dataclasses import dataclass
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ToolExecutionResult:
    """Result of tool execution with metadata."""
    success: bool
    tool_name: str
    result: Any
    execution_time: float
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class ToolManager:
    """
    Manages registration and execution of security tools.
    """
    
    def __init__(self):
        """Initialize the ToolManager with an empty registry."""
        self.tools: Dict[str, Callable] = {}
        self.tool_metadata: Dict[str, Dict[str, Any]] = {}
        self.execution_history: list = []
        logger.info("ToolManager initialized")
    
    def register_tool(self, tool_name: str, tool_function: Callable, 
                     description: str = "", category: str = "general") -> None:
        """
        Register a tool in the registry.
        
        Args:
            tool_name: Name of the tool
            tool_function: Callable function to execute
            description: Description of what the tool does
            category: Category of the tool (e.g., 'recon', 'exploit', 'analysis')
        """
        if not callable(tool_function):
            raise ValueError(f"tool_function must be callable for tool '{tool_name}'")
        
        if tool_name in self.tools:
            logger.warning(f"Tool '{tool_name}' already exists. Overwriting.")
        
        self.tools[tool_name] = tool_function
        self.tool_metadata[tool_name] = {
            "description": description,
            "category": category,
            "registered_at": datetime.now().isoformat()
        }
        
        logger.info(f"Tool '{tool_name}' registered successfully in category '{category}'")
    
    def execute_tool(self, tool_name: str, *args, **kwargs) -> ToolExecutionResult:
        """
        Execute a registered tool.
        
        Args:
            tool_name: Name of the tool to execute
            *args: Positional arguments to pass to the tool
            **kwargs: Keyword arguments to pass to the tool
            
        Returns:
            ToolExecutionResult with execution details
        """
        start_time = datetime.now()
        
        if tool_name not in self.tools:
            error_msg = f"Tool '{tool_name}' not found in registry"
            logger.error(error_msg)
            return ToolExecutionResult(
                success=False,
                tool_name=tool_name,
                result=None,
                execution_time=0.0,
                error_message=error_msg
            )
        
        try:
            # Execute the tool
            tool_function = self.tools[tool_name]
            result = tool_function(*args, **kwargs)
            
            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Create execution result
            execution_result = ToolExecutionResult(
                success=True,
                tool_name=tool_name,
                result=result,
                execution_time=execution_time,
                metadata=self.tool_metadata.get(tool_name, {})
            )
            
            # Store in history
            self.execution_history.append({
                "tool_name": tool_name,
                "timestamp": start_time.isoformat(),
                "execution_time": execution_time,
                "success": True
            })
            
            logger.info(f"Tool '{tool_name}' executed successfully in {execution_time:.3f}s")
            return execution_result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            error_msg = f"Error executing tool '{tool_name}': {str(e)}"
            
            # Store failed execution in history
            self.execution_history.append({
                "tool_name": tool_name,
                "timestamp": start_time.isoformat(),
                "execution_time": execution_time,
                "success": False,
                "error": str(e)
            })
            
            logger.error(error_msg)
            return ToolExecutionResult(
                success=False,
                tool_name=tool_name,
                result=None,
                execution_time=execution_time,
                error_message=error_msg
            )
    
    def list_tools(self) -> Dict[str, Dict[str, Any]]:
        """
        List all registered tools with their metadata.
        
        Returns:
            Dictionary of tool names and their metadata
        """
        return self.tool_metadata.copy()
    
    def get_tool_categories(self) -> Dict[str, list]:
        """
        Get tools grouped by category.
        
        Returns:
            Dictionary mapping categories to lists of tool names
        """
        categories = {}
        for tool_name, metadata in self.tool_metadata.items():
            category = metadata.get("category", "general")
            if category not in categories:
                categories[category] = []
            categories[category].append(tool_name)
        return categories
    
    def get_execution_history(self, limit: int = 10) -> list:
        """
        Get recent execution history.
        
        Args:
            limit: Maximum number of history entries to return
            
        Returns:
            List of execution history entries
        """
        return self.execution_history[-limit:]


# Import OSINT, Network, Password, Analysis, Exploit, and Reverse Engineering modules
from modules.osint_module import osint_search
from modules.network_module import network_scan
from modules.password_module import password_crack
from modules.analysis_module import code_analysis
from modules.exploit_module import generate_reverse_shell_payload, adapt_exploit_template
from modules.reverse_engineering_module import analyze_binary_snippet

# Import Hacking Task Manager tools
from modules.hacking_tasks_module import HackingTaskManager, TaskType

# Import BlackArch Tool Manager
from modules.blackarch_tool_manager import BlackArchToolManager, ToolCategory


def osint_search(query: str) -> Dict[str, Any]:
    """
    Perform OSINT (Open Source Intelligence) search.
    
    Args:
        query (str): Search query for OSINT investigation
        
    Returns:
        dict: Dummy success message for OSINT search
    """
    print(f"Executing tool: osint_search with args: ({query},), kwargs: {{}}")
    return {
        "success": True,
        "message": f"OSINT search completed for query: '{query}'",
        "results_found": 42
    }


def network_scan(target_ip: str) -> Dict[str, Any]:
    """
    Perform network scanning on target IP.
    
    Args:
        target_ip (str): Target IP address to scan
        
    Returns:
        dict: Dummy success message for network scan
    """
    print(f"Executing tool: network_scan with args: ({target_ip},), kwargs: {{}}")
    return {
        "success": True,
        "message": f"Network scan completed for target: '{target_ip}'",
        "open_ports": [22, 80, 443, 8080]
    }


def password_crack(hash_value: str, wordlist_path: str) -> Dict[str, Any]:
    """
    Attempt to crack password hash.
    
    Args:
        hash_value (str): Hash value to crack
        wordlist_path (str): Path to wordlist file
        
    Returns:
        dict: Dummy success message for password cracking
    """
    print(f"Executing tool: password_crack with args: ({hash_value}, {wordlist_path}), kwargs: {{}}")
    return {
        "success": True,
        "message": f"Password cracking completed for hash: '{hash_value[:8]}...'",
        "password_found": "password123"
    }


def code_analysis(code_snippet: str) -> Dict[str, Any]:
    """
    Perform code analysis for security vulnerabilities.
    
    Args:
        code_snippet (str): Code snippet to analyze
        
    Returns:
        dict: Dummy success message for code analysis
    """
    print(f"Executing tool: code_analysis with args: ({code_snippet[:50]}...,), kwargs: {{}}")
    return {
        "success": True,
        "message": f"Code analysis completed for snippet of length: {len(code_snippet)}",
        "vulnerabilities_found": 2
    }


def create_email_tracker_task(target_email: str, tracking_type: str = "pixel", 
                              campaign_id: str = None, track_location: bool = False) -> Dict[str, Any]:
    """
    Create an email tracking task using the HackingTaskManager.
    
    Args:
        target_email (str): Target email address for tracking
        tracking_type (str): Type of tracking (pixel, link, attachment)
        campaign_id (str): Optional campaign identifier
        track_location (bool): Whether to track location data
        
    Returns:
        dict: Result of email tracker task creation
    """
    print(f"Executing tool: create_email_tracker_task with args: ({target_email}, {tracking_type}, {campaign_id}, {track_location}), kwargs: {{}}")
    
    try:
        # Create HackingTaskManager instance
        task_manager = HackingTaskManager()
        
        # Prepare configuration
        config = {
            "target_email": target_email,
            "tracking_type": tracking_type,
            "track_location": track_location
        }
        
        if campaign_id:
            config["campaign_id"] = campaign_id
        
        # Register and generate task
        task_id = task_manager.register_task(TaskType.EMAIL_TRACKING, config)
        task_manager.assign_task(task_id, "tool_agent")
        payload = task_manager.generate_payload(task_id)
        
        return {
            "success": True,
            "message": f"Email tracking task created successfully",
            "task_id": task_id,
            "payload": payload,
            "target_email": target_email,
            "tracking_type": tracking_type
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to create email tracking task: {str(e)}"
        }


def create_extractor_task(extraction_type: str, target_path: str, 
                         exfiltration_method: str = "http", encryption: bool = False) -> Dict[str, Any]:
    """
    Create a data extraction task using the HackingTaskManager.
    
    Args:
        extraction_type (str): Type of data to extract (files, credentials, system_info)
        target_path (str): Target file/directory path
        exfiltration_method (str): Method of data exfiltration (http, dns, ftp)
        encryption (bool): Whether to encrypt extracted data
        
    Returns:
        dict: Result of extractor task creation
    """
    print(f"Executing tool: create_extractor_task with args: ({extraction_type}, {target_path}, {exfiltration_method}, {encryption}), kwargs: {{}}")
    
    try:
        # Create HackingTaskManager instance
        task_manager = HackingTaskManager()
        
        # Prepare configuration
        config = {
            "extraction_type": extraction_type,
            "target_path": target_path,
            "exfiltration_method": exfiltration_method,
            "encryption": encryption
        }
        
        # Register and generate task
        task_id = task_manager.register_task(TaskType.EXTRACTOR_PAYLOAD, config)
        task_manager.assign_task(task_id, "tool_agent")
        payload = task_manager.generate_payload(task_id)
        
        return {
            "success": True,
            "message": f"Data extraction task created successfully",
            "task_id": task_id,
            "payload": payload,
            "extraction_type": extraction_type,
            "target_path": target_path
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to create extraction task: {str(e)}"
        }


def execute_hacking_task(task_id: str) -> Dict[str, Any]:
    """
    Execute a previously created hacking task.
    
    Args:
        task_id (str): ID of the task to execute
        
    Returns:
        dict: Result of task execution
    """
    print(f"Executing tool: execute_hacking_task with args: ({task_id},), kwargs: {{}}")
    
    try:
        # Create HackingTaskManager instance
        task_manager = HackingTaskManager()
        
        # Get task status
        task_status = task_manager.get_task_status(task_id)
        
        if not task_status:
            return {
                "success": False,
                "error": f"Task {task_id} not found"
            }
        
        # Simulate task execution (in real implementation, this would trigger actual execution)
        task_type = task_status.get("task_type")
        
        if task_type == "email_tracking":
            # Simulate email tracking execution
            result = {
                "success": True,
                "message": "Email tracking executed successfully",
                "task_id": task_id,
                "execution_time": "2024-01-15T10:30:00Z",
                "tracking_data": {
                    "email_opened": True,
                    "open_timestamp": "2024-01-15T10:25:00Z",
                    "ip_address": "192.168.1.100",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                }
            }
            task_manager.complete_task(task_id, result)
            
        elif task_type == "extractor_payload":
            # Simulate data extraction execution
            result = {
                "success": True,
                "message": "Data extraction executed successfully",
                "task_id": task_id,
                "execution_time": "2024-01-15T10:30:00Z",
                "extracted_data": {
                    "files_extracted": 15,
                    "total_size_mb": 42.7,
                    "exfiltration_status": "completed"
                }
            }
            task_manager.complete_task(task_id, result)
            
        else:
            return {
                "success": False,
                "error": f"Unsupported task type: {task_type}"
            }
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to execute hacking task: {str(e)}"
        }


def execute_blackarch_nmap(target: str, options: str = "-sS -sV") -> Dict[str, Any]:
    """
    Execute BlackArch nmap tool for network scanning.
    
    Args:
        target (str): Target IP address or hostname
        options (str): Nmap scanning options
        
    Returns:
        dict: Result of nmap scan
    """
    print(f"Executing tool: execute_blackarch_nmap with args: ({target}, {options}), kwargs: {{}}")
    
    try:
        # Create BlackArch Tool Manager
        tool_manager = BlackArchToolManager()
        
        # Find nmap tool
        tool_id = None
        for tid, tool in tool_manager.tools.items():
            if tool.name == "nmap":
                tool_id = tid
                break
        
        if not tool_id:
            return {
                "success": False,
                "error": "nmap tool not found in BlackArch tools"
            }
        
        # Assign and execute nmap
        tool_manager.assign_tool(tool_id, "tool_agent")
        result = tool_manager.execute_tool(tool_id, target, options)
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"Nmap scan completed for target: {target}",
                "target": target,
                "options": options,
                "scan_results": result.get("stdout", ""),
                "tool_id": tool_id
            }
        else:
            return {
                "success": False,
                "error": f"Nmap scan failed: {result.get('error', 'Unknown error')}"
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to execute nmap: {str(e)}"
        }


def execute_blackarch_nikto(target_url: str, options: str = "-h") -> Dict[str, Any]:
    """
    Execute BlackArch nikto tool for web server scanning.
    
    Args:
        target_url (str): Target URL for web scanning
        options (str): Nikto scanning options
        
    Returns:
        dict: Result of nikto scan
    """
    print(f"Executing tool: execute_blackarch_nikto with args: ({target_url}, {options}), kwargs: {{}}")
    
    try:
        # Create BlackArch Tool Manager
        tool_manager = BlackArchToolManager()
        
        # Find nikto tool
        tool_id = None
        for tid, tool in tool_manager.tools.items():
            if tool.name == "nikto":
                tool_id = tid
                break
        
        if not tool_id:
            return {
                "success": False,
                "error": "nikto tool not found in BlackArch tools"
            }
        
        # Assign and execute nikto
        tool_manager.assign_tool(tool_id, "tool_agent")
        result = tool_manager.execute_tool(tool_id, target_url, options)
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"Nikto scan completed for target: {target_url}",
                "target_url": target_url,
                "options": options,
                "scan_results": result.get("stdout", ""),
                "vulnerabilities_found": result.get("stdout", "").count("OSVDB"),
                "tool_id": tool_id
            }
        else:
            return {
                "success": False,
                "error": f"Nikto scan failed: {result.get('error', 'Unknown error')}"
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to execute nikto: {str(e)}"
        }


def execute_blackarch_sqlmap(target_url: str, options: str = "--batch") -> Dict[str, Any]:
    """
    Execute BlackArch sqlmap tool for SQL injection testing.
    
    Args:
        target_url (str): Target URL for SQL injection testing
        options (str): Sqlmap options
        
    Returns:
        dict: Result of sqlmap test
    """
    print(f"Executing tool: execute_blackarch_sqlmap with args: ({target_url}, {options}), kwargs: {{}}")
    
    try:
        # Create BlackArch Tool Manager
        tool_manager = BlackArchToolManager()
        
        # Find sqlmap tool
        tool_id = None
        for tid, tool in tool_manager.tools.items():
            if tool.name == "sqlmap":
                tool_id = tid
                break
        
        if not tool_id:
            return {
                "success": False,
                "error": "sqlmap tool not found in BlackArch tools"
            }
        
        # Assign and execute sqlmap
        tool_manager.assign_tool(tool_id, "tool_agent")
        result = tool_manager.execute_tool(tool_id, target_url, options)
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"SQLMap test completed for target: {target_url}",
                "target_url": target_url,
                "options": options,
                "test_results": result.get("stdout", ""),
                "tool_id": tool_id
            }
        else:
            return {
                "success": False,
                "error": f"SQLMap test failed: {result.get('error', 'Unknown error')}"
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to execute sqlmap: {str(e)}"
        }


def execute_blackarch_hydra(target: str, service: str, username: str, 
                           password_file: str = "/usr/share/wordlists/rockyou.txt", 
                           options: str = "") -> Dict[str, Any]:
    """
    Execute BlackArch hydra tool for password cracking.
    
    Args:
        target (str): Target IP address or hostname
        service (str): Service to attack (ssh, ftp, http, etc.)
        username (str): Username to test
        password_file (str): Path to password file
        options (str): Additional hydra options
        
    Returns:
        dict: Result of hydra attack
    """
    print(f"Executing tool: execute_blackarch_hydra with args: ({target}, {service}, {username}, {password_file}, {options}), kwargs: {{}}")
    
    try:
        # Create BlackArch Tool Manager
        tool_manager = BlackArchToolManager()
        
        # Find hydra tool
        tool_id = None
        for tid, tool in tool_manager.tools.items():
            if tool.name == "hydra":
                tool_id = tid
                break
        
        if not tool_id:
            return {
                "success": False,
                "error": "hydra tool not found in BlackArch tools"
            }
        
        # Build hydra command options
        hydra_options = f"-l {username} -P {password_file} {service}://{target}"
        if options:
            hydra_options += f" {options}"
        
        # Assign and execute hydra
        tool_manager.assign_tool(tool_id, "tool_agent")
        result = tool_manager.execute_tool(tool_id, None, hydra_options)
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"Hydra attack completed for target: {target}",
                "target": target,
                "service": service,
                "username": username,
                "password_file": password_file,
                "attack_results": result.get("stdout", ""),
                "tool_id": tool_id
            }
        else:
            return {
                "success": False,
                "error": f"Hydra attack failed: {result.get('error', 'Unknown error')}"
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to execute hydra: {str(e)}"
        }


def update_blackarch_tools() -> Dict[str, Any]:
    """
    Update all BlackArch tools using pacman.
    
    Returns:
        dict: Result of update operation
    """
    print("Executing tool: update_blackarch_tools with args: (), kwargs: {}")
    
    try:
        # Create BlackArch Tool Manager
        tool_manager = BlackArchToolManager()
        
        # Execute update
        result = tool_manager.update_blackarch_tools()
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to update BlackArch tools: {str(e)}"
        }


def list_blackarch_tools(category: Optional[str] = None) -> Dict[str, Any]:
    """
    List all available BlackArch tools, optionally filtered by category.
    
    Args:
        category (str): Optional category filter
        
    Returns:
        dict: List of available tools
    """
    print(f"Executing tool: list_blackarch_tools with args: ({category},), kwargs: {{}}")
    
    try:
        # Create BlackArch Tool Manager
        tool_manager = BlackArchToolManager()
        
        # Convert category string to enum if provided
        category_filter = None
        if category:
            try:
                category_filter = ToolCategory(category)
            except ValueError:
                return {
                    "success": False,
                    "error": f"Invalid category: {category}"
                }
        
        # Get tools
        tools = tool_manager.list_tools(category_filter=category_filter)
        
        return {
            "success": True,
            "message": f"Retrieved {len(tools)} BlackArch tools",
            "category_filter": category,
            "tool_count": len(tools),
            "tools": tools
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to list BlackArch tools: {str(e)}"
        }


# SocialOSINTAgent Tool Wrappers
def osint_add_target(name: str, email: str = None, social_profiles: str = None) -> Dict[str, Any]:
    """Add a new OSINT target for intelligence gathering."""
    try:
        # Import here to avoid circular imports
        from modules.social_osint_agent import SocialOSINTAgent
        
        agent = SocialOSINTAgent()
        
        # Parse social profiles if provided as JSON string
        profiles = {}
        if social_profiles:
            try:
                profiles = json.loads(social_profiles)
            except json.JSONDecodeError:
                profiles = {}
        
        # This is a synchronous wrapper for async function
        import asyncio
        result = asyncio.run(agent.add_target(
            name=name, 
            email=email, 
            social_profiles=profiles
        ))
        
        return {
            "success": True,
            "target_id": result,
            "message": f"OSINT target '{name}' added successfully"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def osint_collect_data(target_id: str, sources: str = None) -> Dict[str, Any]:
    """Collect OSINT data for a target from various sources."""
    try:
        from modules.social_osint_agent import SocialOSINTAgent
        
        agent = SocialOSINTAgent()
        
        # Parse sources if provided
        source_list = None
        if sources:
            try:
                source_list = json.loads(sources)
            except json.JSONDecodeError:
                source_list = sources.split(',') if sources else None
        
        import asyncio
        collected = asyncio.run(agent.collect_data(target_id, source_list))
        
        return {
            "success": True,
            "target_id": target_id,
            "data_count": len(collected),
            "sources": list(set(d.source.value for d in collected)),
            "message": f"Collected {len(collected)} data items"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def osint_analyze_target(target_id: str) -> Dict[str, Any]:
    """Analyze collected OSINT data for a target."""
    try:
        from modules.social_osint_agent import SocialOSINTAgent
        
        agent = SocialOSINTAgent()
        
        import asyncio
        analysis = asyncio.run(agent.analyze_target(target_id))
        
        return {
            "success": True,
            "target_id": target_id,
            "sentiment_score": analysis.sentiment_score,
            "threat_level": analysis.threat_level.value,
            "key_findings_count": len(analysis.key_findings),
            "recommendations_count": len(analysis.recommendations)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def osint_crack_passwords(target_id: str, password_hashes: str) -> Dict[str, Any]:
    """Attempt to crack password hashes using various tools."""
    try:
        from modules.social_osint_agent import SocialOSINTAgent
        
        agent = SocialOSINTAgent()
        
        # Parse password hashes
        hashes = json.loads(password_hashes) if password_hashes else []
        
        import asyncio
        results = asyncio.run(agent.crack_passwords(target_id, hashes))
        
        cracked_count = sum(1 for r in results if r['success'])
        
        return {
            "success": True,
            "target_id": target_id,
            "total_hashes": len(hashes),
            "cracked_count": cracked_count,
            "success_rate": f"{(cracked_count/len(hashes)*100):.1f}%" if hashes else "0%"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def osint_run_tools(target: str, tools: str = None) -> Dict[str, Any]:
    """Run OSINT tools against a target."""
    try:
        from modules.social_osint_agent import SocialOSINTAgent
        
        agent = SocialOSINTAgent()
        
        # Parse tools if provided
        tool_list = None
        if tools:
            try:
                tool_list = json.loads(tools)
            except json.JSONDecodeError:
                tool_list = tools.split(',') if tools else None
        
        import asyncio
        results = asyncio.run(agent.run_osint_tools(target, tool_list))
        
        successful_tools = [tool for tool, result in results.items() if result.get('success', False)]
        
        return {
            "success": True,
            "target": target,
            "tools_run": list(results.keys()),
            "successful_tools": successful_tools,
            "success_rate": f"{(len(successful_tools)/len(results)*100):.1f}%" if results else "0%"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def osint_generate_report(target_id: str, report_type: str = "summary") -> Dict[str, Any]:
    """Generate OSINT report for a target."""
    try:
        from modules.social_osint_agent import SocialOSINTAgent
        
        agent = SocialOSINTAgent()
        
        import asyncio
        report = asyncio.run(agent.generate_report(target_id, report_type))
        
        return {
            "success": True,
            "target_id": target_id,
            "report_type": report_type,
            "report_generated": True,
            "message": f"{report_type.title()} report generated successfully"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def osint_list_targets() -> Dict[str, Any]:
    """List all OSINT targets."""
    try:
        from modules.social_osint_agent import SocialOSINTAgent
        
        agent = SocialOSINTAgent()
        
        import asyncio
        targets = agent.list_targets()  # This is synchronous
        
        return {
            "success": True,
            "target_count": len(targets),
            "targets": targets[:5]  # Return first 5 targets to avoid too much output
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def osint_get_target_summary(target_id: str) -> Dict[str, Any]:
    """Get summary of target and collected data."""
    try:
        from modules.social_osint_agent import SocialOSINTAgent
        
        agent = SocialOSINTAgent()
        
        import asyncio
        summary = asyncio.run(agent.get_target_summary(target_id))
        
        return {
            "success": True,
            "target_id": target_id,
            "data_count": summary['data_count'],
            "sources": summary['sources'],
            "analysis_complete": summary['analysis_complete'],
            "threat_level": summary['threat_level']
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def osint_remove_target(target_id: str) -> Dict[str, Any]:
    """Remove a target and all associated data."""
    try:
        from modules.social_osint_agent import SocialOSINTAgent
        
        agent = SocialOSINTAgent()
        
        import asyncio
        result = asyncio.run(agent.remove_target(target_id))
        
        return {
            "success": result,
            "target_id": target_id,
            "message": f"Target {target_id} removed successfully" if result else f"Failed to remove target {target_id}"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def create_default_tool_manager() -> ToolManager:
    """
    Create a ToolManager instance with default security tools registered.
    
    Returns:
        ToolManager with pre-registered tools
    """
    manager = ToolManager()
    
    # Register default tools
    manager.register_tool(
        "osint_search", 
        osint_search,
        description="Perform OSINT search on given query",
        category="reconnaissance"
    )
    
    manager.register_tool(
        "network_scan",
        network_scan,
        description="Scan target IP for open ports and services",
        category="reconnaissance"
    )
    
    manager.register_tool(
        "password_crack",
        password_crack,
        description="Attempt to crack password hash using wordlist",
        category="cracking"
    )
    
    manager.register_tool(
        "file_analysis",
        file_analysis,
        description="Analyze file for malware and security threats",
        category="analysis"
    )
    
    manager.register_tool(
        "code_analysis",
        code_analysis,
        description="Analyze code for security vulnerabilities",
        category="analysis"
    )
    
    manager.register_tool(
        "generate_reverse_shell_payload",
        generate_reverse_shell_payload,
        description="Generate reverse shell payload using LLM",
        category="exploitation"
    )
    
    manager.register_tool(
        "adapt_exploit_template",
        adapt_exploit_template,
        description="Adapt exploit template with target information",
        category="exploitation"
    )
    
    manager.register_tool(
        "analyze_binary_snippet",
        analyze_binary_snippet,
        description="Analyze binary snippet using angr and LLM for vulnerability identification",
        category="analysis"
    )
    
    # Register Hacking Task Manager tools
    manager.register_tool(
        "create_email_tracker",
        create_email_tracker_task,
        description="Create an email tracking task with specified parameters",
        category="hacking_tasks"
    )
    
    manager.register_tool(
        "create_extractor",
        create_extractor_task,
        description="Create a data extraction task with specified parameters",
        category="hacking_tasks"
    )
    
    manager.register_tool(
        "execute_hacking_task",
        execute_hacking_task,
        description="Execute a previously created hacking task",
        category="hacking_tasks"
    )
    
    # Register BlackArch Tool Manager tools
    manager.register_tool(
        "execute_blackarch_nmap",
        execute_blackarch_nmap,
        description="Execute BlackArch nmap for network scanning",
        category="blackarch_tools"
    )
    
    manager.register_tool(
        "execute_blackarch_nikto",
        execute_blackarch_nikto,
        description="Execute BlackArch nikto for web server scanning",
        category="blackarch_tools"
    )
    
    manager.register_tool(
        "execute_blackarch_sqlmap",
        execute_blackarch_sqlmap,
        description="Execute BlackArch sqlmap for SQL injection testing",
        category="blackarch_tools"
    )
    
    manager.register_tool(
        "execute_blackarch_hydra",
        execute_blackarch_hydra,
        description="Execute BlackArch hydra for password cracking",
        category="blackarch_tools"
    )
    
    manager.register_tool(
        "update_blackarch_tools",
        update_blackarch_tools,
        description="Update all BlackArch tools using pacman",
        category="blackarch_tools"
    )
    
    manager.register_tool(
        "list_blackarch_tools",
        list_blackarch_tools,
        description="List all available BlackArch tools",
        category="blackarch_tools"
    )
    
    # Register SocialOSINTAgent tools
    manager.register_tool(
        "osint_add_target",
        osint_add_target,
        description="Add a new OSINT target for intelligence gathering",
        category="osint_operations"
    )
    
    manager.register_tool(
        "osint_collect_data",
        osint_collect_data,
        description="Collect OSINT data for a target from various sources",
        category="osint_operations"
    )
    
    manager.register_tool(
        "osint_analyze_target",
        osint_analyze_target,
        description="Analyze collected OSINT data for a target",
        category="osint_operations"
    )
    
    manager.register_tool(
        "osint_crack_passwords",
        osint_crack_passwords,
        description="Attempt to crack password hashes using various tools",
        category="osint_operations"
    )
    
    manager.register_tool(
        "osint_run_tools",
        osint_run_tools,
        description="Run OSINT tools against a target",
        category="osint_operations"
    )
    
    manager.register_tool(
        "osint_generate_report",
        osint_generate_report,
        description="Generate OSINT report for a target",
        category="osint_operations"
    )
    
    manager.register_tool(
        "osint_list_targets",
        osint_list_targets,
        description="List all OSINT targets",
        category="osint_operations"
    )
    
    manager.register_tool(
        "osint_get_target_summary",
        osint_get_target_summary,
        description="Get summary of target and collected data",
        category="osint_operations"
    )
    
    manager.register_tool(
        "osint_remove_target",
        osint_remove_target,
        description="Remove a target and all associated data",
        category="osint_operations"
    )
    
    return manager


# Example usage and testing
if __name__ == "__main__":
    # Create and test the ToolManager
    tool_manager = create_default_tool_manager()
    
    print("=== ToolManager Test ===")
    print(f"Registered tools: {list(tool_manager.tools.keys())}")
    print(f"Tool categories: {tool_manager.get_tool_categories()}")
    print()
    
    # Test each tool
    test_cases = [
        ("osint_search", "example.com"),
        ("network_scan", "192.168.1.1"),
        ("password_crack", "5f4dcc3b5aa765d61d8327deb882cf99", "/path/to/wordlist.txt"),
        ("file_analysis", "/path/to/suspicious.exe"),
        ("code_analysis", "def vulnerable_function():\n    pass")
    ]
    
    for tool_name, *args in test_cases:
        print(f"--- Testing {tool_name} ---")
        result = tool_manager.execute_tool(tool_name, *args)
        print(f"Success: {result.success}")
        print(f"Execution time: {result.execution_time:.3f}s")
        if result.success:
            print(f"Result: {result.result}")
        else:
            print(f"Error: {result.error_message}")
        print()
    
    # Test error case
    print("--- Testing invalid tool ---")
    error_result = tool_manager.execute_tool("nonexistent_tool", "test")
    print(f"Success: {error_result.success}")
    print(f"Error: {error_result.error_message}")
    print()
    
    # Show execution history
    print("=== Execution History ===")
    for entry in tool_manager.get_execution_history():
        print(f"{entry['timestamp']}: {entry['tool_name']} - {entry['execution_time']:.3f}s - {'SUCCESS' if entry['success'] else 'FAILED'}")
