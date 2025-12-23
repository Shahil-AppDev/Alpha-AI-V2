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


# Initialize ToolManager with default tools
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
