"""
Base Agent and LLM Autonomous Agent implementations for AI-driven security tools.
"""

import os
import json
import logging
import re
import uuid
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

import openai
from openai import OpenAI
import requests
from dotenv import load_dotenv

# Import ToolManager
from tool_manager import ToolManager, ToolExecutionResult

# Import HackingTaskManager
from modules.hacking_tasks_module import HackingTaskManager, TaskType, TaskStatus
from modules.hacking_task_classes import HackingTaskFactory

# Import BlackArch Tool Manager
from modules.blackarch_tool_manager import BlackArchToolManager, ToolCategory, ToolStatus as BlackArchToolStatus

# Import SocialOSINTAgent
from modules.social_osint_agent import SocialOSINTAgent

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    """Configuration for LLM client."""
    api_endpoint: str
    api_key: str
    model: str = "gpt-3.5-turbo"
    max_tokens: int = 2000
    temperature: float = 0.7
    timeout: int = 30
    max_tool_calls: int = 5  # Maximum number of tool calls per task
    require_human_approval: bool = True  # Enable human approval for critical actions


@dataclass
class CriticalAction:
    """Represents a critical action requiring human approval."""
    action_type: str
    description: str
    tool_name: str
    parameters: Dict[str, Any]
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL


class BaseAgent(ABC):
    """
    Base class for AI agents that interact with LLM services.
    """
    
    def __init__(self, llm_client=None, config: Optional[LLMConfig] = None):
        """
        Initialize the base agent with LLM client configuration.
        
        Args:
            llm_client: LLM client instance (OpenAI, custom HTTP client, etc.)
            config: LLM configuration object
        """
        self.llm_client = llm_client
        self.config = config or self._get_default_config()
        self._validate_config()
        
    def _get_default_config(self) -> LLMConfig:
        """Get default configuration from environment variables."""
        return LLMConfig(
            api_endpoint=os.getenv("LLM_API_URL", os.getenv("LLM_API_ENDPOINT", "http://localhost:8000")),
            api_key=os.getenv("LLM_API_KEY", "dummy-key"),
            model=os.getenv("LLM_MODEL", "gpt-3.5-turbo"),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "2000")),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.7")),
            timeout=int(os.getenv("LLM_TIMEOUT", "30"))
        )
    
    def _validate_config(self):
        """Validate the LLM configuration."""
        if not self.config.api_endpoint:
            raise ValueError("LLM API endpoint is required")
        if not self.config.api_key:
            raise ValueError("LLM API key is required")
    
    @abstractmethod
    def execute_task(self, task_description: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute a task using the LLM.
        
        Args:
            task_description: Description of the task to execute
            context: Additional context information for the task
            
        Returns:
            Dictionary containing the LLM response and metadata
        """
        pass
    
    def _prepare_prompt(self, task_description: str, context: Dict[str, Any] = None) -> str:
        """
        Prepare the prompt for the LLM with task description, context, memory, and tool instructions.
        
        Args:
            task_description: Description of the task
            context: Additional context information
            
        Returns:
            Formatted prompt string with memory and tool calling instructions
        """
        prompt = f"Task: {task_description}\n\n"
        
        # Add relevant memory to provide context
        relevant_memory = self.get_relevant_memory(task_description)
        if relevant_memory:
            prompt += "Relevant Previous Experience:\n"
            for i, memory_entry in enumerate(relevant_memory[-5:], 1):  # Show last 5 relevant entries
                prompt += f"{i}. [{memory_entry['type'].upper()}] {memory_entry['content'][:200]}...\n"
            prompt += "\n"
        
        if context:
            prompt += "Context:\n"
            for key, value in context.items():
                prompt += f"- {key}: {json.dumps(value, indent=2)}\n"
            prompt += "\n"
        
        # Add tool calling instructions if ToolManager is available
        if self.tool_manager:
            available_tools = list(self.tool_manager.tools.keys())
            prompt += f"Available tools: {', '.join(available_tools)}\n\n"
            prompt += "If you need to use a tool, format your response exactly as follows:\n"
            prompt += "ACTION: TOOL_CALL\n"
            prompt += "TOOL_NAME: <tool_name>\n"
            prompt += "ARGUMENTS: {\"arg1\": \"value1\", \"arg2\": \"value2\"}\n\n"
            prompt += "After providing the tool call, I will execute it and return the results for your analysis.\n\n"
        
        prompt += "Please provide a detailed response to complete this task."
        return prompt


class LLMAutonomousAgent(BaseAgent):
    """
    Concrete implementation of BaseAgent using OpenAI library with ToolManager integration.
    Enhanced with memory and planning capabilities.
    """
    
    def __init__(self, config: Optional[LLMConfig] = None, tool_manager: Optional[ToolManager] = None, 
                 hacking_task_manager: Optional[HackingTaskManager] = None, 
                 blackarch_tool_manager: Optional[BlackArchToolManager] = None,
                 social_osint_agent: Optional[SocialOSINTAgent] = None):
        """
        Initialize the LLM Autonomous Agent.
        
        Args:
            config: LLM configuration object
            tool_manager: ToolManager instance for tool execution
            hacking_task_manager: HackingTaskManager instance for advanced hacking tasks
            blackarch_tool_manager: BlackArchToolManager instance for BlackArch Linux tools
            social_osint_agent: SocialOSINTAgent instance for OSINT operations
        """
        super().__init__(config=config)
        self.llm_client = self._initialize_client()
        self.tool_manager = tool_manager
        self.hacking_task_manager = hacking_task_manager or HackingTaskManager()
        self.hacking_task_factory = HackingTaskFactory(self.hacking_task_manager)
        self.blackarch_tool_manager = blackarch_tool_manager or BlackArchToolManager()
        self.social_osint_agent = social_osint_agent or SocialOSINTAgent()
        self.agent_id = f"agent_{uuid.uuid4().hex[:8]}"
        self.tool_call_history: List[Dict[str, Any]] = []
        
        # Memory system for storing conversation history and observations
        self.memory: List[Dict[str, Any]] = []
        self.max_memory_size = 100  # Maximum number of memory entries to keep
        
        # Planning system
        self.current_plan: Optional[List[Dict[str, Any]]] = None
        self.plan_step_index: int = 0
        
        # Human approval system
        self.critical_actions_history: List[Dict[str, Any]] = []
        self.pending_approval: Optional[CriticalAction] = None
        
        # Define critical action patterns
        self.critical_action_patterns = {
            'exploit': ['generate_reverse_shell_payload', 'adapt_exploit_template'],
            'password_cracking': ['password_crack'],
            'binary_analysis': ['analyze_binary_snippet'],
            'network_exploitation': ['network_scan'],  # Considered critical when targeting live systems
            'destructive': ['file_delete', 'system_modify'],  # Future tools
            'hacking_tasks': ['create_email_tracker', 'create_extractor', 'execute_hacking_task'],
            'blackarch_tools': ['execute_blackarch_tool', 'assign_blackarch_tool', 'update_blackarch_tools'],
            'osint_operations': ['osint_collect_data', 'osint_analyze_target', 'osint_crack_passwords', 'osint_run_tools']
        }
        
        if self.tool_manager:
            logger.info(f"LLMAutonomousAgent initialized with ToolManager containing {len(self.tool_manager.tools)} tools")
        else:
            logger.warning("LLMAutonomousAgent initialized without ToolManager - tool calling disabled")
        
        if self.hacking_task_manager:
            logger.info(f"LLMAutonomousAgent initialized with HackingTaskManager")
        
        if self.blackarch_tool_manager:
            logger.info(f"LLMAutonomousAgent initialized with BlackArchToolManager containing {len(self.blackarch_tool_manager.tools)} tools")
        
        logger.info(f"LLMAutonomousAgent {self.agent_id} initialized with memory and planning capabilities")
        
    def _identify_critical_action(self, tool_name: str, parameters: Dict[str, Any]) -> Optional[CriticalAction]:
        """
        Identify if a tool execution requires human approval.
        
        Args:
            tool_name: Name of the tool to be executed
            parameters: Parameters for the tool execution
            
        Returns:
            CriticalAction object if approval is required, None otherwise
        """
        if not self.config.require_human_approval:
            return None
            
        # Check if tool is in critical patterns
        for action_type, critical_tools in self.critical_action_patterns.items():
            if tool_name in critical_tools:
                # Determine risk level based on tool and parameters
                risk_level = self._assess_risk_level(tool_name, parameters)
                
                description = f"Execute {tool_name} with parameters: {parameters}"
                
                return CriticalAction(
                    action_type=action_type,
                    description=description,
                    tool_name=tool_name,
                    parameters=parameters,
                    risk_level=risk_level
                )
        
        return None
    
    def _assess_risk_level(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """
        Assess the risk level of a critical action.
        
        Args:
            tool_name: Name of the tool
            parameters: Tool parameters
            
        Returns:
            Risk level: LOW, MEDIUM, HIGH, or CRITICAL
        """
        if tool_name in ['generate_reverse_shell_payload', 'adapt_exploit_template']:
            return 'CRITICAL'
        elif tool_name == 'password_crack':
            return 'HIGH'
        elif tool_name == 'analyze_binary_snippet':
            return 'MEDIUM'
        elif tool_name == 'network_scan':
            # Check if targeting live external systems
            if 'target_ip' in parameters:
                ip = parameters['target_ip']
                if not (ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.')):
                    return 'HIGH'
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _request_human_approval(self, critical_action: CriticalAction) -> bool:
        """
        Request human approval for a critical action.
        
        Args:
            critical_action: The critical action requiring approval
            
        Returns:
            True if approved, False if denied
        """
        print("\n" + "="*60)
        print("🚨 CRITICAL ACTION REQUIRING HUMAN APPROVAL")
        print("="*60)
        print(f"Action Type: {critical_action.action_type.upper()}")
        print(f"Risk Level: {critical_action.risk_level}")
        print(f"Tool: {critical_action.tool_name}")
        print(f"Description: {critical_action.description}")
        print("\n⚠️  This action may have security implications.")
        print("⚠️  Please review carefully before proceeding.")
        print("="*60)
        
        # Store pending approval
        self.pending_approval = critical_action
        
        # Get user input
        while True:
            response = input("\nDo you approve this action? (yes/confirm/no/deny): ").strip().lower()
            
            if response in ['yes', 'confirm', 'y', 'approve']:
                print("✅ Action APPROVED by human operator.")
                self._log_approval_decision(critical_action, approved=True)
                self.pending_approval = None
                return True
            elif response in ['no', 'deny', 'n', 'reject']:
                print("❌ Action DENIED by human operator.")
                self._log_approval_decision(critical_action, approved=False)
                self.pending_approval = None
                return False
            else:
                print("Invalid response. Please enter 'yes/confirm' or 'no/deny'.")
    
    def _log_approval_decision(self, critical_action: CriticalAction, approved: bool) -> None:
        """
        Log the approval decision to memory and history.
        
        Args:
            critical_action: The action that was approved/denied
            approved: Whether the action was approved
        """
        # Add to memory
        self.add_to_memory({
            "type": "human_approval",
            "content": f"Human {'approved' if approved else 'denied'} critical action: {critical_action.description}",
            "metadata": {
                "action_type": critical_action.action_type,
                "tool_name": critical_action.tool_name,
                "risk_level": critical_action.risk_level,
                "approved": approved,
                "timestamp": self._get_timestamp()
            }
        })
        
        # Add to critical actions history
        self.critical_actions_history.append({
            "action": critical_action,
            "approved": approved,
            "timestamp": self._get_timestamp()
        })
        
        logger.info(f"Critical action {critical_action.tool_name} {'approved' if approved else 'denied'} by human operator")
    
    def _generate_alternative_approach(self, denied_action: CriticalAction) -> str:
        """
        Generate an alternative approach when a critical action is denied.
        
        Args:
            denied_action: The action that was denied
            
        Returns:
            Alternative approach suggestion
        """
        alternatives = {
            'exploit': "Instead of executing exploits, consider:\n"
                     "- Performing passive reconnaissance\n"
                     "- Analyzing system configurations\n"
                     "- Reviewing security policies and documentation\n"
                     "- Using non-invasive vulnerability scanners",
                     
            'password_cracking': "Instead of password cracking, consider:\n"
                               "- Reviewing password policies\n"
                               "- Analyzing password strength requirements\n"
                               "- Implementing multi-factor authentication\n"
                               "- Educating users on secure password practices",
                               
            'binary_analysis': "For safer binary analysis:\n"
                             "- Use static analysis tools only\n"
                             "- Analyze in isolated sandbox environment\n"
                             "- Review source code if available\n"
                             "- Use automated vulnerability scanners",
                             
            'network_exploitation': "Instead of active network exploitation:\n"
                                   "- Perform passive network monitoring\n"
                                   "- Analyze network configurations\n"
                                   "- Review firewall rules and policies\n"
                                   "- Use network mapping tools without active scanning"
        }
        
        return alternatives.get(denied_action.action_type, 
                              "Consider using less invasive analysis methods and consult with security team before proceeding.")
        
    def _initialize_client(self) -> OpenAI:
        """
        Initialize the OpenAI client with configuration.
        
        Returns:
            Configured OpenAI client
        """
        try:
            # Check if using custom endpoint (like our mock service)
            if "localhost" in self.config.api_endpoint or not self.config.api_endpoint.startswith("https://api.openai.com"):
                # For custom endpoints, we'll use HTTP requests instead of OpenAI client
                logger.info(f"Using custom LLM endpoint: {self.config.api_endpoint}")
                return None
            
            # For OpenAI API
            client = OpenAI(
                api_key=self.config.api_key,
                base_url=self.config.api_endpoint if self.config.api_endpoint != "https://api.openai.com/v1" else None,
                timeout=self.config.timeout
            )
            logger.info("OpenAI client initialized successfully")
            return client
            
        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}")
            raise
    
    def add_to_memory(self, entry: Dict[str, Any]) -> None:
        """
        Add an entry to the agent's memory.
        
        Args:
            entry: Memory entry containing type, content, and metadata
        """
        memory_entry = {
            "timestamp": self._get_timestamp(),
            "type": entry.get("type", "observation"),
            "content": entry.get("content", ""),
            "metadata": entry.get("metadata", {})
        }
        
        self.memory.append(memory_entry)
        
        # Maintain memory size limit
        if len(self.memory) > self.max_memory_size:
            self.memory = self.memory[-self.max_memory_size:]
        
        logger.debug(f"Added to memory: {memory_entry['type']} - {memory_entry['content'][:100]}...")
    
    def get_relevant_memory(self, task_description: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get relevant memory entries based on task description.
        
        Args:
            task_description: Current task to find relevant memory for
            limit: Maximum number of memory entries to return
            
        Returns:
            List of relevant memory entries
        """
        # Simple relevance: return most recent entries
        # In a more sophisticated implementation, this could use semantic similarity
        recent_memory = self.memory[-limit:] if len(self.memory) > limit else self.memory
        
        # Filter for entries that might be relevant to security tasks
        relevant_keywords = ["vulnerability", "scan", "analysis", "exploit", "target", "security", "password", "hash", "network", "osint"]
        
        filtered_memory = []
        for entry in recent_memory:
            content_lower = entry["content"].lower()
            if any(keyword in content_lower for keyword in relevant_keywords):
                filtered_memory.append(entry)
        
        # If no filtered results, return recent memory
        return filtered_memory if filtered_memory else recent_memory
    
    
    def execute_task(self, task_description: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute a security analysis task using the LLM with tool call support.
        
        Args:
            task_description (str): Description of the task to execute
            context (dict, optional): Additional context information for the task
            
        Returns:
            dict: The LLM's response with tool execution results if applicable
        """
        try:
            # Format the prompt with task description and context
            prompt = self._format_prompt(task_description, context)
            
            # Store in memory
            self._add_to_memory("user", task_description, context)
            
            # Send request to LLM API
            response = self._send_to_llm(prompt)
            
            # Parse LLM response to detect tool calls
            parsed_response = self._parse_response(response)
            
            # Check if LLM is requesting a tool call
            tool_call = self._detect_tool_call(parsed_response)
            
            if tool_call:
                # Execute the requested tool
                tool_result = self._execute_tool_call(tool_call)
                
                # Send tool result back to LLM for final response
                final_response = self._send_tool_result_to_llm(task_description, tool_call, tool_result)
                
                # Parse final response
                final_parsed = self._parse_response(final_response)
                
                # Store tool call and result in memory
                self._add_to_memory("tool_call", f"Executed {tool_call['tool_name']}", tool_call)
                self._add_to_memory("tool_result", f"Tool result: {tool_result}", tool_result)
                self._add_to_memory("assistant", final_parsed.get("result", ""), None)
                
                # Add tool call to history
                self.tool_call_history.append({
                    "tool_name": tool_call["tool_name"],
                    "arguments": tool_call["arguments"],
                    "result": tool_result,
                    "timestamp": datetime.now().isoformat()
                })
                
                return {
                    "success": True,
                    "result": final_parsed.get("result", ""),
                    "tool_call": tool_call,
                    "tool_result": tool_result,
                    "action": final_parsed.get("action", None)
                }
            else:
                # No tool call detected, return direct LLM response
                self._add_to_memory("assistant", parsed_response.get("result", ""), None)
                
                return {
                    "success": True,
                    "result": parsed_response.get("result", ""),
                    "action": parsed_response.get("action", None)
                }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return {
                "error": f"API request failed: {str(e)}",
                "result": None,
                "action": None
            }
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            return {
                "error": f"JSON parsing failed: {str(e)}",
                "result": response.text if hasattr(response, 'text') else str(response),
                "action": None
            }
        except Exception as e:
            logger.error(f"Unexpected error during task execution: {e}")
            return {
                "error": f"Unexpected error: {str(e)}",
                "result": None,
                "action": None
            }
    
    def _detect_tool_call(self, response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect if the LLM response contains a tool call request.
        
        Args:
            response: Parsed LLM response
            
        Returns:
            dict with tool_name and arguments if tool call detected, None otherwise
        """
        result_text = response.get("result", "")
        
        # Check for tool call format: ACTION: TOOL_CALL\nTOOL_NAME: tool_name\nARGUMENTS: {"arg": "value"}
        if "ACTION: TOOL_CALL" in result_text:
            lines = result_text.split('\n')
            tool_call = {}
            
            for line in lines:
                if line.strip().startswith("TOOL_NAME:"):
                    tool_call["tool_name"] = line.split("TOOL_NAME:", 1)[1].strip()
                elif line.strip().startswith("ARGUMENTS:"):
                    args_str = line.split("ARGUMENTS:", 1)[1].strip()
                    try:
                        tool_call["arguments"] = json.loads(args_str)
                    except json.JSONDecodeError:
                        tool_call["arguments"] = {"raw_args": args_str}
            
            if "tool_name" in tool_call:
                return tool_call
        
        return None
    
    def _execute_tool_call(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool call using the tool_manager.
        
        Args:
            tool_call: Dictionary containing tool_name and arguments
            
        Returns:
            Tool execution result
        """
        if not self.tool_manager:
            return {
                "success": False,
                "error": "No tool manager available"
            }
        
        tool_name = tool_call["tool_name"]
        arguments = tool_call.get("arguments", {})
        
        # Convert arguments dict to *args and **kwargs
        args = []
        kwargs = {}
        
        if isinstance(arguments, dict):
            kwargs = arguments
        else:
            args = [arguments]
        
        try:
            result = self.tool_manager.execute_tool(tool_name, *args, **kwargs)
            return result
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _send_tool_result_to_llm(self, original_task: str, tool_call: Dict[str, Any], tool_result: Dict[str, Any]) -> requests.Response:
        """
        Send the tool execution result back to the LLM for final processing.
        
        Args:
            original_task: Original task description
            tool_call: The tool call that was executed
            tool_result: Result from tool execution
            
        Returns:
            LLM response to the tool result
        """
        follow_up_prompt = f"""Original task: {original_task}

I executed the following tool:
Tool: {tool_call['tool_name']}
Arguments: {tool_call.get('arguments', {})}

Tool execution result:
{json.dumps(tool_result, indent=2)}

Please analyze this tool result and provide a comprehensive response to complete the original task. 
Focus on what the tool result means for the security analysis and what actions should be taken next.

Respond with a JSON format:
{{
    "result": "Your analysis and recommendations based on the tool result",
    "action": "Recommended next steps (optional)",
    "confidence": "High/Medium/Low confidence level"
}}
"""
        
        return self._send_to_llm(follow_up_prompt)
        """
        Detect if the LLM response contains a tool call request.
        
        Args:
            response: Parsed LLM response
            
        Returns:
            dict with tool_name and arguments if tool call detected, None otherwise
        """
        result_text = response.get("result", "")
        
        # Check for tool call format: ACTION: TOOL_CALL\nTOOL_NAME: tool_name\nARGUMENTS: {"arg": "value"}
        if "ACTION: TOOL_CALL" in result_text:
            lines = result_text.split('\n')
            tool_call = {}
            
            for line in lines:
                if line.strip().startswith("TOOL_NAME:"):
                    tool_call["tool_name"] = line.split("TOOL_NAME:", 1)[1].strip()
                elif line.strip().startswith("ARGUMENTS:"):
                    args_str = line.split("ARGUMENTS:", 1)[1].strip()
                    try:
                        tool_call["arguments"] = json.loads(args_str)
                    except json.JSONDecodeError:
                        tool_call["arguments"] = {"raw_args": args_str}
            
            if "tool_name" in tool_call:
                return tool_call
        
        return None
    
    def _execute_tool_call(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool call using the tool_manager.
        
        Args:
            tool_call: Dictionary containing tool_name and arguments
            
        Returns:
            Tool execution result
        """
        if not self.tool_manager:
            return {
                "success": False,
                "error": "No tool manager available"
            }
        
        tool_name = tool_call["tool_name"]
        arguments = tool_call.get("arguments", {})
        
        # Convert arguments dict to *args and **kwargs
        args = []
        kwargs = {}
        
        if isinstance(arguments, dict):
            kwargs = arguments
        else:
            args = [arguments]
        
        try:
            result = self.tool_manager.execute_tool(tool_name, *args, **kwargs)
            return result
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _send_tool_result_to_llm(self, original_task: str, tool_call: Dict[str, Any], tool_result: Dict[str, Any]) -> requests.Response:
        """
        Send the tool execution result back to the LLM for final processing.
        
        Args:
            original_task: Original task description
            tool_call: The tool call that was executed
            tool_result: Result from tool execution
            
        Returns:
            LLM response to the tool result
        """
        follow_up_prompt = f"""Original task: {original_task}

I executed the following tool:
Tool: {tool_call['tool_name']}
Arguments: {tool_call.get('arguments', {})}

Tool execution result:
{json.dumps(tool_result, indent=2)}

Please analyze this tool result and provide a comprehensive response to complete the original task. 
Focus on what the tool result means for the security analysis and what actions should be taken next.

Respond with a JSON format:
{{
    "result": "Your analysis and recommendations based on the tool result",
    "action": "Recommended next steps (optional)",
    "confidence": "High/Medium/Low confidence level"
}}
"""
        
        return self._send_to_llm(follow_up_prompt)
    
    def _generate_plan(self, objective: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate a step-by-step plan to accomplish the objective.
        
        Args:
            objective: High-level objective
            context: Additional context information
            
        Returns:
            Dictionary containing the generated plan
        """
        planning_prompt = f"""
You are an AI security expert. Break down the following high-level objective into a sequence of specific, actionable steps:

Objective: {objective}

Available tools: {', '.join(self.tool_manager.tools.keys()) if self.tool_manager else 'No tools available'}

Create a detailed plan with 3-7 steps. Each step should:
1. Be specific and actionable
2. Have a clear description of what needs to be done
3. Be achievable with the available tools
4. Follow a logical sequence for security analysis

Format your response as follows:
PLAN:
1. [Step Description]
   Type: [analysis/reconnaissance/exploitation/reporting]
   
2. [Step Description]
   Type: [analysis/reconnaissance/exploitation/reporting]
   
[Continue for all steps]

Example:
PLAN:
1. Perform OSINT reconnaissance on target.com
   Type: reconnaissance
   
2. Scan the target for open ports and services
   Type: reconnaissance
   
3. Analyze the web application for vulnerabilities
   Type: analysis
   
4. Attempt to exploit identified vulnerabilities
   Type: exploitation
   
5. Generate a comprehensive security report
   Type: reporting
"""
        
        # Add context if provided
        if context:
            planning_prompt += f"\n\nAdditional Context:\n"
            for key, value in context.items():
                planning_prompt += f"- {key}: {json.dumps(value, indent=2)}\n"
        
        # Add relevant memory
        relevant_memory = self.get_relevant_memory(objective, limit=5)
        if relevant_memory:
            planning_prompt += "\n\nRelevant Previous Experience:\n"
            for i, memory_entry in enumerate(relevant_memory, 1):
                planning_prompt += f"{i}. [{memory_entry['type'].upper()}] {memory_entry['content'][:150]}...\n"
        
        try:
            if self.llm_client is None:
                llm_response = self._execute_with_custom_endpoint(planning_prompt)
            else:
                llm_response = self._execute_with_openai(planning_prompt)
            
            if not llm_response["success"]:
                return {"success": False, "error": llm_response.get("error", "Failed to generate plan")}
            
            response_text = llm_response["response"]
            
            # Parse the plan from the response
            plan = self._parse_plan_from_response(response_text)
            
            if not plan:
                return {"success": False, "error": "Failed to parse plan from LLM response"}
            
            return {"success": True, "plan": plan}
            
        except Exception as e:
            logger.error(f"Error generating plan: {e}")
            return {"success": False, "error": str(e)}
    
    def _parse_plan_from_response(self, response_text: str) -> List[Dict[str, Any]]:
        """
        Parse the plan from the LLM response.
        
        Args:
            response_text: The LLM response containing the plan
            
        Returns:
            List of plan steps
        """
        plan_steps = []
        
        # Look for the PLAN: section
        if "PLAN:" in response_text:
            plan_section = response_text.split("PLAN:")[1].strip()
        else:
            # If no PLAN: section, try to parse the whole response
            plan_section = response_text.strip()
        
        # Parse numbered steps
        lines = plan_section.split('\n')
        current_step = None
        
        for line in lines:
            line = line.strip()
            
            # Match numbered steps (e.g., "1. Step description")
            if re.match(r'^\d+\.\s+', line):
                if current_step:
                    plan_steps.append(current_step)
                
                step_text = re.sub(r'^\d+\.\s+', '', line)
                current_step = {
                    "description": step_text,
                    "type": "analysis"  # Default type
                }
            
            # Match type specification
            elif line.startswith("Type:"):
                if current_step:
                    current_step["type"] = line.replace("Type:", "").strip()
        
        # Add the last step
        if current_step:
            plan_steps.append(current_step)
        
        return plan_steps
    
    def _should_continue_after_failure(self, failed_step: Dict[str, Any], remaining_steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Ask the LLM whether to continue execution after a step failure.
        
        Args:
            failed_step: The failed step result
            remaining_steps: Remaining steps in the plan
            
        Returns:
            Dictionary with decision to continue or stop
        """
        decision_prompt = f"""
A step in our security analysis plan has failed:

Failed Step: {failed_step.get('step_description', 'Unknown')}
Error: {failed_step.get('error', 'Unknown error')}

Remaining Steps:
{chr(10).join([f"{i+1}. {step['description']}" for i, step in enumerate(remaining_steps)])}

Should we continue with the remaining steps or stop the execution? 
Consider:
1. Is the failure critical to the overall objective?
2. Can we still achieve meaningful results with the remaining steps?
3. Are there alternative approaches we should take?

Respond with either:
CONTINUE: [reason for continuing]
STOP: [reason for stopping]
"""
        
        try:
            if self.llm_client is None:
                llm_response = self._execute_with_custom_endpoint(decision_prompt)
            else:
                llm_response = self._execute_with_openai(decision_prompt)
            
            if not llm_response["success"]:
                return {"continue": False, "reason": "Failed to get LLM decision"}
            
            response_text = llm_response["response"].strip().upper()
            
            if response_text.startswith("CONTINUE:"):
                return {"continue": True, "reason": response_text[9:].strip()}
            else:
                return {"continue": False, "reason": response_text[5:].strip()}
                
        except Exception as e:
            logger.error(f"Error getting continue decision: {e}")
            return {"continue": False, "reason": f"Error: {str(e)}"}
    
    def _refine_plan_based_on_results(self, objective: str, remaining_steps: List[Dict[str, Any]], last_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ask the LLM to refine the remaining plan based on execution results.
        
        Args:
            objective: The overall objective
            remaining_steps: Current remaining steps
            last_result: Result of the last executed step
            
        Returns:
            Dictionary with refined plan
        """
        refinement_prompt = f"""
Based on the results of our last step, please review and potentially refine our remaining plan:

Objective: {objective}

Last Step Result: {last_result.get('response', 'No response')[:300]}...
Success: {last_result.get('success', False)}

Current Remaining Steps:
{chr(10).join([f"{i+1}. {step['description']} ({step['type']})" for i, step in enumerate(remaining_steps)])}

Please review the remaining steps and provide either:
1. SAME: Keep the current plan as is
2. MODIFIED: [provide modified steps]

Consider:
- Do we need to adjust our approach based on the results?
- Are any remaining steps no longer necessary?
- Should we add new steps based on what we've learned?
- Should we modify the order or content of existing steps?
"""
        
        try:
            if self.llm_client is None:
                llm_response = self._execute_with_custom_endpoint(refinement_prompt)
            else:
                llm_response = self._execute_with_openai(refinement_prompt)
            
            if not llm_response["success"]:
                return {"success": True, "modified": False, "remaining_steps": remaining_steps}
            
            response_text = llm_response["response"].strip()
            
            if response_text.startswith("SAME:"):
                return {"success": True, "modified": False, "remaining_steps": remaining_steps}
            elif response_text.startswith("MODIFIED:"):
                modified_text = response_text[9:].strip()
                modified_steps = self._parse_plan_from_response(modified_text)
                
                if modified_steps:
                    return {"success": True, "modified": True, "remaining_steps": modified_steps}
                else:
                    logger.warning("Failed to parse modified plan, keeping original")
                    return {"success": True, "modified": False, "remaining_steps": remaining_steps}
            else:
                # Default to keeping original plan
                return {"success": True, "modified": False, "remaining_steps": remaining_steps}
                
        except Exception as e:
            logger.error(f"Error refining plan: {e}")
            return {"success": True, "modified": False, "remaining_steps": remaining_steps}
    
    def _generate_execution_summary(self, objective: str, execution_results: List[Dict[str, Any]]) -> str:
        """
        Generate a final summary of the plan execution.
        
        Args:
            objective: The original objective
            execution_results: Results from all executed steps
            
        Returns:
            Generated summary string
        """
        summary_prompt = f"""
Generate a comprehensive summary of our security analysis execution:

Objective: {objective}

Execution Results:
{chr(10).join([f"Step {i+1}: {result.get('step_description', 'Unknown')} - {'SUCCESS' if result.get('success') else 'FAILED'}" for i, result in enumerate(execution_results)])}

Please provide:
1. Overall assessment of the objective completion
2. Key findings and discoveries
3. Security implications and recommendations
4. Limitations or areas that need further investigation

Format as a professional security analysis summary.
"""
        
        try:
            if self.llm_client is None:
                llm_response = self._execute_with_custom_endpoint(summary_prompt)
            else:
                llm_response = self._execute_with_openai(summary_prompt)
            
            if llm_response["success"]:
                return llm_response["response"]
            else:
                return "Failed to generate execution summary."
                
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
            return f"Error generating summary: {str(e)}"
    
    def _parse_tool_call(self, response_text: str) -> Optional[Dict[str, Any]]:
        """
        Parse tool call from LLM response.
        
        Args:
            response_text: The text response from the LLM
            
        Returns:
            Dictionary with tool_name and arguments if tool call found, None otherwise
        """
        try:
            # Look for the tool call pattern
            pattern = r'ACTION:\s*TOOL_CALL\s*\nTOOL_NAME:\s*(\w+)\s*\nARGUMENTS:\s*({.*?})\s*\n'
            match = re.search(pattern, response_text, re.DOTALL | re.IGNORECASE)
            
            if match:
                tool_name = match.group(1).strip()
                arguments_str = match.group(2).strip()
                
                # Parse arguments as JSON
                try:
                    arguments = json.loads(arguments_str)
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse arguments as JSON: {arguments_str}")
                    return None
                
                logger.info(f"Parsed tool call: {tool_name} with arguments {arguments}")
                return {
                    "tool_name": tool_name,
                    "arguments": arguments
                }
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error parsing tool call: {e}")
            return None
    
    def _execute_tool_call(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool call using the ToolManager with human approval for critical actions.
        
        Args:
            tool_call: Dictionary with tool_name and arguments
            
        Returns:
            ToolExecutionResult converted to dictionary
        """
        try:
            if not self.tool_manager:
                return {
                    "success": False,
                    "error": "No ToolManager available",
                    "tool_name": tool_call["tool_name"]
                }
            
            tool_name = tool_call["tool_name"]
            arguments = tool_call["arguments"]
            
            # Check if this is a critical action requiring human approval
            critical_action = self._identify_critical_action(tool_name, arguments)
            
            if critical_action:
                logger.info(f"Critical action detected: {tool_name} - requesting human approval")
                
                # Request human approval
                approved = self._request_human_approval(critical_action)
                
                if not approved:
                    # Generate alternative approach and return failure
                    alternative = self._generate_alternative_approach(critical_action)
                    
                    return {
                        "success": False,
                        "error": f"Critical action denied by human operator. {alternative}",
                        "tool_name": tool_name,
                        "critical_action_denied": True,
                        "alternative_approach": alternative,
                        "risk_level": critical_action.risk_level
                    }
                
                logger.info(f"Critical action approved: {tool_name}")
            
            # Execute the tool
            result = self.tool_manager.execute_tool(tool_name, **arguments)
            
            # Convert ToolExecutionResult to dictionary
            result_dict = {
                "success": result.success,
                "tool_name": result.tool_name,
                "result": result.result,
                "execution_time": result.execution_time,
                "error_message": result.error_message,
                "metadata": result.metadata
            }
            
            # Add critical action metadata if applicable
            if critical_action:
                result_dict["critical_action"] = {
                    "approved": True,
                    "risk_level": critical_action.risk_level,
                    "action_type": critical_action.action_type
                }
            
            return result_dict
            
        except Exception as e:
            logger.error(f"Error executing tool call: {e}")
            return {
                "success": False,
                "error": str(e),
                "tool_name": tool_call.get("tool_name", "unknown")
            }
    def _execute_with_openai(self, prompt: str) -> Dict[str, Any]:
        """
        Execute task using OpenAI client.
        
        Args:
            prompt: Formatted prompt for the LLM
            
        Returns:
            LLM response dictionary
        """
        try:
            response = self.llm_client.chat.completions.create(
                model=self.config.model,
                messages=[
                    {"role": "system", "content": "You are an AI assistant specialized in security analysis and offensive security operations."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature
            )
            
            return {
                "success": True,
                "response": response.choices[0].message.content,
                "model": self.config.model,
                "tokens_used": response.usage.total_tokens if response.usage else None,
                "prompt_tokens": response.usage.prompt_tokens if response.usage else None,
                "completion_tokens": response.usage.completion_tokens if response.usage else None
            }
            
        except openai.APIError as e:
            logger.error(f"OpenAI API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error with OpenAI client: {e}")
            raise
    
    def _execute_with_custom_endpoint(self, prompt: str) -> Dict[str, Any]:
        """
        Execute task using custom HTTP endpoint (like our mock service).
        
        Args:
            prompt: Formatted prompt for the LLM
            
        Returns:
            LLM response dictionary
        """
        try:
            payload = {
                "model": self.config.model,
                "messages": [
                    {"role": "system", "content": "You are an AI assistant specialized in security analysis and offensive security operations."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature
            }
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}"
            }
            
            # Remove /generate from endpoint if it exists to avoid duplication
            base_url = self.config.api_endpoint.rstrip('/generate')
            if not base_url.endswith('/'):
                base_url += '/'
                
            response = requests.post(
                f"{base_url}generate",
                json=payload,
                headers=headers,
                timeout=self.config.timeout
            )
            
            response.raise_for_status()
            result = response.json()
            
            return {
                "success": True,
                "response": result.get("choices", [{}])[0].get("message", {}).get("content", "No response content"),
                "model": result.get("model", self.config.model),
                "tokens_used": result.get("usage", {}).get("total_tokens"),
                "prompt_tokens": result.get("usage", {}).get("prompt_tokens"),
                "completion_tokens": result.get("usage", {}).get("completion_tokens")
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP request error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error with custom endpoint: {e}")
            raise
    
    # Hacking Task Management Methods
    def create_email_tracker(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create and start an email tracking task.
        
        Args:
            config: Configuration for email tracking
                - target_email: Target email address
                - tracking_type: Type of tracking (pixel, link, attachment)
                - campaign_id: Campaign identifier
                - track_location: Whether to track location
                
        Returns:
            Dictionary with task creation result
        """
        try:
            email_tracker = self.hacking_task_factory.create_email_tracker(config)
            
            if email_tracker.start():
                email_tracker.assign_to_agent(self.agent_id)
                payload = email_tracker.generate_payload()
                
                # Store in memory
                self.add_to_memory({
                    "type": "hacking_task_created",
                    "content": f"Created email tracking task for {config.get('target_email')}",
                    "metadata": {
                        "task_id": email_tracker.task_id,
                        "task_type": "email_tracking",
                        "config": config
                    }
                })
                
                return {
                    "success": True,
                    "task_id": email_tracker.task_id,
                    "payload": payload,
                    "message": "Email tracking task created successfully"
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to create email tracking task"
                }
                
        except Exception as e:
            logger.error(f"Error creating email tracker: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def create_extractor(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create and start a data extraction task.
        
        Args:
            config: Configuration for data extraction
                - extraction_type: Type of data to extract (files, credentials, system_info)
                - target_path: Target file/directory path
                - exfiltration_method: Method of data exfiltration (http, dns, ftp)
                - encryption: Whether to encrypt extracted data
                
        Returns:
            Dictionary with task creation result
        """
        try:
            extractor = self.hacking_task_factory.create_extractor(config)
            
            if extractor.start():
                extractor.assign_to_agent(self.agent_id)
                payload = extractor.generate_payload()
                
                # Store in memory
                self.add_to_memory({
                    "type": "hacking_task_created",
                    "content": f"Created data extraction task for {config.get('target_path')}",
                    "metadata": {
                        "task_id": extractor.task_id,
                        "task_type": "data_extraction",
                        "config": config
                    }
                })
                
                return {
                    "success": True,
                    "task_id": extractor.task_id,
                    "payload": payload,
                    "message": "Data extraction task created successfully"
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to create data extraction task"
                }
                
        except Exception as e:
            logger.error(f"Error creating extractor: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def execute_hacking_task(self, task_id: str) -> Dict[str, Any]:
        """
        Execute a previously created hacking task.
        
        Args:
            task_id: ID of the task to execute
            
        Returns:
            Dictionary with task execution result
        """
        try:
            # Get task from hacking task manager
            task_status = self.hacking_task_manager.get_task_status(task_id)
            
            if not task_status:
                return {
                    "success": False,
                    "error": f"Task {task_id} not found"
                }
            
            # Check if task is assigned to this agent
            if task_status.get("assigned_to") != self.agent_id:
                return {
                    "success": False,
                    "error": f"Task {task_id} is not assigned to this agent"
                }
            
            # Execute the task based on type
            task_type = task_status.get("task_type")
            
            if task_type == "email_tracking":
                # Get the email tracker task and execute
                agent_tasks = self.hacking_task_manager.get_agent_tasks(self.agent_id)
                for task_info in agent_tasks:
                    if task_info["task_id"] == task_id:
                        # Create a new email tracker instance to execute
                        from modules.hacking_task_classes import EmailTrackerTask
                        email_tracker = EmailTrackerTask(task_info["config"], self.hacking_task_manager)
                        email_tracker.task_id = task_id
                        email_tracker.assigned_to = self.agent_id
                        result = email_tracker.execute_tracking()
                        
                        # Store in memory
                        self.add_to_memory({
                            "type": "hacking_task_executed",
                            "content": f"Executed email tracking task {task_id}",
                            "metadata": {
                                "task_id": task_id,
                                "result": result
                            }
                        })
                        
                        return result
            
            elif task_type == "extractor_payload":
                # Get the extractor task and execute
                agent_tasks = self.hacking_task_manager.get_agent_tasks(self.agent_id)
                for task_info in agent_tasks:
                    if task_info["task_id"] == task_id:
                        # Create a new extractor instance to execute
                        from modules.hacking_task_classes import ExtractorTask
                        extractor = ExtractorTask(task_info["config"], self.hacking_task_manager)
                        extractor.task_id = task_id
                        extractor.assigned_to = self.agent_id
                        result = extractor.execute_extraction()
                        
                        # Store in memory
                        self.add_to_memory({
                            "type": "hacking_task_executed",
                            "content": f"Executed data extraction task {task_id}",
                            "metadata": {
                                "task_id": task_id,
                                "result": result
                            }
                        })
                        
                        return result
            
            else:
                return {
                    "success": False,
                    "error": f"Unsupported task type: {task_type}"
                }
                
        except Exception as e:
            logger.error(f"Error executing hacking task {task_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_hacking_tasks(self) -> Dict[str, Any]:
        """
        Get all hacking tasks assigned to this agent.
        
        Returns:
            Dictionary containing agent's hacking tasks
        """
        try:
            agent_tasks = self.hacking_task_manager.get_agent_tasks(self.agent_id)
            
            return {
                "success": True,
                "agent_id": self.agent_id,
                "task_count": len(agent_tasks),
                "tasks": agent_tasks
            }
            
        except Exception as e:
            logger.error(f"Error getting hacking tasks: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_hacking_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get the status of a specific hacking task.
        
        Args:
            task_id: ID of the task
            
        Returns:
            Dictionary with task status
        """
        try:
            task_status = self.hacking_task_manager.get_task_status(task_id)
            
            if task_status:
                return {
                    "success": True,
                    "task": task_status
                }
            else:
                return {
                    "success": False,
                    "error": f"Task {task_id} not found"
                }
                
        except Exception as e:
            logger.error(f"Error getting task status: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    # BlackArch Tool Management Methods
    def assign_blackarch_tool(self, tool_name: str, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Assign a BlackArch tool to an agent.
        
        Args:
            tool_name: Name of the BlackArch tool to assign
            agent_id: Optional agent ID (defaults to current agent)
            
        Returns:
            Dictionary with assignment result
        """
        try:
            if agent_id is None:
                agent_id = self.agent_id
            
            # Find tool by name
            tool_id = None
            for tid, tool in self.blackarch_tool_manager.tools.items():
                if tool.name == tool_name:
                    tool_id = tid
                    break
            
            if not tool_id:
                return {
                    "success": False,
                    "error": f"BlackArch tool '{tool_name}' not found"
                }
            
            # Assign the tool
            success = self.blackarch_tool_manager.assign_tool(tool_id, agent_id)
            
            if success:
                # Store in memory
                self.add_to_memory({
                    "type": "blackarch_tool_assigned",
                    "content": f"Assigned BlackArch tool '{tool_name}' to agent {agent_id}",
                    "metadata": {
                        "tool_id": tool_id,
                        "tool_name": tool_name,
                        "agent_id": agent_id
                    }
                })
                
                return {
                    "success": True,
                    "tool_id": tool_id,
                    "tool_name": tool_name,
                    "agent_id": agent_id,
                    "message": f"BlackArch tool '{tool_name}' assigned successfully"
                }
            else:
                return {
                    "success": False,
                    "error": f"Failed to assign BlackArch tool '{tool_name}'"
                }
                
        except Exception as e:
            logger.error(f"Error assigning BlackArch tool: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def execute_blackarch_tool(self, tool_name: str, target: Optional[str] = None, 
                             options: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
        """
        Execute a BlackArch tool.
        
        Args:
            tool_name: Name of the BlackArch tool to execute
            target: Target for the tool (IP, URL, etc.)
            options: Additional command line options
            timeout: Execution timeout in seconds
            
        Returns:
            Dictionary with execution result
        """
        try:
            # Find tool by name
            tool_id = None
            for tid, tool in self.blackarch_tool_manager.tools.items():
                if tool.name == tool_name:
                    tool_id = tid
                    break
            
            if not tool_id:
                return {
                    "success": False,
                    "error": f"BlackArch tool '{tool_name}' not found"
                }
            
            # Check if tool is assigned to this agent
            tool = self.blackarch_tool_manager.tools[tool_id]
            if tool.assigned_to != self.agent_id:
                # Try to assign it first
                assign_result = self.assign_blackarch_tool(tool_name)
                if not assign_result.get("success"):
                    return {
                        "success": False,
                        "error": f"BlackArch tool '{tool_name}' is not assigned to this agent and assignment failed"
                    }
            
            # Execute the tool
            result = self.blackarch_tool_manager.execute_tool(
                tool_id, target, options, timeout
            )
            
            # Store in memory
            self.add_to_memory({
                "type": "blackarch_tool_executed",
                "content": f"Executed BlackArch tool '{tool_name}' on target '{target}'",
                "metadata": {
                    "tool_id": tool_id,
                    "tool_name": tool_name,
                    "target": target,
                    "options": options,
                    "result": result
                }
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing BlackArch tool: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_blackarch_tools(self, category: Optional[str] = None) -> Dict[str, Any]:
        """
        Get all BlackArch tools, optionally filtered by category.
        
        Args:
            category: Optional category filter
            
        Returns:
            Dictionary containing BlackArch tools
        """
        try:
            category_filter = None
            if category:
                try:
                    category_filter = ToolCategory(category)
                except ValueError:
                    return {
                        "success": False,
                        "error": f"Invalid category: {category}"
                    }
            
            tools = self.blackarch_tool_manager.list_tools(
                category_filter=category_filter
            )
            
            return {
                "success": True,
                "agent_id": self.agent_id,
                "tool_count": len(tools),
                "category_filter": category,
                "tools": tools
            }
            
        except Exception as e:
            logger.error(f"Error getting BlackArch tools: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_blackarch_tool_status(self, tool_name: str) -> Dict[str, Any]:
        """
        Get the status of a specific BlackArch tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Dictionary with tool status
        """
        try:
            # Find tool by name
            tool_id = None
            for tid, tool in self.blackarch_tool_manager.tools.items():
                if tool.name == tool_name:
                    tool_id = tid
                    break
            
            if not tool_id:
                return {
                    "success": False,
                    "error": f"BlackArch tool '{tool_name}' not found"
                }
            
            tool_status = self.blackarch_tool_manager.get_tool_status(tool_id)
            
            if tool_status:
                return {
                    "success": True,
                    "tool": tool_status
                }
            else:
                return {
                    "success": False,
                    "error": f"Failed to get status for tool '{tool_name}'"
                }
                
        except Exception as e:
            logger.error(f"Error getting BlackArch tool status: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def update_blackarch_tools(self) -> Dict[str, Any]:
        """
        Update all BlackArch tools using pacman.
        
        Returns:
            Dictionary with update results
        """
        try:
            result = self.blackarch_tool_manager.update_blackarch_tools()
            
            # Store in memory
            self.add_to_memory({
                "type": "blackarch_tools_updated",
                "content": f"BlackArch tools update: {'successful' if result.get('success') else 'failed'}",
                "metadata": {
                    "result": result
                }
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Error updating BlackArch tools: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def search_blackarch_tools(self, query: str) -> Dict[str, Any]:
        """
        Search for BlackArch tools by name or description.
        
        Args:
            query: Search query
            
        Returns:
            Dictionary with search results
        """
        try:
            results = self.blackarch_tool_manager.search_tools(query)
            
            return {
                "success": True,
                "query": query,
                "result_count": len(results),
                "results": results
            }
            
        except Exception as e:
            logger.error(f"Error searching BlackArch tools: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_agent_blackarch_tools(self) -> Dict[str, Any]:
        """
        Get all BlackArch tools assigned to this agent.
        
        Returns:
            Dictionary containing agent's BlackArch tools
        """
        try:
            agent_tools = self.blackarch_tool_manager.get_agent_tools(self.agent_id)
            
            return {
                "success": True,
                "agent_id": self.agent_id,
                "tool_count": len(agent_tools),
                "tools": agent_tools
            }
            
        except Exception as e:
            logger.error(f"Error getting agent BlackArch tools: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    # SocialOSINTAgent Integration Methods
    async def osint_add_target(self, name: str, email: Optional[str] = None,
                              social_profiles: Dict[str, str] = None, **kwargs) -> Dict[str, Any]:
        """
        Add a new OSINT target.
        
        Args:
            name: Target name
            email: Target email address
            social_profiles: Social media profile URLs
            **kwargs: Additional target information
            
        Returns:
            Dictionary containing target ID and status
        """
        try:
            target_id = await self.social_osint_agent.add_target(
                name=name, email=email, social_profiles=social_profiles, **kwargs
            )
            
            return {
                "success": True,
                "target_id": target_id,
                "message": f"OSINT target '{name}' added successfully"
            }
            
        except Exception as e:
            logger.error(f"Error adding OSINT target: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def osint_collect_data(self, target_id: str, sources: List[str] = None) -> Dict[str, Any]:
        """
        Collect OSINT data for a target.
        
        Args:
            target_id: Target identifier
            sources: Data sources to use
            
        Returns:
            Dictionary containing collection results
        """
        try:
            collected = await self.social_osint_agent.collect_data(target_id, sources)
            
            return {
                "success": True,
                "target_id": target_id,
                "data_count": len(collected),
                "sources": list(set(d.source.value for d in collected)),
                "data": [{"id": d.data_id, "source": d.source.value, "confidence": d.confidence_score} for d in collected]
            }
            
        except Exception as e:
            logger.error(f"Error collecting OSINT data: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def osint_analyze_target(self, target_id: str) -> Dict[str, Any]:
        """
        Analyze collected OSINT data for a target.
        
        Args:
            target_id: Target identifier
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            analysis = await self.social_osint_agent.analyze_target(target_id)
            
            return {
                "success": True,
                "target_id": target_id,
                "analysis_id": analysis.result_id,
                "sentiment_score": analysis.sentiment_score,
                "threat_level": analysis.threat_level.value,
                "key_findings": analysis.key_findings,
                "recommendations": analysis.recommendations
            }
            
        except Exception as e:
            logger.error(f"Error analyzing OSINT target: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def osint_crack_passwords(self, target_id: str, password_hashes: List[str]) -> Dict[str, Any]:
        """
        Attempt to crack password hashes.
        
        Args:
            target_id: Target identifier
            password_hashes: Hash values to crack
            
        Returns:
            Dictionary containing cracking results
        """
        try:
            results = await self.social_osint_agent.crack_passwords(target_id, password_hashes)
            
            cracked_count = sum(1 for r in results if r['success'])
            
            return {
                "success": True,
                "target_id": target_id,
                "total_hashes": len(password_hashes),
                "cracked_count": cracked_count,
                "results": results
            }
            
        except Exception as e:
            logger.error(f"Error cracking passwords: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def osint_run_tools(self, target: str, tools: List[str] = None) -> Dict[str, Any]:
        """
        Run OSINT tools against a target.
        
        Args:
            target: Target domain or username
            tools: Tools to run
            
        Returns:
            Dictionary containing tool execution results
        """
        try:
            results = await self.social_osint_agent.run_osint_tools(target, tools)
            
            successful_tools = [tool for tool, result in results.items() if result.get('success', False)]
            
            return {
                "success": True,
                "target": target,
                "tools_run": list(results.keys()),
                "successful_tools": successful_tools,
                "results": results
            }
            
        except Exception as e:
            logger.error(f"Error running OSINT tools: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def osint_generate_report(self, target_id: str, report_type: str = 'summary') -> Dict[str, Any]:
        """
        Generate OSINT report for a target.
        
        Args:
            target_id: Target identifier
            report_type: Type of report ('summary', 'detailed', 'threat')
            
        Returns:
            Dictionary containing generated report
        """
        try:
            report = await self.social_osint_agent.generate_report(target_id, report_type)
            
            return {
                "success": True,
                "target_id": target_id,
                "report_type": report_type,
                "report": report
            }
            
        except Exception as e:
            logger.error(f"Error generating OSINT report: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def osint_list_targets(self) -> Dict[str, Any]:
        """
        List all OSINT targets.
        
        Returns:
            Dictionary containing all targets
        """
        try:
            targets = self.social_osint_agent.list_targets()
            
            return {
                "success": True,
                "target_count": len(targets),
                "targets": targets
            }
            
        except Exception as e:
            logger.error(f"Error listing OSINT targets: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def osint_get_target_summary(self, target_id: str) -> Dict[str, Any]:
        """
        Get summary of target and collected data.
        
        Args:
            target_id: Target identifier
            
        Returns:
            Dictionary containing target summary
        """
        try:
            summary = await self.social_osint_agent.get_target_summary(target_id)
            
            return {
                "success": True,
                "summary": summary
            }
            
        except Exception as e:
            logger.error(f"Error getting OSINT target summary: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def osint_remove_target(self, target_id: str) -> Dict[str, Any]:
        """
        Remove a target and all associated data.
        
        Args:
            target_id: Target identifier
            
        Returns:
            Dictionary containing removal status
        """
        try:
            result = await self.social_osint_agent.remove_target(target_id)
            
            return {
                "success": result,
                "target_id": target_id,
                "message": f"Target {target_id} removed successfully" if result else f"Failed to remove target {target_id}"
            }
            
        except Exception as e:
            logger.error(f"Error removing OSINT target: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }


# Example usage and testing
if __name__ == "__main__":
    # Test the integrated agent with ToolManager
    try:
        # Create ToolManager with default tools
        from tool_manager import create_default_tool_manager
        tool_manager = create_default_tool_manager()
        
        # Create agent with ToolManager
        agent = LLMAutonomousAgent(tool_manager=tool_manager)
        
        print("=== Testing Integrated Agent-Tool System ===")
        print(f"Agent initialized with {len(tool_manager.tools)} tools")
        print(f"Available tools: {list(tool_manager.tools.keys())}")
        print()
        
        # Test task that should trigger tool usage
        test_task = "Perform an OSINT search for 'example.com' and analyze the results for security implications."
        
        print(f"Executing task: {test_task}")
        result = agent.execute_task(test_task)
        
        print("\n=== Task Execution Result ===")
        print(f"Success: {result['success']}")
        print(f"Response: {result.get('response', 'No response')}")
        
        if result.get('tool_calls'):
            print(f"\nTool calls made: {len(result['tool_calls'])}")
            for i, tool_call in enumerate(result['tool_calls']):
                print(f"  {i+1}. {tool_call['tool_name']} - Success: {tool_call['result']['success']}")
                if tool_call['result']['success']:
                    print(f"     Result: {tool_call['result']['result']}")
                else:
                    print(f"     Error: {tool_call['result'].get('error_message', 'Unknown error')}")
        
        print(f"\nTokens used: {result.get('tokens_used', 'N/A')}")
        print(f"Model: {result.get('model', 'N/A')}")
        
        # Test another task with different tool
        test_task2 = "Scan the IP address 192.168.1.1 for open ports and identify any services."
        
        print(f"\n=== Second Test ===")
        print(f"Executing task: {test_task2}")
        result2 = agent.execute_task(test_task2)
        
        print(f"Success: {result2['success']}")
        print(f"Response: {result2.get('response', 'No response')}")
        
        if result2.get('tool_calls'):
            print(f"Tool calls made: {len(result2['tool_calls'])}")
            for tool_call in result2['tool_calls']:
                print(f"  - {tool_call['tool_name']}: {tool_call['result']['result']}")
        
    except Exception as e:
        print(f"Error testing integrated agent: {e}")
        import traceback
        traceback.print_exc()
