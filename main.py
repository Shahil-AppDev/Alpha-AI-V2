#!/usr/bin/env python3
"""
AI Security Tool - Main Application
==================================

This is the main entry point for the AI Security Tool that orchestrates
the autonomous agent with all security analysis modules.

Usage:
    python main.py [--objective "your objective here"] [--clear-memory]

Features:
- Environment variable loading and configuration
- ToolManager initialization with all modules
- LLMAutonomousAgent with human approval system
- Complete security analysis workflow
- Memory management and persistence
- Comprehensive reporting and output handling
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

# Add src directory to path
sys.path.append(str(Path(__file__).parent / "src"))

# Import our modules
from agent import LLMAutonomousAgent, LLMConfig
from tool_manager import create_default_tool_manager

# Load environment variables
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ai_security_tool.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class AISecurityTool:
    """
    Main AI Security Tool application class.
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the AI Security Tool.
        
        Args:
            config_file: Optional path to configuration file
        """
        self.config_file = config_file
        self.config = None
        self.tool_manager = None
        self.agent = None
        self.memory_file = "agent_memory.json"
        
        # Load configuration and initialize components
        self._load_environment()
        self._initialize_components()
        
    def _load_environment(self) -> None:
        """
        Load environment variables and configuration.
        """
        logger.info("Loading environment variables...")
        
        # Load from .env file if it exists
        env_file = Path(__file__).parent / ".env"
        if env_file.exists():
            load_dotenv(env_file)
            logger.info(f"Loaded environment from {env_file}")
        
        # Load configuration from file if provided
        if self.config_file and Path(self.config_file).exists():
            with open(self.config_file, 'r') as f:
                file_config = json.load(f)
                logger.info(f"Loaded configuration from {self.config_file}")
        else:
            file_config = {}
        
        # Create LLM configuration
        self.config = LLMConfig(
            api_endpoint=os.getenv("LLM_ENDPOINT", file_config.get("llm_endpoint", "http://llm-service:8000/generate")),
            api_key=os.getenv("LLM_API_KEY", file_config.get("llm_api_key", "test-key")),
            model=os.getenv("LLM_MODEL", file_config.get("llm_model", "gpt-3.5-turbo")),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", file_config.get("llm_max_tokens", 2000))),
            temperature=float(os.getenv("LLM_TEMPERATURE", file_config.get("llm_temperature", 0.7))),
            timeout=int(os.getenv("LLM_TIMEOUT", file_config.get("llm_timeout", 30))),
            max_tool_calls=int(os.getenv("MAX_TOOL_CALLS", file_config.get("max_tool_calls", 5))),
            require_human_approval=os.getenv("REQUIRE_HUMAN_APPROVAL", file_config.get("require_human_approval", "true")).lower() == "true"
        )
        
        logger.info(f"Configuration loaded:")
        logger.info(f"  LLM Endpoint: {self.config.api_endpoint}")
        logger.info(f"  Model: {self.config.model}")
        logger.info(f"  Human Approval: {self.config.require_human_approval}")
        logger.info(f"  Max Tool Calls: {self.config.max_tool_calls}")
        
    def _initialize_components(self) -> None:
        """
        Initialize ToolManager and LLMAutonomousAgent.
        """
        logger.info("Initializing ToolManager...")
        
        # Initialize ToolManager with all modules
        self.tool_manager = create_default_tool_manager()
        
        logger.info(f"ToolManager initialized with {len(self.tool_manager.tools)} tools:")
        for category, tools in self.tool_manager.get_tool_categories().items():
            logger.info(f"  {category}: {tools}")
        
        logger.info("Initializing LLMAutonomousAgent...")
        
        # Initialize the autonomous agent
        self.agent = LLMAutonomousAgent(config=self.config, tool_manager=self.tool_manager)
        
        logger.info("LLMAutonomousAgent initialized successfully")
        logger.info(f"Agent has {len(self.agent.tool_manager.tools)} tools available")
        logger.info(f"Human approval system: {'ENABLED' if self.config.require_human_approval else 'DISABLED'}")
        
    def load_memory(self) -> None:
        """
        Load agent memory from file if it exists.
        """
        if Path(self.memory_file).exists():
            try:
                with open(self.memory_file, 'r') as f:
                    memory_data = json.load(f)
                    self.agent.memory = memory_data.get("memory", [])
                    self.agent.critical_actions_history = memory_data.get("critical_actions_history", [])
                    logger.info(f"Loaded {len(self.agent.memory)} memory entries from file")
            except Exception as e:
                logger.warning(f"Failed to load memory from file: {e}")
                logger.info("Starting with empty memory")
        else:
            logger.info("No existing memory file found - starting fresh")
            
    def save_memory(self) -> None:
        """
        Save agent memory to file for persistence.
        """
        try:
            memory_data = {
                "memory": self.agent.memory,
                "critical_actions_history": self.agent.critical_actions_history,
                "saved_at": datetime.now().isoformat()
            }
            
            with open(self.memory_file, 'w') as f:
                json.dump(memory_data, f, indent=2)
                
            logger.info(f"Saved {len(self.agent.memory)} memory entries to file")
            
        except Exception as e:
            logger.error(f"Failed to save memory to file: {e}")
            
    def clear_memory(self) -> None:
        """
        Clear agent memory and remove memory file.
        """
        logger.info("Clearing agent memory...")
        
        # Clear in-memory data
        self.agent.memory.clear()
        self.agent.critical_actions_history.clear()
        
        # Remove memory file if it exists
        if Path(self.memory_file).exists():
            try:
                os.remove(self.memory_file)
                logger.info("Memory file removed")
            except Exception as e:
                logger.warning(f"Failed to remove memory file: {e}")
                
        logger.info("Agent memory cleared successfully")
        
    def display_results(self, results: Dict[str, Any]) -> None:
        """
        Display the execution results in a formatted way.
        
        Args:
            results: Results from plan_and_execute
        """
        print("\n" + "="*80)
        print("🤖 AI SECURITY TOOL - EXECUTION RESULTS")
        print("="*80)
        
        if results.get("success"):
            print(f"✅ Status: SUCCESS")
            print(f"🎯 Objective: {results.get('objective', 'N/A')}")
            print(f"⏱️  Execution Time: {results.get('execution_time', 'N/A')} seconds")
            print(f"📋 Plan Steps: {len(results.get('execution_results', []))}")
            
            # Display plan
            print("\n📋 EXECUTION PLAN:")
            plan = results.get('original_plan', [])
            for i, step in enumerate(plan, 1):
                print(f"   {i}. {step.get('description', 'N/A')} ({step.get('type', 'analysis')})")
            
            # Display execution results
            print("\n🔄 EXECUTION RESULTS:")
            execution_results = results.get('execution_results', [])
            for i, result in enumerate(execution_results, 1):
                status = "✅" if result.get('success', False) else "❌"
                step_desc = result.get('step_description', f'Step {i}')
                print(f"   {status} {step_desc}")
                
                if not result.get('success', False):
                    error = result.get('error', 'Unknown error')
                    print(f"      Error: {error}")
            
            # Display final summary
            summary = results.get('final_summary', 'No summary available')
            print(f"\n📊 FINAL SUMMARY:")
            print(f"   {summary}")
            
            # Display critical actions if any
            if self.agent.critical_actions_history:
                print(f"\n🚨 CRITICAL ACTIONS HISTORY:")
                for i, action_record in enumerate(self.agent.critical_actions_history[-5:], 1):  # Last 5 actions
                    action = action_record.get('action', {})
                    approved = action_record.get('approved', False)
                    status = "✅ APPROVED" if approved else "❌ DENIED"
                    print(f"   {i}. {action.get('tool_name', 'N/A')} - {status}")
                    print(f"      Risk Level: {action.get('risk_level', 'N/A')}")
                    print(f"      Description: {action.get('description', 'N/A')[:100]}...")
                    
        else:
            print(f"❌ Status: FAILED")
            print(f"🎯 Objective: {results.get('objective', 'N/A')}")
            error = results.get('error', 'Unknown error')
            print(f"❌ Error: {error}")
            
        print("="*80)
        
    def run_objective(self, objective: str, clear_memory: bool = False) -> Dict[str, Any]:
        """
        Run the AI Security Tool with a specific objective.
        
        Args:
            objective: The security analysis objective
            clear_memory: Whether to clear memory before execution
            
        Returns:
            Execution results dictionary
        """
        logger.info(f"Starting AI Security Tool with objective: {objective}")
        
        # Clear memory if requested
        if clear_memory:
            self.clear_memory()
        else:
            # Load existing memory
            self.load_memory()
        
        # Add objective to memory
        self.agent.add_to_memory({
            "type": "objective",
            "content": f"Starting security analysis: {objective}",
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "objective": objective
            }
        })
        
        try:
            # Execute the objective using the agent
            logger.info("Executing plan_and_execute workflow...")
            start_time = datetime.now()
            
            results = self.agent.plan_and_execute(objective)
            
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            results['execution_time'] = execution_time
            
            logger.info(f"Execution completed in {execution_time:.2f} seconds")
            logger.info(f"Success: {results.get('success', False)}")
            
            # Save memory after execution
            self.save_memory()
            
            # Display results
            self.display_results(results)
            
            return results
            
        except KeyboardInterrupt:
            logger.warning("Execution interrupted by user")
            self.save_memory()  # Save progress before exiting
            return {
                "success": False,
                "error": "Execution interrupted by user",
                "objective": objective
            }
            
        except Exception as e:
            logger.error(f"Unexpected error during execution: {e}")
            self.save_memory()  # Save progress before exiting
            return {
                "success": False,
                "error": str(e),
                "objective": objective
            }
            
    def interactive_mode(self) -> None:
        """
        Run the tool in interactive mode.
        """
        print("\n🤖 AI Security Tool - Interactive Mode")
        print("Type 'help' for commands or 'quit' to exit")
        print("="*60)
        
        while True:
            try:
                user_input = input("\n🎯 Enter your security objective: ").strip()
                
                if not user_input:
                    continue
                    
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("👋 Goodbye!")
                    break
                    
                if user_input.lower() == 'help':
                    self._show_help()
                    continue
                    
                if user_input.lower() == 'clear':
                    self.clear_memory()
                    print("✅ Memory cleared")
                    continue
                    
                if user_input.lower() == 'status':
                    self._show_status()
                    continue
                    
                # Execute the objective
                self.run_objective(user_input)
                
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
                
    def _show_help(self) -> None:
        """Display help information."""
        print("\n📚 Available Commands:")
        print("  help     - Show this help message")
        print("  status   - Show current tool status")
        print("  clear    - Clear agent memory")
        print("  quit     - Exit the application")
        print("\n🎯 Example Objectives:")
        print("  'Perform OSINT on example.com and identify potential vulnerabilities'")
        print("  'Scan 192.168.1.1 for open ports and services'")
        print("  'Analyze the binary file /path/to/malware for threats'")
        print("  'Generate a reverse shell payload for testing purposes'")
        
    def _show_status(self) -> None:
        """Display current tool status."""
        print(f"\n📊 AI Security Tool Status:")
        print(f"  Tools Available: {len(self.tool_manager.tools)}")
        print(f"  Memory Entries: {len(self.agent.memory)}")
        print(f"  Critical Actions: {len(self.agent.critical_actions_history)}")
        print(f"  Human Approval: {'ENABLED' if self.config.require_human_approval else 'DISABLED'}")
        print(f"  LLM Endpoint: {self.config.api_endpoint}")


def main():
    """
    Main entry point for the AI Security Tool.
    """
    parser = argparse.ArgumentParser(
        description="AI Security Tool - Autonomous Security Analysis Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --objective "Perform OSINT on target.com"
  python main.py --objective "Scan 192.168.1.1 for open ports" --clear-memory
  python main.py --interactive
  python main.py --config config.json
        """
    )
    
    parser.add_argument(
        "--objective", "-o",
        type=str,
        help="Security analysis objective for the agent"
    )
    
    parser.add_argument(
        "--clear-memory", "-c",
        action="store_true",
        help="Clear agent memory before execution"
    )
    
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Run in interactive mode"
    )
    
    parser.add_argument(
        "--config",
        type=str,
        help="Path to configuration file (JSON)"
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize the AI Security Tool
        print("🤖 Initializing AI Security Tool...")
        tool = AISecurityTool(config_file=args.config)
        
        if args.interactive:
            # Run in interactive mode
            tool.interactive_mode()
        elif args.objective:
            # Run with specific objective
            results = tool.run_objective(args.objective, clear_memory=args.clear_memory)
            
            # Exit with appropriate code
            sys.exit(0 if results.get("success", False) else 1)
        else:
            # Default objective if none provided
            default_objective = "Perform OSINT on target.com, identify open ports, and suggest potential attack vectors"
            print(f"No objective provided, using default: {default_objective}")
            results = tool.run_objective(default_objective, clear_memory=args.clear_memory)
            
            # Exit with appropriate code
            sys.exit(0 if results.get("success", False) else 1)
            
    except KeyboardInterrupt:
        print("\n👋 Application interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
