"""
Specialized Hacking Task Classes
Implementation of specific hacking task classes that integrate with the HackingTaskManager.
"""

import json
import logging
import time
import uuid
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .hacking_tasks_module import (
    HackingTaskManager, TaskType, TaskStatus, HackingTask,
    EmailTrackingPayloadGenerator, ExtractorPayloadGenerator
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailTrackerTask:
    """
    Specialized class for managing email tracking operations.
    Integrates with HackingTaskManager for orchestration.
    """
    
    def __init__(self, config: Dict[str, Any], task_manager: HackingTaskManager):
        """
        Initialize EmailTrackerTask.
        
        Args:
            config: Configuration for email tracking
            task_manager: HackingTaskManager instance
        """
        self.config = config
        self.task_manager = task_manager
        self.task_id: Optional[str] = None
        self.status = "initialized"
        self.assigned_to: Optional[str] = None
        self.payload: Optional[Dict[str, Any]] = None
        self.tracking_results: List[Dict[str, Any]] = []
        self.created_at = datetime.now()
        
        # Email tracking specific attributes
        self.target_email = config.get("target_email")
        self.tracking_type = config.get("tracking_type", "pixel")
        self.campaign_id = config.get("campaign_id", f"campaign_{uuid.uuid4().hex[:8]}")
        
    def start(self) -> bool:
        """
        Start the email tracking task.
        
        Returns:
            True if task started successfully, False otherwise
        """
        try:
            # Register task with HackingTaskManager
            self.task_id = self.task_manager.register_task(
                TaskType.EMAIL_TRACKING, 
                self.config
            )
            
            logger.info(f"Started email tracking task: {self.task_id}")
            self.status = "registered"
            return True
            
        except Exception as e:
            logger.error(f"Failed to start email tracking task: {str(e)}")
            self.status = "failed"
            return False
    
    def assign_to_agent(self, agent_id: str) -> bool:
        """
        Assign the task to a specific agent.
        
        Args:
            agent_id: ID of the agent to assign to
            
        Returns:
            True if assignment successful, False otherwise
        """
        if not self.task_id:
            logger.error("Task not registered - cannot assign")
            return False
        
        success = self.task_manager.assign_task(self.task_id, agent_id)
        if success:
            self.assigned_to = agent_id
            self.status = "assigned"
            logger.info(f"Assigned email tracking task {self.task_id} to agent {agent_id}")
        
        return success
    
    def generate_payload(self) -> Optional[Dict[str, Any]]:
        """
        Generate the email tracking payload.
        
        Returns:
            Generated payload or None if failed
        """
        if not self.task_id:
            logger.error("Task not registered - cannot generate payload")
            return None
        
        payload = self.task_manager.generate_payload(self.task_id)
        if payload:
            self.payload = payload
            self.status = "payload_generated"
            logger.info(f"Generated payload for email tracking task {self.task_id}")
        
        return payload
    
    def execute_tracking(self) -> Dict[str, Any]:
        """
        Execute the email tracking operation.
        
        Returns:
            Results of the tracking operation
        """
        if not self.payload:
            logger.error("No payload available - generate payload first")
            return {"success": False, "error": "No payload available"}
        
        try:
            # Simulate email tracking execution
            tracking_result = {
                "success": True,
                "task_id": self.task_id,
                "campaign_id": self.campaign_id,
                "tracking_type": self.tracking_type,
                "target_email": self.target_email,
                "execution_time": datetime.now().isoformat(),
                "tracking_data": self._simulate_tracking_data()
            }
            
            self.tracking_results.append(tracking_result)
            self.status = "completed"
            
            # Update task in HackingTaskManager
            self.task_manager.complete_task(self.task_id, tracking_result)
            
            logger.info(f"Completed email tracking for task {self.task_id}")
            return tracking_result
            
        except Exception as e:
            error_msg = f"Email tracking execution failed: {str(e)}"
            logger.error(error_msg)
            
            # Update task status to failed
            if self.task_id:
                self.task_manager.fail_task(self.task_id, error_msg)
            
            self.status = "failed"
            return {"success": False, "error": error_msg}
    
    def _simulate_tracking_data(self) -> Dict[str, Any]:
        """Simulate tracking data for demonstration purposes."""
        return {
            "email_opened": True,
            "open_timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "location": {
                "country": "US",
                "city": "New York",
                "coordinates": {"lat": 40.7128, "lng": -74.0060}
            },
            "device_info": {
                "platform": "Windows",
                "browser": "Chrome",
                "screen_resolution": "1920x1080"
            }
        }
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get all tracking results."""
        return self.tracking_results.copy()
    
    def heartbeat(self) -> bool:
        """
        Send a heartbeat to the Hacking Task Manager.
        
        Returns:
            True if heartbeat successful, False otherwise
        """
        if self.task_id:
            # Update task status to show it's still active
            self.task_manager.update_task_status(
                self.task_id, 
                TaskStatus.IN_PROGRESS,
                {"last_heartbeat": datetime.now().isoformat()}
            )
            logger.debug(f"Heartbeat sent for task {self.task_id}")
            return True
        return False


class ExtractorTask:
    """
    Specialized class for managing data extraction operations.
    """
    
    def __init__(self, config: Dict[str, Any], task_manager: HackingTaskManager):
        """
        Initialize ExtractorTask.
        
        Args:
            config: Configuration for data extraction
            task_manager: HackingTaskManager instance
        """
        self.config = config
        self.task_manager = task_manager
        self.task_id: Optional[str] = None
        self.status = "initialized"
        self.assigned_to: Optional[str] = None
        self.payload: Optional[Dict[str, Any]] = None
        self.extraction_results: List[Dict[str, Any]] = []
        self.created_at = datetime.now()
        
        # Extraction specific attributes
        self.extraction_type = config.get("extraction_type", "files")
        self.target_path = config.get("target_path")
        self.exfiltration_method = config.get("exfiltration_method", "http")
    
    def start(self) -> bool:
        """Start the extraction task."""
        try:
            self.task_id = self.task_manager.register_task(
                TaskType.EXTRACTOR_PAYLOAD,
                self.config
            )
            
            logger.info(f"Started extraction task: {self.task_id}")
            self.status = "registered"
            return True
            
        except Exception as e:
            logger.error(f"Failed to start extraction task: {str(e)}")
            self.status = "failed"
            return False
    
    def assign_to_agent(self, agent_id: str) -> bool:
        """Assign the task to a specific agent."""
        if not self.task_id:
            logger.error("Task not registered - cannot assign")
            return False
        
        success = self.task_manager.assign_task(self.task_id, agent_id)
        if success:
            self.assigned_to = agent_id
            self.status = "assigned"
            logger.info(f"Assigned extraction task {self.task_id} to agent {agent_id}")
        
        return success
    
    def generate_payload(self) -> Optional[Dict[str, Any]]:
        """Generate the extraction payload."""
        if not self.task_id:
            logger.error("Task not registered - cannot generate payload")
            return None
        
        payload = self.task_manager.generate_payload(self.task_id)
        if payload:
            self.payload = payload
            self.status = "payload_generated"
            logger.info(f"Generated payload for extraction task {self.task_id}")
        
        return payload
    
    def execute_extraction(self) -> Dict[str, Any]:
        """Execute the data extraction operation."""
        if not self.payload:
            logger.error("No payload available - generate payload first")
            return {"success": False, "error": "No payload available"}
        
        try:
            # Simulate data extraction execution
            extraction_result = {
                "success": True,
                "task_id": self.task_id,
                "extraction_type": self.extraction_type,
                "target_path": self.target_path,
                "execution_time": datetime.now().isoformat(),
                "extracted_data": self._simulate_extraction_data()
            }
            
            self.extraction_results.append(extraction_result)
            self.status = "completed"
            
            # Update task in HackingTaskManager
            self.task_manager.complete_task(self.task_id, extraction_result)
            
            logger.info(f"Completed data extraction for task {self.task_id}")
            return extraction_result
            
        except Exception as e:
            error_msg = f"Data extraction execution failed: {str(e)}"
            logger.error(error_msg)
            
            # Update task status to failed
            if self.task_id:
                self.task_manager.fail_task(self.task_id, error_msg)
            
            self.status = "failed"
            return {"success": False, "error": error_msg}
    
    def _simulate_extraction_data(self) -> Dict[str, Any]:
        """Simulate extracted data for demonstration purposes."""
        if self.extraction_type == "files":
            return {
                "files_extracted": 15,
                "total_size_mb": 42.7,
                "file_list": [
                    {"name": "document1.pdf", "size_mb": 2.1, "type": "PDF"},
                    {"name": "report.docx", "size_mb": 1.8, "type": "DOCX"},
                    {"name": "presentation.pptx", "size_mb": 5.2, "type": "PPTX"}
                ],
                "exfiltration_status": "completed",
                "exfil_endpoint": self.config.get("exfil_endpoint", "https://exfil.example.com/upload")
            }
        elif self.extraction_type == "credentials":
            return {
                "credentials_found": 8,
                "credential_types": {
                    "browser_passwords": 3,
                    "system_hashes": 2,
                    "application_tokens": 3
                },
                "encrypted_package": "base64_encrypted_data_here",
                "exfiltration_status": "completed"
            }
        elif self.extraction_type == "system_info":
            return {
                "system_info_collected": True,
                "hardware": {
                    "cpu": "Intel Core i7-9700K",
                    "ram_gb": 16,
                    "disk_gb": 512
                },
                "software": {
                    "os": "Windows 10 Pro",
                    "installed_programs": 45
                },
                "network": {
                    "interfaces": 2,
                    "active_connections": 12
                },
                "exfiltration_status": "completed"
            }
        
        return {"status": "unknown_extraction_type"}
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get all extraction results."""
        return self.extraction_results.copy()
    
    def heartbeat(self) -> bool:
        """Send a heartbeat to the Hacking Task Manager."""
        if self.task_id:
            self.task_manager.update_task_status(
                self.task_id,
                TaskStatus.IN_PROGRESS,
                {"last_heartbeat": datetime.now().isoformat()}
            )
            logger.debug(f"Heartbeat sent for task {self.task_id}")
            return True
        return False


class HackingTaskFactory:
    """
    Factory class for creating specialized hacking tasks.
    """
    
    def __init__(self, task_manager: HackingTaskManager):
        """
        Initialize the factory with a task manager.
        
        Args:
            task_manager: HackingTaskManager instance
        """
        self.task_manager = task_manager
    
    def create_email_tracker(self, config: Dict[str, Any]) -> EmailTrackerTask:
        """
        Create an email tracking task.
        
        Args:
            config: Configuration for email tracking
            
        Returns:
            EmailTrackerTask instance
        """
        return EmailTrackerTask(config, self.task_manager)
    
    def create_extractor(self, config: Dict[str, Any]) -> ExtractorTask:
        """
        Create a data extraction task.
        
        Args:
            config: Configuration for data extraction
            
        Returns:
            ExtractorTask instance
        """
        return ExtractorTask(config, self.task_manager)
    
    def create_task(self, task_type: TaskType, config: Dict[str, Any]):
        """
        Create a task based on type.
        
        Args:
            task_type: Type of task to create
            config: Configuration for the task
            
        Returns:
            Appropriate task instance
        """
        if task_type == TaskType.EMAIL_TRACKING:
            return self.create_email_tracker(config)
        elif task_type == TaskType.EXTRACTOR_PAYLOAD:
            return self.create_extractor(config)
        else:
            raise ValueError(f"Unsupported task type: {task_type}")


# Example usage and testing
if __name__ == "__main__":
    # Create HackingTaskManager and factory
    task_manager = HackingTaskManager()
    factory = HackingTaskFactory(task_manager)
    
    # Test EmailTrackerTask
    print("=== Testing EmailTrackerTask ===")
    email_config = {
        "target_email": "target@example.com",
        "tracking_type": "pixel",
        "campaign_id": "test_campaign_001",
        "track_location": True
    }
    
    email_tracker = factory.create_email_tracker(email_config)
    
    # Start and execute the task
    if email_tracker.start():
        email_tracker.assign_to_agent("agent_001")
        payload = email_tracker.generate_payload()
        if payload:
            result = email_tracker.execute_tracking()
            print(f"Email tracking result: {json.dumps(result, indent=2)}")
    
    # Test ExtractorTask
    print("\n=== Testing ExtractorTask ===")
    extractor_config = {
        "extraction_type": "files",
        "target_path": "/Users/Target/Documents",
        "exfiltration_method": "http",
        "exfil_endpoint": "https://exfil.example.com/upload",
        "encryption": True
    }
    
    extractor = factory.create_extractor(extractor_config)
    
    # Start and execute the task
    if extractor.start():
        extractor.assign_to_agent("agent_002")
        payload = extractor.generate_payload()
        if payload:
            result = extractor.execute_extraction()
            print(f"Extraction result: {json.dumps(result, indent=2)}")
    
    # Show task manager status
    print("\n=== Task Manager Status ===")
    all_tasks = task_manager.list_tasks()
    for task in all_tasks:
        print(f"Task {task['task_id']}: {task['task_type']} - {task['status']}")
    
    # Show agent assignments
    print("\n=== Agent Assignments ===")
    for agent_id in ["agent_001", "agent_002"]:
        agent_tasks = task_manager.get_agent_tasks(agent_id)
        print(f"Agent {agent_id} has {len(agent_tasks)} tasks:")
        for task in agent_tasks:
            print(f"  - {task['task_id']}: {task['task_type']}")
