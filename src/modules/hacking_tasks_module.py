"""
Hacking Tasks Module for AI Agent Orchestrator
Provides specialized components for managing advanced hacking tasks including
email tracking, extractor payloads, and other security operations.
"""

import json
import logging
import uuid
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Enumeration for task status states."""
    REGISTERED = "registered"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskType(Enum):
    """Enumeration for different hacking task types."""
    EMAIL_TRACKING = "email_tracking"
    EXTRACTOR_PAYLOAD = "extractor_payload"
    NETWORK_EXPLOITATION = "network_exploitation"
    SOCIAL_ENGINEERING = "social_engineering"
    PERSISTENCE = "persistence"
    C2_COMMUNICATION = "c2_communication"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class HackingTask:
    """Represents a hacking task with metadata and status."""
    task_id: str
    task_type: TaskType
    config: Dict[str, Any]
    status: TaskStatus = TaskStatus.REGISTERED
    assigned_to: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def update_status(self, new_status: TaskStatus, metadata: Optional[Dict[str, Any]] = None):
        """Update task status and timestamp."""
        self.status = new_status
        self.updated_at = datetime.now()
        if metadata:
            self.metadata.update(metadata)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary representation."""
        return {
            "task_id": self.task_id,
            "task_type": self.task_type.value,
            "config": self.config,
            "status": self.status.value,
            "assigned_to": self.assigned_to,
            "payload": self.payload,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata
        }


class PayloadGenerator(ABC):
    """Abstract base class for payload generators."""
    
    @abstractmethod
    def generate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a payload based on the provided configuration.
        
        Args:
            config: Configuration dictionary containing payload parameters
            
        Returns:
            Dictionary containing the generated payload and metadata
        """
        pass
    
    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate the payload configuration.
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            True if configuration is valid, False otherwise
        """
        pass


class EmailTrackingPayloadGenerator(PayloadGenerator):
    """Payload generator for email tracking operations."""
    
    def generate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate an email tracking payload.
        
        Args:
            config: Configuration containing tracking parameters
                - target_email: Target email address
                - tracking_type: Type of tracking (pixel, link, etc.)
                - campaign_id: Campaign identifier
                - custom_params: Additional tracking parameters
                
        Returns:
            Dictionary containing the email tracking payload
        """
        if not self.validate_config(config):
            raise ValueError("Invalid configuration for email tracking payload")
        
        tracking_type = config.get("tracking_type", "pixel")
        campaign_id = config.get("campaign_id", f"campaign_{uuid.uuid4().hex[:8]}")
        
        payload = {
            "payload_type": "email_tracking",
            "payload_id": f"email_track_{uuid.uuid4().hex[:8]}",
            "campaign_id": campaign_id,
            "tracking_type": tracking_type,
            "target_email": config.get("target_email"),
            "generated_at": datetime.now().isoformat()
        }
        
        if tracking_type == "pixel":
            payload.update(self._generate_pixel_payload(config))
        elif tracking_type == "link":
            payload.update(self._generate_link_payload(config))
        elif tracking_type == "attachment":
            payload.update(self._generate_attachment_payload(config))
        
        # Add custom parameters
        if "custom_params" in config:
            payload["custom_params"] = config["custom_params"]
        
        logger.info(f"Generated email tracking payload: {payload['payload_id']}")
        return payload
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate email tracking configuration."""
        required_fields = ["target_email"]
        for field in required_fields:
            if field not in config:
                logger.error(f"Missing required field: {field}")
                return False
        
        # Validate email format (basic check)
        email = config.get("target_email", "")
        if "@" not in email or "." not in email:
            logger.error("Invalid email format")
            return False
        
        # Validate tracking type
        tracking_type = config.get("tracking_type", "pixel")
        valid_types = ["pixel", "link", "attachment"]
        if tracking_type not in valid_types:
            logger.error(f"Invalid tracking type: {tracking_type}")
            return False
        
        return True
    
    def _generate_pixel_payload(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate tracking pixel payload."""
        return {
            "tracking_pixel": {
                "url": f"https://tracker.example.com/pixel/{uuid.uuid4().hex}",
                "dimensions": {"width": 1, "height": 1},
                "transparent": True
            },
            "tracking_data": {
                "opens": True,
                "timestamp": True,
                "ip_address": True,
                "user_agent": True,
                "location": config.get("track_location", False)
            }
        }
    
    def _generate_link_payload(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate tracking link payload."""
        return {
            "tracking_link": {
                "url": f"https://link.example.com/click/{uuid.uuid4().hex}",
                "redirect_url": config.get("redirect_url", "https://example.com"),
                "parameters": {
                    "utm_source": "email",
                    "utm_medium": "campaign",
                    "utm_campaign": config.get("campaign_id", "default")
                }
            },
            "tracking_data": {
                "clicks": True,
                "timestamp": True,
                "ip_address": True,
                "user_agent": True,
                "referrer": True
            }
        }
    
    def _generate_attachment_payload(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate attachment-based tracking payload."""
        return {
            "tracking_attachment": {
                "filename": config.get("attachment_name", "document.pdf"),
                "macro_enabled": config.get("macro_enabled", False),
                "execution_method": config.get("execution_method", "macro")
            },
            "tracking_data": {
                "opened": True,
                "executed": True,
                "timestamp": True,
                "system_info": config.get("collect_system_info", False)
            }
        }


class ExtractorPayloadGenerator(PayloadGenerator):
    """Payload generator for data extraction operations."""
    
    def generate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a data extraction payload.
        
        Args:
            config: Configuration containing extraction parameters
                - extraction_type: Type of data to extract
                - target_path: Target file/directory path
                - exfiltration_method: Method of data exfiltration
                - encryption: Whether to encrypt extracted data
                
        Returns:
            Dictionary containing the extraction payload
        """
        if not self.validate_config(config):
            raise ValueError("Invalid configuration for extractor payload")
        
        extraction_type = config.get("extraction_type", "files")
        exfiltration_method = config.get("exfiltration_method", "http")
        
        payload = {
            "payload_type": "data_extraction",
            "payload_id": f"extract_{uuid.uuid4().hex[:8]}",
            "extraction_type": extraction_type,
            "exfiltration_method": exfiltration_method,
            "target_path": config.get("target_path"),
            "generated_at": datetime.now().isoformat()
        }
        
        if extraction_type == "files":
            payload.update(self._generate_file_extraction_payload(config))
        elif extraction_type == "credentials":
            payload.update(self._generate_credential_extraction_payload(config))
        elif extraction_type == "system_info":
            payload.update(self._generate_system_info_payload(config))
        
        # Add exfiltration configuration
        payload["exfiltration"] = self._configure_exfiltration(exfiltration_method, config)
        
        # Add encryption if requested
        if config.get("encryption", False):
            payload["encryption"] = self._configure_encryption(config)
        
        logger.info(f"Generated extraction payload: {payload['payload_id']}")
        return payload
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate extraction configuration."""
        required_fields = ["extraction_type", "target_path"]
        for field in required_fields:
            if field not in config:
                logger.error(f"Missing required field: {field}")
                return False
        
        valid_extraction_types = ["files", "credentials", "system_info", "browser_data"]
        if config["extraction_type"] not in valid_extraction_types:
            logger.error(f"Invalid extraction type: {config['extraction_type']}")
            return False
        
        return True
    
    def _generate_file_extraction_payload(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate file extraction payload."""
        return {
            "file_extraction": {
                "target_path": config.get("target_path"),
                "file_patterns": config.get("file_patterns", ["*"]),
                "recursive": config.get("recursive", True),
                "max_size_mb": config.get("max_size_mb", 100),
                "exclude_patterns": config.get("exclude_patterns", [])
            }
        }
    
    def _generate_credential_extraction_payload(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate credential extraction payload."""
        return {
            "credential_extraction": {
                "sources": config.get("credential_sources", ["browsers", "system", "applications"]),
                "include_passwords": config.get("include_passwords", True),
                "include_hashes": config.get("include_hashes", True),
                "include_tokens": config.get("include_tokens", True)
            }
        }
    
    def _generate_system_info_payload(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate system information extraction payload."""
        return {
            "system_info_extraction": {
                "hardware_info": config.get("hardware_info", True),
                "software_info": config.get("software_info", True),
                "network_config": config.get("network_config", True),
                "running_processes": config.get("running_processes", True),
                "user_accounts": config.get("user_accounts", True)
            }
        }
    
    def _configure_exfiltration(self, method: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure data exfiltration method."""
        base_config = {
            "method": method,
            "compression": config.get("compression", True),
            "chunk_size_kb": config.get("chunk_size_kb", 1024)
        }
        
        if method == "http":
            base_config.update({
                "endpoint": config.get("exfil_endpoint", "https://exfil.example.com/upload"),
                "headers": config.get("http_headers", {}),
                "timeout_seconds": config.get("timeout", 30)
            })
        elif method == "dns":
            base_config.update({
                "dns_domain": config.get("dns_domain", "exfil.example.com"),
                "record_type": config.get("dns_record_type", "TXT"),
                "max_data_per_query": config.get("max_dns_data", 255)
            })
        elif method == "ftp":
            base_config.update({
                "ftp_server": config.get("ftp_server", "ftp.example.com"),
                "ftp_port": config.get("ftp_port", 21),
                "ftp_username": config.get("ftp_username", "anonymous"),
                "ftp_password": config.get("ftp_password", "anonymous@example.com")
            })
        
        return base_config
    
    def _configure_encryption(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure encryption for extracted data."""
        return {
            "enabled": True,
            "algorithm": config.get("encryption_algorithm", "AES256"),
            "key_derivation": config.get("key_derivation", "PBKDF2"),
            "public_key": config.get("public_key", None)  # For asymmetric encryption
        }


class HackingTaskManager:
    """
    Manages hacking tasks including registration, assignment, and payload generation.
    """
    
    def __init__(self):
        """Initialize the HackingTaskManager."""
        self.tasks: Dict[str, HackingTask] = {}
        self.payload_generators: Dict[str, PayloadGenerator] = {}
        self.agent_assignments: Dict[str, List[str]] = {}  # agent_id -> list of task_ids
        self._register_default_generators()
        logger.info("HackingTaskManager initialized")
    
    def _register_default_generators(self):
        """Register default payload generators."""
        self.register_payload_generator("email_tracking", EmailTrackingPayloadGenerator())
        self.register_payload_generator("extractor_payload", ExtractorPayloadGenerator())
    
    def register_task(self, task_type: TaskType, config: Dict[str, Any], 
                     task_id: Optional[str] = None) -> str:
        """
        Register a new hacking task with the orchestrator.
        
        Args:
            task_type: Type of the hacking task
            config: Configuration dictionary for the task
            task_id: Optional custom task ID (auto-generated if not provided)
            
        Returns:
            Task ID of the registered task
        """
        if task_id is None:
            task_id = f"task_{uuid.uuid4().hex[:8]}"
        
        if task_id in self.tasks:
            raise ValueError(f"Task with ID '{task_id}' already exists")
        
        task = HackingTask(
            task_id=task_id,
            task_type=task_type,
            config=config
        )
        
        self.tasks[task_id] = task
        logger.info(f"Registered task {task_id} of type {task_type.value}")
        return task_id
    
    def update_task_status(self, task_id: str, status: TaskStatus, 
                          metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update the status of a hacking task.
        
        Args:
            task_id: ID of the task to update
            status: New status for the task
            metadata: Optional metadata to include with the update
            
        Returns:
            True if update successful, False if task not found
        """
        if task_id not in self.tasks:
            logger.error(f"Task {task_id} not found")
            return False
        
        self.tasks[task_id].update_status(status, metadata)
        logger.info(f"Updated task {task_id} status to {status.value}")
        return True
    
    def get_available_tasks(self, task_type: Optional[TaskType] = None) -> List[str]:
        """
        Get a list of available hacking tasks.
        
        Args:
            task_type: Optional filter for specific task type
            
        Returns:
            List of task IDs that are available for assignment
        """
        available_tasks = []
        for task_id, task in self.tasks.items():
            if task.status == TaskStatus.REGISTERED:
                if task_type is None or task.task_type == task_type:
                    available_tasks.append(task_id)
        
        return available_tasks
    
    def assign_task(self, task_id: str, agent_id: str) -> bool:
        """
        Assign a hacking task to an agent.
        
        Args:
            task_id: ID of the task to assign
            agent_id: ID of the agent to assign the task to
            
        Returns:
            True if assignment successful, False otherwise
        """
        if task_id not in self.tasks:
            logger.error(f"Task {task_id} not found")
            return False
        
        task = self.tasks[task_id]
        if task.status != TaskStatus.REGISTERED:
            logger.error(f"Task {task_id} is not available for assignment (status: {task.status.value})")
            return False
        
        # Update task
        task.assigned_to = agent_id
        task.update_status(TaskStatus.ASSIGNED)
        
        # Update agent assignments
        if agent_id not in self.agent_assignments:
            self.agent_assignments[agent_id] = []
        self.agent_assignments[agent_id].append(task_id)
        
        logger.info(f"Assigned task {task_id} to agent {agent_id}")
        return True
    
    def generate_payload(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Generate a payload for a hacking task.
        
        Args:
            task_id: ID of the task to generate payload for
            
        Returns:
            Generated payload dictionary or None if failed
        """
        if task_id not in self.tasks:
            logger.error(f"Task {task_id} not found")
            return None
        
        task = self.tasks[task_id]
        if task.status != TaskStatus.ASSIGNED:
            logger.error(f"Task {task_id} must be assigned before payload generation (status: {task.status.value})")
            return None
        
        # Get appropriate payload generator
        generator_key = task.task_type.value
        if generator_key not in self.payload_generators:
            logger.error(f"No payload generator registered for task type: {generator_key}")
            return None
        
        try:
            generator = self.payload_generators[generator_key]
            payload = generator.generate(task.config)
            
            # Update task with payload
            task.payload = payload
            task.update_status(TaskStatus.IN_PROGRESS)
            
            logger.info(f"Generated payload for task {task_id}")
            return payload
            
        except Exception as e:
            logger.error(f"Failed to generate payload for task {task_id}: {str(e)}")
            task.update_status(TaskStatus.FAILED, {"error": str(e)})
            return None
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the status of a hacking task.
        
        Args:
            task_id: ID of the task
            
        Returns:
            Task dictionary or None if not found
        """
        if task_id not in self.tasks:
            return None
        
        return self.tasks[task_id].to_dict()
    
    def get_agent_tasks(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Get all tasks assigned to a specific agent.
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            List of task dictionaries assigned to the agent
        """
        if agent_id not in self.agent_assignments:
            return []
        
        agent_tasks = []
        for task_id in self.agent_assignments[agent_id]:
            task_status = self.get_task_status(task_id)
            if task_status:
                agent_tasks.append(task_status)
        
        return agent_tasks
    
    def register_payload_generator(self, task_type: str, generator: PayloadGenerator):
        """
        Register a payload generator for a specific task type.
        
        Args:
            task_type: Task type identifier
            generator: PayloadGenerator instance
        """
        self.payload_generators[task_type] = generator
        logger.info(f"Registered payload generator for task type: {task_type}")
    
    def list_tasks(self, status_filter: Optional[TaskStatus] = None) -> List[Dict[str, Any]]:
        """
        List all tasks with optional status filter.
        
        Args:
            status_filter: Optional status to filter by
            
        Returns:
            List of task dictionaries
        """
        tasks = []
        for task in self.tasks.values():
            if status_filter is None or task.status == status_filter:
                tasks.append(task.to_dict())
        
        return tasks
    
    def complete_task(self, task_id: str, result: Dict[str, Any]) -> bool:
        """
        Mark a task as completed with results.
        
        Args:
            task_id: ID of the task to complete
            result: Results of the task execution
            
        Returns:
            True if successful, False otherwise
        """
        if task_id not in self.tasks:
            logger.error(f"Task {task_id} not found")
            return False
        
        self.tasks[task_id].update_status(TaskStatus.COMPLETED, {"result": result})
        logger.info(f"Completed task {task_id}")
        return True
    
    def fail_task(self, task_id: str, error_message: str) -> bool:
        """
        Mark a task as failed with error information.
        
        Args:
            task_id: ID of the task to fail
            error_message: Error message describing the failure
            
        Returns:
            True if successful, False otherwise
        """
        if task_id not in self.tasks:
            logger.error(f"Task {task_id} not found")
            return False
        
        self.tasks[task_id].update_status(TaskStatus.FAILED, {"error": error_message})
        logger.error(f"Failed task {task_id}: {error_message}")
        return True


# Example usage and testing
if __name__ == "__main__":
    # Create HackingTaskManager
    task_manager = HackingTaskManager()
    
    # Test email tracking task
    print("=== Testing Email Tracking Task ===")
    email_config = {
        "target_email": "target@example.com",
        "tracking_type": "pixel",
        "campaign_id": "test_campaign_001",
        "track_location": True
    }
    
    email_task_id = task_manager.register_task(TaskType.EMAIL_TRACKING, email_config)
    print(f"Registered email tracking task: {email_task_id}")
    
    # Assign and generate payload
    task_manager.assign_task(email_task_id, "agent_001")
    email_payload = task_manager.generate_payload(email_task_id)
    print(f"Generated payload: {json.dumps(email_payload, indent=2)}")
    
    # Test extractor task
    print("\n=== Testing Extractor Task ===")
    extractor_config = {
        "extraction_type": "files",
        "target_path": "/Users/Target/Documents",
        "exfiltration_method": "http",
        "exfil_endpoint": "https://exfil.example.com/upload",
        "encryption": True,
        "file_patterns": ["*.pdf", "*.docx", "*.txt"]
    }
    
    extractor_task_id = task_manager.register_task(TaskType.EXTRACTOR_PAYLOAD, extractor_config)
    print(f"Registered extractor task: {extractor_task_id}")
    
    # Assign and generate payload
    task_manager.assign_task(extractor_task_id, "agent_002")
    extractor_payload = task_manager.generate_payload(extractor_task_id)
    print(f"Generated payload: {json.dumps(extractor_payload, indent=2)}")
    
    # List all tasks
    print("\n=== All Tasks ===")
    for task in task_manager.list_tasks():
        print(f"Task {task['task_id']}: {task['task_type']} - {task['status']}")
    
    # Get agent tasks
    print("\n=== Agent 001 Tasks ===")
    agent_tasks = task_manager.get_agent_tasks("agent_001")
    for task in agent_tasks:
        print(f"Assigned: {task['task_id']} - {task['task_type']}")
