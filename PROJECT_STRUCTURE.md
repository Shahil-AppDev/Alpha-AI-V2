# AI-Driven Offensive Security Tool - Project Structure

## Directory Structure

```
ai-offensive-security/
├── docker/                          # Docker configurations
│   ├── Dockerfile                  # Main application Dockerfile
│   ├── docker-compose.yml          # Service orchestration
│   └── mock_llm/                   # Mock LLM service
├── src/                            # Core agent logic and Python modules
│   ├── agent.py                    # Main autonomous agent
│   ├── tool_manager.py             # Tool management system
│   ├── modules/                    # Security analysis modules
│   │   ├── osint_module.py         # OSINT reconnaissance
│   │   ├── network_module.py      # Network scanning
│   │   ├── password_module.py      # Password cracking
│   │   ├── analysis_module.py      # Code analysis
│   │   ├── exploit_module.py       # Exploit generation
│   │   └── reverse_engineering_module.py  # Binary analysis
│   └── requirements.txt            # Python dependencies
├── tools/                          # Custom scripts and utilities
│   ├── scanners/                   # Network scanning tools
│   ├── exploits/                   # Exploit scripts
│   ├── wordlists/                  # Password wordlists
│   └── utilities/                  # Helper scripts
├── config/                         # Configuration files
│   ├── default.json               # Default configuration
│   ├── llm_config.json            # LLM service configuration
│   └── tool_configs/               # Individual tool configurations
├── data/                          # Data storage
│   ├── logs/                      # Application logs
│   ├── memory/                    # Agent memory storage
│   ├── results/                   # Analysis results
│   └── temp/                      # Temporary files
├── main.py                        # Main application entry point
├── README.md                      # Project documentation
└── .env                          # Environment variables
```

## Directory Descriptions

### `docker/`
Contains all Docker-related configurations:
- **Dockerfile**: Main application container definition
- **docker-compose.yml**: Multi-service orchestration
- **mock_llm/**: Mock LLM service for testing

### `src/`
Core application code:
- **agent.py**: Autonomous agent with planning and execution
- **tool_manager.py**: Tool registration and management
- **modules/**: Security analysis modules
- **requirements.txt**: Python package dependencies

### `tools/`
Custom security tools and utilities:
- **scanners/**: Network and vulnerability scanners
- **exploits/**: Exploit development scripts
- **wordlists/**: Password cracking wordlists
- **utilities/**: Helper and automation scripts

### `config/`
Configuration management:
- **default.json**: Default application settings
- **llm_config.json**: LLM service configuration
- **tool_configs/**: Individual tool configurations

### `data/`
Data storage and management:
- **logs/**: Application and security logs
- **memory/**: Agent memory and context storage
- **results/**: Analysis results and reports
- **temp/**: Temporary files and caches

## Key Features

- **Modular Architecture**: Separate modules for different security functions
- **Docker Support**: Complete containerization with service orchestration
- **Human Oversight**: Built-in approval system for critical actions
- **Memory Management**: Persistent context and audit trails
- **Extensible**: Easy to add new tools and modules
- **Configuration Driven**: Flexible configuration management

## Security Considerations

- **Non-root User**: Containers run with non-privileged users
- **Network Isolation**: Services communicate through internal networks
- **Audit Logging**: Complete logging of all actions and decisions
- **Access Controls**: Human approval required for dangerous operations
- **Data Protection**: Encrypted storage for sensitive data
