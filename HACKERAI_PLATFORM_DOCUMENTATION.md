# HackerAI Platform - Comprehensive Documentation

## Overview

The HackerAI Platform is a comprehensive, containerized security tool management system that integrates hundreds of open-source hacking tools into a unified AI-powered interface. Built with scalability, security, and ease of use in mind, it provides enterprise-grade capabilities for penetration testing, security research, and intelligence gathering.

## Architecture

### High-Level Architecture

```mermaid
graph TB
    subgraph "Frontend Layer"
        A[Web Dashboard] --> B[REST API]
        C[Mobile App] --> B
        D[CLI Tools] --> B
    end
    
    subgraph "API Gateway"
        B --> E[Nginx Reverse Proxy]
        E --> F[Rate Limiting]
        E --> G[SSL Termination]
    end
    
    subgraph "Application Layer"
        H[HackerAI API] --> I[Universal Tool Manager]
        H --> J[Social OSINT Agent]
        H --> K[Task Scheduler]
        H --> L[Result Processor]
    end
    
    subgraph "Tool Execution Layer"
        I --> M[Native Executor]
        I --> N[Docker Executor]
        I --> O[Kubernetes Executor]
        I --> P[Cloud Executor]
    end
    
    subgraph "Tool Containers"
        Q[OSINT Tools] --> R[Network Tools]
        R --> S[Web Security]
        S --> T[Password Cracking]
        T --> U[Exploitation]
        U --> V[Wireless]
        V --> W[Forensics]
        W --> X[Malware Analysis]
    end
    
    subgraph "Data Layer"
        Y[PostgreSQL] --> Z[Redis Cache]
        Z --> AA[MinIO Storage]
        AA --> BB[Time Series DB]
    end
    
    subgraph "Monitoring"
        CC[Prometheus] --> DD[Grafana]
        DD --> EE[Alert Manager]
        EE --> FF[Log Aggregation]
    end
```

### Core Components

#### 1. Universal Tool Manager
The heart of the platform, managing hundreds of security tools across multiple categories:
- **Tool Registration**: Dynamic tool discovery and registration
- **Execution Management**: Multiple execution modes (Native, Docker, Kubernetes, Cloud)
- **Resource Management**: CPU, memory, and GPU resource allocation
- **Statistics & Monitoring**: Real-time execution metrics and success rates

#### 2. HackerAI API Server
FastAPI-based REST API providing:
- **Tool Execution Endpoints**: Execute any registered tool
- **Assessment Workflows**: Comprehensive security assessments
- **OSINT Integration**: Social media intelligence gathering
- **Management APIs**: Tool installation, updates, and configuration
- **Monitoring APIs**: System health and performance metrics

#### 3. Containerized Tool Environment
Each tool category runs in isolated containers:
- **Security Isolation**: Tools run in isolated environments
- **Resource Control**: CPU, memory, and network limits
- **Scalability**: Horizontal scaling of tool containers
- **Portability**: Deploy anywhere Docker runs

#### 4. Social OSINT Agent
Advanced intelligence gathering capabilities:
- **Multi-source Collection**: Social media, public records, forums
- **NLP Processing**: Sentiment analysis, entity extraction
- **Threat Assessment**: Automated risk analysis
- **Privacy Compliance**: GDPR and CCPA compliant

## Tool Categories

### 1. OSINT & Social Engineering
| Tool | Function | Docker Image |
|------|----------|--------------|
| theHarvester | Email/subdomain harvesting | blackarch/theharvester |
| Sherlock | Username search across 300+ sites | sherlock/sherlock |
| Recon-ng | Web reconnaissance framework | blackarch/recon-ng |
| Maltego | Visual link analysis | paterva/maltego |
| SpiderFoot | OSINT automation | spiderfoot/spiderfoot |
| SET | Social engineering toolkit | trustedsec/social-engineer-toolkit |

### 2. Network Scanning & Enumeration
| Tool | Function | Docker Image |
|------|----------|--------------|
| Nmap | Network discovery and port scanning | instrumentisto/nmap |
| Masscan | High-speed port scanner | instrumentisto/masscan |
| Nikto | Web server vulnerability scanner | frapsoft/nikto |
| Unicornscan | Asynchronous network scanner | blackarch/unicornscan |
| Hping3 | Network packet crafting | blackarch/hping3 |
| Netdiscover | ARP-based network scanner | blackarch/netdiscover |

### 3. Web Application Security
| Tool | Function | Docker Image |
|------|----------|--------------|
| SQLMap | SQL injection testing | sqlmapproject/sqlmap |
| Burp Suite | Web application testing | portswigger/burp |
| OWASP ZAP | Automated web scanning | owasp/zap2docker-stable |
| Gobuster | Directory/file brute forcing | oj/gobuster |
| Feroxbuster | Fast content discovery | epi052/feroxbuster |
| FFuf | Fast web fuzzer | ffuf/ffuf |

### 4. Password Cracking
| Tool | Function | Docker Image |
|------|----------|--------------|
| Hashcat | GPU-accelerated password recovery | daisukehishimoto/hashcat |
| John the Ripper | Advanced password cracker | blackarch/john |
| Hydra | Parallel login cracker | blackarch/hydra |
| Medusa | Parallel brute force tool | blackarch/medusa |
| Patator | Multi-purpose brute forcer | land0r/patator |

### 5. Exploitation Frameworks
| Tool | Function | Docker Image |
|------|----------|--------------|
| Metasploit | Exploitation framework | metasploitframework/metasploit-framework |
| Empire | Post-exploitation framework | bc-security/empire |
| Cobalt Strike | Commercial penetration testing | (Commercial) |
| BeEF | Browser exploitation framework | beefproject/beef |

### 6. Wireless Security
| Tool | Function | Docker Image |
|------|----------|--------------|
| Aircrack-ng | Wi-Fi security suite | aircrack-ng/aircrack-ng |
| Bettercap | Swiss army knife for networks | bettercap/bettercap |
| Kismet | Wireless network detector | kismetwireless/kismet |
| Wifite | Automated wireless auditor | derv82/wifite2 |

### 7. Forensics & Malware Analysis
| Tool | Function | Docker Image |
|------|----------|--------------|
| Autopsy | Digital forensics platform | sleuthkit/autopsy |
| Volatility | Memory forensics framework | volatilityfoundation/volatility |
| YARA | Malware identification | virustotal/yara |
| Ghidra | Reverse engineering suite | nsa/ghidra |
| Radare2 | Reverse engineering framework | radareorg/radare2 |

## Installation & Deployment

### Prerequisites

- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+, Arch Linux)
- **Docker**: Version 20.10+
- **Docker Compose**: Version 2.0+
- **RAM**: Minimum 8GB, Recommended 16GB+
- **Storage**: Minimum 100GB, Recommended 500GB+
- **GPU**: Optional NVIDIA GPU for password cracking
- **Network**: Internet connection for tool downloads

### Quick Start

1. **Clone the Repository**
```bash
git clone https://github.com/your-org/hackerai-platform.git
cd hackerai-platform
```

2. **Run Deployment Script**
```bash
chmod +x deploy/hackerai-deploy.sh
./deploy/hackerai-deploy.sh --domain your-domain.com --ssl
```

3. **Access the Platform**
- API: `https://your-domain.com:8080`
- Documentation: `https://your-domain.com:8080/docs`
- Grafana: `https://your-domain.com:3000`
- Prometheus: `https://your-domain.com:9090`

### Manual Installation

#### 1. Environment Setup
```bash
# Create project directory
mkdir -p /opt/hackerai
cd /opt/hackerai

# Create environment file
cat > .env << EOF
POSTGRES_PASSWORD=your_secure_password
REDIS_PASSWORD=your_redis_password
MINIO_ROOT_PASSWORD=your_minio_password
HACKERAI_API_KEY=your_api_key
JWT_SECRET=your_jwt_secret
EOF
```

#### 2. Docker Compose Deployment
```bash
# Start core services
docker-compose -f docker/hackerai-platform/docker-compose.yml up -d

# Start tool containers
docker-compose -f docker/hackerai-platform/docker-compose.yml --profile tools up -d

# Check service status
docker-compose -f docker/hackerai-platform/docker-compose.yml ps
```

#### 3. SSL Configuration
```bash
# Using Let's Encrypt
certbot certonly --standalone -d your-domain.com
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem config/ssl/cert.pem
cp /etc/letsencrypt/live/your-domain.com/privkey.pem config/ssl/key.pem

# Restart Nginx
docker-compose restart nginx
```

## API Usage

### Authentication
All API endpoints require Bearer token authentication:
```bash
curl -H "Authorization: Bearer hackerai-api-key-2024" \
     https://your-domain.com:8080/api/v1/status
```

### Tool Execution

#### Basic Tool Execution
```bash
curl -X POST \
     -H "Authorization: Bearer hackerai-api-key-2024" \
     -H "Content-Type: application/json" \
     -d '{
       "tool_name": "nmap",
       "target": "192.168.1.1",
       "parameters": {
         "ports": "1-1000",
         "scan_type": "-sS -sV"
       }
     }' \
     https://your-domain.com:8080/api/v1/tools/execute
```

#### OSINT Data Collection
```bash
# Add OSINT target
curl -X POST \
     -H "Authorization: Bearer hackerai-api-key-2024" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "John Doe",
       "email": "john@example.com",
       "social_profiles": {
         "twitter": "@johndoe",
         "linkedin": "john-doe"
       }
     }' \
     https://your-domain.com:8080/api/v1/osint/target

# Collect data
curl -X POST \
     -H "Authorization: Bearer hackerai-api-key-2024" \
     https://your-domain.com:8080/api/v1/osint/{target_id}/collect
```

#### Comprehensive Assessment
```bash
curl -X POST \
     -H "Authorization: Bearer hackerai-api-key-2024" \
     -H "Content-Type: application/json" \
     -d '{
       "target": "example.com",
       "categories": ["osint", "network", "web"]
     }' \
     https://your-domain.com:8080/api/v1/assess
```

### Python SDK Example

```python
import asyncio
import aiohttp
import json

class HackerAIClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    async def execute_tool(self, tool_name, target, parameters=None):
        async with aiohttp.ClientSession() as session:
            data = {
                "tool_name": tool_name,
                "target": target,
                "parameters": parameters or {}
            }
            
            async with session.post(
                f"{self.base_url}/api/v1/tools/execute",
                headers=self.headers,
                json=data
            ) as response:
                return await response.json()
    
    async def run_assessment(self, target, categories=None):
        async with aiohttp.ClientSession() as session:
            data = {
                "target": target,
                "categories": categories or ["osint", "network", "web"]
            }
            
            async with session.post(
                f"{self.base_url}/api/v1/assess",
                headers=self.headers,
                json=data
            ) as response:
                return await response.json()

# Usage example
async def main():
    client = HackerAIClient("https://your-domain.com:8080", "hackerai-api-key-2024")
    
    # Execute nmap scan
    result = await client.execute_tool(
        "nmap", 
        "192.168.1.1",
        {"ports": "1-1000", "scan_type": "-sS"}
    )
    print("Nmap result:", result)
    
    # Run comprehensive assessment
    assessment = await client.run_assessment("example.com")
    print("Assessment result:", assessment)

asyncio.run(main())
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_PASSWORD` | PostgreSQL password | - |
| `REDIS_PASSWORD` | Redis password | - |
| `MINIO_ROOT_PASSWORD` | MinIO password | - |
| `HACKERAI_API_KEY` | API authentication key | - |
| `JWT_SECRET` | JWT signing secret | - |
| `HACKERAI_ENV` | Environment (dev/prod) | production |
| `HACKERAI_DOMAIN` | Platform domain | localhost |
| `SSL_ENABLED` | Enable SSL | false |
| `ENABLE_GPU` | Enable GPU support | false |
| `HACKERAI_MAX_CONCURRENT_TOOLS` | Max concurrent tools | 10 |
| `HACKERAI_LOG_LEVEL` | Logging level | INFO |

### Tool Configuration

Tools can be configured through YAML files in `config/tools/`:

```yaml
# config/tools/custom_tool.yaml
name: "custom-scanner"
category: "network_scanning"
description: "Custom network scanner"
version: "1.0.0"
executable_path: "/usr/bin/custom-scanner"
docker_image: "custom/scanner:latest"
parameters:
  target:
    type: "string"
    required: true
  ports:
    type: "string"
    default: "1-1000"
execution_mode: "docker"
```

### Resource Limits

Configure resource limits per tool category:

```yaml
# config/resources.yaml
osint:
  cpu_limit: "500m"
  memory_limit: "512Mi"
  concurrent_limit: 5

network:
  cpu_limit: "1000m"
  memory_limit: "1Gi"
  concurrent_limit: 3

password:
  cpu_limit: "2000m"
  memory_limit: "2Gi"
  gpu_limit: 1
  concurrent_limit: 2
```

## Monitoring & Observability

### Prometheus Metrics

The platform exposes comprehensive metrics:

- **Tool Execution Metrics**: Success rates, execution times, error counts
- **System Metrics**: CPU, memory, disk usage
- **API Metrics**: Request rates, response times, error rates
- **Business Metrics**: Assessments completed, data collected, threats identified

### Grafana Dashboards

Pre-built dashboards include:

- **Platform Overview**: System health and performance
- **Tool Performance**: Individual tool statistics
- **Security Metrics**: Threat detection and assessment results
- **Resource Usage**: Container resource utilization

### Alerting

Configurable alerts for:

- **Service Downtime**: Platform or tool unavailability
- **High Error Rates**: Elevated tool failure rates
- **Resource Exhaustion**: CPU, memory, or storage limits
- **Security Events**: Suspicious activities or threats

## Security Considerations

### Container Security

- **Non-root Users**: All containers run as non-root users
- **Read-only Filesystems**: Containers use read-only filesystems where possible
- **Resource Limits**: CPU, memory, and network restrictions
- **Network Isolation**: Tool containers in isolated networks
- **Seccomp Profiles**: System call filtering for security

### API Security

- **Authentication**: Bearer token-based authentication
- **Authorization**: Role-based access control
- **Rate Limiting**: API rate limiting per user and endpoint
- **Input Validation**: Comprehensive input sanitization
- **HTTPS**: TLS encryption for all communications

### Data Protection

- **Encryption**: Data encrypted at rest and in transit
- **Access Controls**: Role-based data access
- **Audit Logging**: Complete audit trail of all actions
- **Data Retention**: Configurable data retention policies
- **Privacy Compliance**: GDPR and CCPA compliant

## Scaling & Performance

### Horizontal Scaling

- **Load Balancing**: Multiple API instances behind load balancer
- **Container Orchestration**: Kubernetes support for auto-scaling
- **Database Scaling**: Read replicas and connection pooling
- **Caching**: Redis caching for frequently accessed data

### Performance Optimization

- **Async Processing**: Non-blocking tool execution
- **Connection Pooling**: Database and external API connection pooling
- **Caching Strategy**: Multi-level caching (memory, Redis, CDN)
- **Resource Management**: Intelligent resource allocation

### High Availability

- **Redundancy**: Multiple instances of critical services
- **Health Checks**: Comprehensive health monitoring
- **Failover**: Automatic failover for failed services
- **Backup**: Automated backup and recovery

## Troubleshooting

### Common Issues

#### 1. Container Startup Failures
```bash
# Check container logs
docker-compose logs hackerai-platform

# Check resource usage
docker stats

# Restart services
docker-compose restart
```

#### 2. Tool Execution Failures
```bash
# Check tool status
curl -H "Authorization: Bearer your-api-key" \
     https://your-domain.com:8080/api/v1/tools/nmap

# View execution logs
docker-compose logs hackerai-platform | grep "execution_id"

# Check tool container
docker exec -it hackerai-osint bash
```

#### 3. Database Connection Issues
```bash
# Check database status
docker-compose exec postgres pg_isready -U hackerai

# Test connection
docker-compose exec postgres psql -U hackerai -d hackerai

# Reset database
docker-compose down -v
docker-compose up -d postgres
```

#### 4. Performance Issues
```bash
# Check resource usage
docker stats

# Monitor API performance
curl -w "@curl-format.txt" -o /dev/null -s \
     https://your-domain.com:8080/health

# Analyze slow queries
docker-compose exec postgres psql -U hackerai -c \
    "SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"
```

### Debug Mode

Enable debug logging:
```bash
# Set debug environment
export HACKERAI_LOG_LEVEL=DEBUG

# Restart with debug
docker-compose down
docker-compose up -d

# View debug logs
docker-compose logs -f hackerai-platform
```

## Development

### Adding New Tools

1. **Create Tool Definition**
```python
# src/modules/tools/new_tool.py
from universal_tool_manager import ToolDefinition, ToolCategory

new_tool = ToolDefinition(
    name="new-tool",
    category=ToolCategory.NETWORK_SCANNING,
    description="Description of the tool",
    version="1.0.0",
    executable_path="/usr/bin/new-tool",
    docker_image="custom/new-tool:latest",
    parameters={
        "target": {"type": "string", "required": True},
        "option": {"type": "string", "default": "default_value"}
    }
)
```

2. **Create Dockerfile**
```dockerfile
# docker/tools/new/Dockerfile
FROM archlinux:latest
RUN pacman -Syu --noconfirm --needed new-tool
RUN useradd -m -u 1000 newuser
USER newuser
CMD ["/bin/bash"]
```

3. **Register Tool**
```python
# In UniversalToolManager.__init__
self.register_tool(new_tool)
```

### Custom Executors

Create custom execution environments:
```python
class CloudExecutor(ToolExecutor):
    async def execute(self, tool, target, parameters):
        # Implement cloud execution logic
        pass
    
    async def is_available(self):
        # Check cloud availability
        return True
```

### Testing

Run the test suite:
```bash
# Run all tests
python -m pytest tests/

# Run specific tests
python -m pytest tests/test_tool_manager.py

# Run with coverage
python -m pytest --cov=src tests/
```

## Contributing

### Development Setup

1. **Clone Repository**
```bash
git clone https://github.com/your-org/hackerai-platform.git
cd hackerai-platform
```

2. **Setup Development Environment**
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

3. **Run Tests**
```bash
pytest tests/
```

4. **Code Style**
```bash
black src/
flake8 src/
mypy src/
```

### Submitting Changes

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: https://docs.hackerai.com
- **Issues**: https://github.com/your-org/hackerai-platform/issues
- **Discussions**: https://github.com/your-org/hackerai-platform/discussions
- **Email**: support@hackerai.com

## Changelog

### Version 1.0.0
- Initial release
- Universal Tool Manager
- 50+ integrated security tools
- REST API with authentication
- Docker containerization
- Monitoring and alerting
- Comprehensive documentation

---

**HackerAI Platform** - Enterprise-Grade Security Tool Management System

Built for security professionals, by security professionals.
