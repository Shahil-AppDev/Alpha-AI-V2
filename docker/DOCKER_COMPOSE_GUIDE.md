# Docker Compose Configuration Guide

## ✅ Complete Docker Compose Setup

The `docker-compose-new.yml` file provides a comprehensive orchestration setup for the AI-driven offensive security tool with LLM services and agent application.

## 📋 **Service Architecture**

### 1. **LLM Service** (`llm-service`)
- **Purpose**: Provides AI language model capabilities
- **Build Context**: Uses the main Dockerfile with all hacking tools and LLM packages
- **Port Mapping**: `8000:8000` for API access
- **GPU Support**: Configurable with NVIDIA runtime
- **Health Checks**: Automated service monitoring

### 2. **Agent Application** (`agent-app`)
- **Purpose**: Main AI security analysis tool
- **Dependencies**: Requires healthy LLM service
- **Volume Mounts**: Code, config, data, and tools
- **Environment**: Configurable LLM endpoint and security settings
- **GPU Support**: Optional GPU acceleration

## 🐳 **Service Configuration**

### LLM Service Configuration
```yaml
llm-service:
  build:
    context: ..
    dockerfile: docker/Dockerfile
  container_name: ai-offensive-llm-service
  ports:
    - "8000:8000"
  environment:
    - LLM_MODEL=gpt-3.5-turbo
    - LLM_API_KEY=test-key
    - MAX_TOKENS=2048
    - TEMPERATURE=0.7
```

### Agent Application Configuration
```yaml
agent-app:
  build:
    context: ..
    dockerfile: docker/Dockerfile
  container_name: ai-offensive-agent-app
  depends_on:
    llm-service:
      condition: service_healthy
  environment:
    - LLM_API_ENDPOINT=http://llm-service:8000/generate
    - REQUIRE_HUMAN_APPROVAL=true
    - MAX_TOOL_CALLS=10
```

## 🗂️ **Volume Mounts**

### Persistent Data Storage
- **`../data:/app/data`** - Analysis results, memory, and temporary files
- **`../config:/app/config:ro`** - Configuration files (read-only)
- **`../src:/app/src:ro`** - Agent source code (read-only for security)
- **`../tools:/app/tools:ro`** - Security tools and scripts (read-only)

### LLM Weights Management
- **`./llm-weights:/opt/llm/weights:ro`** - Model weights directory
- **Note**: Model weights must be managed separately due to size and licensing

### Logging and Monitoring
- **`../data/logs:/app/logs`** - Application logs
- **Health Checks**: Automated service monitoring
- **Restart Policy**: `unless-stopped` for high availability

## 🚀 **GPU Configuration**

### Enable GPU Support
```yaml
# Uncomment in both services
deploy:
  resources:
    reservations:
      devices:
        - driver: nvidia
          count: all
          capabilities: [gpu]
```

### GPU Prerequisites
1. **NVIDIA Docker Runtime**: Install `nvidia-docker2`
2. **GPU Drivers**: Ensure compatible NVIDIA drivers
3. **CUDA Support**: Verify CUDA installation
4. **Test GPU**: `docker run --rm --gpus all nvidia/cuda:11.0-base nvidia-smi`

### CPU-Only Deployment
- Keep GPU sections commented out
- Uses CPU-optimized PyTorch installation
- Reduced image size and resource requirements

## 🔧 **Network Configuration**

### Custom Network
```yaml
networks:
  ai-security-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### Service Communication
- **Internal DNS**: Services communicate via container names
- **Port Exposure**: Only LLM service exposed to host
- **Security**: Agent service isolated from external access

## 📊 **Environment Variables**

### LLM Configuration
- `LLM_API_ENDPOINT` - Points to LLM service
- `LLM_MODEL` - Model identifier
- `LLM_API_KEY` - Authentication key
- `MAX_TOKENS` - Response token limit
- `TEMPERATURE` - Model creativity setting

### Agent Configuration
- `REQUIRE_HUMAN_APPROVAL` - Human oversight for critical actions
- `MAX_TOOL_CALLS` - Tool call limit per session
- `LOG_LEVEL` - Logging verbosity
- `ENABLE_AUDIT_LOGGING` - Comprehensive audit trail
- `SESSION_TIMEOUT` - Session duration limit

## 🛠️ **Usage Examples**

### Start All Services
```bash
docker-compose -f docker-compose-new.yml up -d
```

### Start Individual Services
```bash
# Start only LLM service
docker-compose -f docker-compose-new.yml up -d llm-service

# Start only agent application
docker-compose -f docker-compose-new.yml up -d agent-app
```

### View Logs
```bash
# View all service logs
docker-compose -f docker-compose-new.yml logs -f

# View specific service logs
docker-compose -f docker-compose-new.yml logs -f llm-service
docker-compose -f docker-compose-new.yml logs -f agent-app
```

### Stop Services
```bash
docker-compose -f docker-compose-new.yml down
```

### Scale Services
```bash
# Scale agent application for load balancing
docker-compose -f docker-compose-new.yml up -d --scale agent-app=3
```

## 🔍 **Health Monitoring**

### Health Check Configuration
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

### Monitoring Commands
```bash
# Check service status
docker-compose -f docker-compose-new.yml ps

# Check health status
docker inspect ai-offensive-llm-service | grep Health -A 5
docker inspect ai-offensive-agent-app | grep Health -A 5
```

## 🗄️ **Optional Services**

### Database Service (PostgreSQL)
```yaml
# Uncomment in docker-compose.yml
database:
  image: postgres:15-alpine
  environment:
    - POSTGRES_DB=ai_security
    - POSTGRES_USER=ai_user
    - POSTGRES_PASSWORD=secure_password
  volumes:
    - postgres_data:/var/lib/postgresql/data
```

### Redis Cache Service
```yaml
# Uncomment in docker-compose.yml
redis:
  image: redis:7-alpine
  volumes:
    - redis_data:/data
```

## 🔒 **Security Considerations**

### Volume Security
- **Read-Only Mounts**: Source code and tools mounted read-only
- **Data Isolation**: Separate volume for sensitive data
- **Permission Management**: Proper file permissions on mounts

### Network Security
- **Internal Network**: Services communicate via private network
- **Port Exposure**: Minimal external port exposure
- **Service Isolation**: Agent service not exposed externally

### Environment Security
- **API Keys**: Use environment variables for sensitive data
- **Configuration**: Separate config files for different environments
- **Audit Logging**: Comprehensive logging for security monitoring

## 📝 **Configuration Files**

### Environment File (.env)
```bash
# .env file
LLM_API_KEY=your_actual_api_key
LLM_MODEL=gpt-4
MAX_TOKENS=4096
TEMPERATURE=0.7
REQUIRE_HUMAN_APPROVAL=true
MAX_TOOL_CALLS=15
LOG_LEVEL=INFO
ENABLE_AUDIT_LOGGING=true
```

### Override File (docker-compose.override.yml)
```yaml
# For development overrides
version: '3.8'
services:
  agent-app:
    environment:
      - LOG_LEVEL=DEBUG
    volumes:
      - ../src:/app/src  # Read-write for development
```

## 🚀 **Production Deployment**

### Production Configuration
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  llm-service:
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 8G
          cpus: '4'
        reservations:
          memory: 4G
          cpus: '2'
  
  agent-app:
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 4G
          cpus: '2'
```

### Deployment Commands
```bash
# Deploy to production
docker-compose -f docker-compose-new.yml -f docker-compose.prod.yml up -d

# Update deployment
docker-compose -f docker-compose-new.yml -f docker-compose.prod.yml up -d --force-recreate
```

The comprehensive Docker Compose configuration provides a robust, scalable, and secure deployment solution for the AI-driven offensive security tool with full LLM integration and hacking tool capabilities.
