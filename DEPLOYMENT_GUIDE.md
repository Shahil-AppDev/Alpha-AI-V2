# AI-Driven Offensive Security Tool - Deployment Guide

## 🚀 Deployment Overview

This guide provides step-by-step instructions for deploying the AI-driven offensive security tool with all components including LLM services and the main agent application.

## 📋 Prerequisites

### Required Software
- **Docker Desktop** (latest version)
- **Git** for cloning repositories
- **PowerShell** (Windows) or **Bash** (Linux/Mac)

### System Requirements
- **RAM**: 8GB minimum (16GB recommended for LLM operations)
- **Storage**: 20GB free space
- **Network**: Internet connection for cloning repositories

## 🔧 Deployment Methods

### Method 1: Automated Deployment (Recommended)

#### Windows PowerShell
```powershell
# Navigate to project directory
cd "C:\Users\DarkNode\Desktop\Projet Web\Alpha AI"

# Run deployment script
.\deploy.ps1
```

#### Linux/Mac Bash
```bash
# Navigate to project directory
cd "/path/to/Alpha AI"

# Make script executable
chmod +x deploy.sh

# Run deployment script
./deploy.sh
```

### Method 2: Manual Deployment

#### Step 1: Start Docker Desktop
1. Launch Docker Desktop from your applications
2. Wait for it to fully start (Docker icon should be green)
3. Verify Docker is running:
   ```bash
   docker info
   ```

#### Step 2: Build Main Application Image
```bash
# Build the main application with LLM source code
docker build -f docker/Dockerfile -t ai-offensive-security:latest .
```

#### Step 3: Deploy LLM Service
```bash
# Deploy the mock LLM service
docker-compose -f docker/docker-compose.yml up -d llm-service

# Wait for service to be ready
sleep 10

# Verify LLM service is running
docker ps | grep llm-service
```

#### Step 4: Deploy Main Application
```bash
# Create network if it doesn't exist
docker network create ai-security-network

# Run the main application
docker run -d \
    --name ai-offensive-security \
    --network ai-security-network \
    -e LLM_ENDPOINT=http://llm-service:8000/generate \
    -e LLM_API_KEY=test-key \
    -e LLM_MODEL=gpt-3.5-turbo \
    -e REQUIRE_HUMAN_APPROVAL=true \
    -e MAX_TOOL_CALLS=5 \
    -v "$(pwd)/data:/app/data" \
    -v "$(pwd)/config:/app/config" \
    -v "$(pwd)/tools:/app/tools" \
    ai-offensive-security:latest \
    --help
```

## 🔍 Verification Steps

### Check Service Status
```bash
# List running containers
docker ps --filter "name=llm-service" --filter "name=ai-offensive-security"

# Check container logs
docker logs -f llm-service
docker logs -f ai-offensive-security
```

### Test LLM Service
```bash
# Test LLM endpoint
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello"}]}'
```

### Test Main Application
```bash
# Run a test security analysis
docker exec -it ai-offensive-security python main.py \
  --objective "Perform OSINT on example.com" \
  --clear-memory
```

## 📊 Expected Output

### Successful Deployment Should Show:
```
🚀 Deploying AI-Driven Offensive Security Tool...
📦 Building main application image...
🤖 Deploying LLM service...
⏳ Waiting for LLM service to be ready...
🔧 Deploying main application...
✅ Verifying deployment...
✅ LLM service is running
✅ Main application is running
🎉 Deployment completed!
```

### Service Status:
```
CONTAINER ID   IMAGE                    COMMAND                  CREATED         STATUS         PORTS                    NAMES
xxxxxxxxxxxx   llm-service              "python server.py"       2 minutes ago   Up 2 minutes   0.0.0.0:8000->8000/tcp   llm-service
xxxxxxxxxxxx   ai-offensive-security    "python main.py --help"   1 minute ago    Up 1 minute                             ai-offensive-security
```

## 🛠️ Troubleshooting

### Common Issues

#### Docker Desktop Not Running
**Error**: `Docker Desktop is unable to start`
**Solution**: 
1. Restart Docker Desktop
2. Check system resources
3. Verify Docker installation

#### Build Failures
**Error**: `failed to build: failed to receive status`
**Solution**:
1. Check internet connection
2. Clear Docker cache: `docker system prune -a`
3. Restart Docker Desktop

#### Network Issues
**Error**: `network ai-security-network not found`
**Solution**: Create network manually:
```bash
docker network create ai-security-network
```

#### Port Conflicts
**Error**: `port 8000 already in use`
**Solution**: Change port in docker-compose.yml or stop conflicting service

### Debug Commands
```bash
# Check Docker system
docker system info

# Check container logs
docker logs <container_name>

# Inspect container
docker inspect <container_name>

# Access container shell
docker exec -it <container_name> /bin/bash

# Clean up failed deployments
docker-compose -f docker/docker-compose.yml down -v
docker system prune -a
```

## 📁 Directory Structure After Deployment

```
/opt/llms/                    # LLM source code (in container)
├── mixtral-7b/              # Mixtral 7B source
├── llama-3b/                # Llama 3B source
├── gpt-j/                   # GPT-J source
└── vicuna/                  # Vicuna source

/app/                        # Application directory (in container)
├── src/                     # Source code
├── main.py                  # Main application
├── data/                    # Data storage (mounted)
├── config/                  # Configuration (mounted)
└── tools/                   # Tools and utilities (mounted)
```

## 🔒 Security Considerations

### Production Deployment
- Use non-root users in containers
- Implement proper network isolation
- Set resource limits
- Enable audit logging
- Use secrets management for API keys

### Network Security
- Use internal networks for service communication
- Expose only necessary ports
- Implement firewall rules
- Use HTTPS for external communication

### Data Protection
- Encrypt sensitive data at rest
- Implement proper backup strategies
- Use secure volume mounting
- Regular security updates

## 🚀 Next Steps

After successful deployment:

1. **Configure Model Weights**: Download and configure LLM model weights
2. **Customize Configuration**: Modify config files for your environment
3. **Test Security Features**: Verify human approval system
4. **Monitor Performance**: Set up monitoring and alerting
5. **Scale Deployment**: Consider multi-node deployment for production

## 📞 Support

For deployment issues:
1. Check Docker Desktop status
2. Review container logs
3. Verify network connectivity
4. Check system resources
5. Consult troubleshooting section above

The AI-driven offensive security tool is now ready for deployment and testing!
