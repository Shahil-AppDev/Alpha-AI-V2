#!/bin/bash
# AI-Driven Offensive Security Tool - Deployment Script

echo "🚀 Deploying AI-Driven Offensive Security Tool..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop and try again."
    exit 1
fi

# Build the main application image
echo "📦 Building main application image..."
docker build -f docker/Dockerfile -t ai-offensive-security:latest .

if [ $? -ne 0 ]; then
    echo "❌ Failed to build main application image"
    exit 1
fi

# Deploy LLM service
echo "🤖 Deploying LLM service..."
docker-compose -f docker/docker-compose.yml up -d llm-service

if [ $? -ne 0 ]; then
    echo "❌ Failed to deploy LLM service"
    exit 1
fi

# Wait for LLM service to be ready
echo "⏳ Waiting for LLM service to be ready..."
sleep 10

# Deploy main application
echo "🔧 Deploying main application..."
docker run -d \
    --name ai-offensive-security \
    --network ai-security-network \
    -e LLM_ENDPOINT=http://llm-service:8000/generate \
    -e LLM_API_KEY=test-key \
    -e LLM_MODEL=gpt-3.5-turbo \
    -e REQUIRE_HUMAN_APPROVAL=true \
    -e MAX_TOOL_CALLS=5 \
    -v $(pwd)/data:/app/data \
    -v $(pwd)/config:/app/config \
    -v $(pwd)/tools:/app/tools \
    ai-offensive-security:latest \
    --help

if [ $? -ne 0 ]; then
    echo "❌ Failed to deploy main application"
    exit 1
fi

# Verify deployment
echo "✅ Verifying deployment..."
sleep 5

# Check if services are running
if docker ps | grep -q "llm-service"; then
    echo "✅ LLM service is running"
else
    echo "❌ LLM service is not running"
fi

if docker ps | grep -q "ai-offensive-security"; then
    echo "✅ Main application is running"
else
    echo "❌ Main application is not running"
fi

echo "🎉 Deployment completed!"
echo ""
echo "📋 Service Status:"
docker ps --filter "name=llm-service" --filter "name=ai-offensive-security"
echo ""
echo "🔍 To test the deployment:"
echo "  docker exec -it ai-offensive-security python main.py --objective 'Perform OSINT on example.com'"
echo ""
echo "📊 To view logs:"
echo "  docker logs -f llm-service"
echo "  docker logs -f ai-offensive-security"
