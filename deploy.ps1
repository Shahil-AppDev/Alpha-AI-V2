# AI-Driven Offensive Security Tool - PowerShell Deployment Script

Write-Host "🚀 Deploying AI-Driven Offensive Security Tool..." -ForegroundColor Green

# Check if Docker is running
try {
    $dockerInfo = docker info 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Docker is not running. Please start Docker Desktop and try again." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Docker is not installed or not running. Please install/start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Build the main application image
Write-Host "📦 Building main application image..." -ForegroundColor Yellow
docker build -f docker/Dockerfile -t ai-offensive-security:latest .

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to build main application image" -ForegroundColor Red
    exit 1
}

# Deploy LLM service
Write-Host "🤖 Deploying LLM service..." -ForegroundColor Yellow
docker-compose -f docker/docker-compose.yml up -d llm-service

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to deploy LLM service" -ForegroundColor Red
    exit 1
}

# Wait for LLM service to be ready
Write-Host "⏳ Waiting for LLM service to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Deploy main application
Write-Host "🔧 Deploying main application..." -ForegroundColor Yellow
$pwd = (Get-Location).Path
docker run -d `
    --name ai-offensive-security `
    --network ai-security-network `
    -e LLM_ENDPOINT=http://llm-service:8000/generate `
    -e LLM_API_KEY=test-key `
    -e LLM_MODEL=gpt-3.5-turbo `
    -e REQUIRE_HUMAN_APPROVAL=true `
    -e MAX_TOOL_CALLS=5 `
    -v "${pwd}/data:/app/data" `
    -v "${pwd}/config:/app/config" `
    -v "${pwd}/tools:/app/tools" `
    ai-offensive-security:latest `
    --help

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to deploy main application" -ForegroundColor Red
    exit 1
}

# Verify deployment
Write-Host "✅ Verifying deployment..." -ForegroundColor Green
Start-Sleep -Seconds 5

# Check if services are running
$llmService = docker ps --filter "name=llm-service" --format "table {{.Names}}"
$mainApp = docker ps --filter "name=ai-offensive-security" --format "table {{.Names}}"

if ($llmService -like "*llm-service*") {
    Write-Host "✅ LLM service is running" -ForegroundColor Green
} else {
    Write-Host "❌ LLM service is not running" -ForegroundColor Red
}

if ($mainApp -like "*ai-offensive-security*") {
    Write-Host "✅ Main application is running" -ForegroundColor Green
} else {
    Write-Host "❌ Main application is not running" -ForegroundColor Red
}

Write-Host "🎉 Deployment completed!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Service Status:" -ForegroundColor Cyan
docker ps --filter "name=llm-service" --filter "name=ai-offensive-security"
Write-Host ""
Write-Host "🔍 To test the deployment:" -ForegroundColor Cyan
Write-Host "  docker exec -it ai-offensive-security python main.py --objective 'Perform OSINT on example.com'"
Write-Host ""
Write-Host "📊 To view logs:" -ForegroundColor Cyan
Write-Host "  docker logs -f llm-service"
Write-Host "  docker logs -f ai-offensive-security"
