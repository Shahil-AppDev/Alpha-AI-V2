# Enhanced AI Security Team Orchestrator - PowerShell Deployment Script

Write-Host "🚀 Deploying Enhanced AI Security Team Orchestrator..." -ForegroundColor Green
Write-Host ""
Write-Host "📋 This will deploy:" -ForegroundColor Cyan
Write-Host "  • Security Team Structure (Black Hat, Red Team, Blue Team, Purple Teams)" -ForegroundColor White
Write-Host "  • AI Agent Orchestrator with OpenRouter Integration" -ForegroundColor White
Write-Host "  • Team Workflow Engine" -ForegroundColor White
Write-Host "  • Comprehensive Security Tools" -ForegroundColor White
Write-Host "  • Monitoring & Analytics Dashboard" -ForegroundColor White
Write-Host ""

# Check if Docker is running
try {
    $dockerInfo = docker info 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Docker is not running. Please start Docker Desktop and try again." -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Host "❌ Docker is not installed or not running. Please install/start Docker Desktop." -ForegroundColor Red
    exit 1
}

Write-Host "✅ Docker is running" -ForegroundColor Green

# Check system resources
$memory = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB
$cores = (Get-CimInstance -ClassName Win32_Processor).NumberOfCores

Write-Host "📊 System Resources:" -ForegroundColor Cyan
Write-Host "  • Memory: $([math]::Round($memory, 1)) GB" -ForegroundColor White
Write-Host "  • CPU Cores: $cores" -ForegroundColor White

if ($memory -lt 16) {
    Write-Host "⚠️  Warning: Less than 16GB RAM detected. Performance may be degraded." -ForegroundColor Yellow
}

if ($cores -lt 8) {
    Write-Host "⚠️  Warning: Less than 8 CPU cores detected. Performance may be degraded." -ForegroundColor Yellow
}

Write-Host ""

# Check for required environment variables
$openRouterKey = $env:OPENROUTER_API_KEY
if (-not $openRouterKey) {
    Write-Host "⚠️  Warning: OPENROUTER_API_KEY environment variable not set." -ForegroundColor Yellow
    Write-Host "   AI features will be limited without OpenRouter API key." -ForegroundColor Yellow
    Write-Host "   Set it with: `$env:OPENROUTER_API_KEY = 'your-api-key'" -ForegroundColor Yellow
    Write-Host ""
}

# Create necessary directories
Write-Host "📁 Creating directories..." -ForegroundColor Yellow
$directories = @(
    "data/logs",
    "data/security-teams",
    "data/workflows",
    "data/exercises",
    "data/metrics",
    "config/security-teams",
    "config/workflows",
    "tools/blackarch",
    "tools/offensive",
    "tools/defensive",
    "tools/osint",
    "tools/password",
    "tools/social",
    "tools/teamdev",
    "backups",
    "monitoring"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  ✅ Created: $dir" -ForegroundColor Green
    }
}

Write-Host ""

# Generate configuration files
Write-Host "⚙️  Generating configuration files..." -ForegroundColor Yellow

# Security Teams Configuration
$teamsConfig = @"
security_teams:
  black_hat:
    members: 5
    risk_tolerance: "high"
    capabilities:
      - "zero_day_exploitation"
      - "custom_malware_development"
      - "apt_simulation"
      - "vulnerability_discovery"
    tools:
      - "metasploit"
      - "custom_exploits"
      - "malware_frameworks"
  
  red_team:
    members: 8
    risk_tolerance: "medium"
    capabilities:
      - "penetration_testing"
      - "vulnerability_assessment"
      - "adversary_emulation"
      - "attack_simulation"
    tools:
      - "metasploit"
      - "burp_suite"
      - "nmap"
      - "sqlmap"
  
  blue_team:
    members: 10
    risk_tolerance: "low"
    capabilities:
      - "threat_detection"
      - "incident_response"
      - "forensic_analysis"
      - "security_monitoring"
    tools:
      - "siem"
      - "ids_ips"
      - "volatility"
      - "wireshark"
  
  purple_team:
    members: 4
    risk_tolerance: "medium"
    capabilities:
      - "team_collaboration"
      - "strategy_development"
      - "exercise_planning"
      - "metrics_analysis"
    tools:
      - "collaboration_platforms"
      - "documentation_tools"
      - "analytics_platforms"

orchestrator:
  openrouter_api_key: "$($env:OPENROUTER_API_KEY ?? '')"
  max_concurrent_exercises: 5
  default_timeout: 3600
  auto_distribute: true

workflows:
  collaborative_exercise:
    enabled: true
    frequency: "quarterly"
    duration: "1_week"
  
  incident_response:
    enabled: true
    response_time_target: "1_hour"
    recovery_time_target: "24_hours"
  
  threat_intelligence:
    enabled: true
    collection_frequency: "daily"
    analysis_frequency: "weekly"

monitoring:
  enabled: true
  metrics_interval: 60
  alert_thresholds:
    cpu: 90
    memory: 85
    disk: 80
"@

Set-Content -Path "config/security-teams/teams.yaml" -Value $teamsConfig
Write-Host "  ✅ Generated: config/security-teams/teams.yaml" -ForegroundColor Green

# Build the main application image
Write-Host "📦 Building main application image..." -ForegroundColor Yellow
docker build -f docker/security-orchestrator/Dockerfile -t security-orchestrator:latest .

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to build main application image" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Main application image built successfully" -ForegroundColor Green

# Build tool images
Write-Host "🛠️  Building security tool images..." -ForegroundColor Yellow

$toolImages = @(
    "blackarch-tools",
    "offensive-tools", 
    "defensive-tools",
    "osint-tools",
    "password-tools",
    "social-tools",
    "teamdev-tools"
)

foreach ($toolImage in $toolImages) {
    Write-Host "  🔨 Building $toolImage..." -ForegroundColor Cyan
    $dockerfile = "docker/tools/$($toolImage -replace '-tools$')/Dockerfile"
    if (Test-Path $dockerfile) {
        docker build -f $dockerfile -t "$toolImage`:latest docker/tools/$($toolImage -replace '-tools$')/
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    ✅ $toolImage built successfully" -ForegroundColor Green
        } else {
            Write-Host "    ⚠️  $toolImage build failed, continuing..." -ForegroundColor Yellow
        }
    } else {
        Write-Host "    ⚠️  Dockerfile not found for $toolImage" -ForegroundColor Yellow
    }
}

Write-Host ""

# Deploy infrastructure services
Write-Host "🏗️  Deploying infrastructure services..." -ForegroundColor Yellow
docker-compose -f docker/security-orchestrator/docker-compose.yml up -d postgres redis elasticsearch prometheus grafana

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to deploy infrastructure services" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Infrastructure services deployed" -ForegroundColor Green

# Wait for infrastructure to be ready
Write-Host "⏳ Waiting for infrastructure services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# Deploy security tools
Write-Host "🛡️  Deploying security tools..." -ForegroundColor Yellow
docker-compose -f docker/security-orchestrator/docker-compose.yml up -d blackarch-tools offensive-tools defensive-tools osint-tools password-tools social-tools teamdev-tools

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to deploy security tools" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Security tools deployed" -ForegroundColor Green

# Deploy main orchestrator
Write-Host "🧠 Deploying Security Team Orchestrator..." -ForegroundColor Yellow
$pwd = (Get-Location).Path
docker run -d `
    --name security-orchestrator `
    --network security-net `
    -p 8080:8080 `
    -p 8443:8443 `
    -e OPENROUTER_API_KEY="$($env:OPENROUTER_API_KEY ?? '')" `
    -e DATABASE_URL="postgresql://orchestrator:$($env:POSTGRES_PASSWORD ?? 'orchestrator_pass')@postgres:5432/orchestrator_db" `
    -e REDIS_URL="redis://redis:6379/0" `
    -e ELASTICSEARCH_URL="http://elasticsearch:9200" `
    -e LOG_LEVEL="INFO" `
    -e ENVIRONMENT="production" `
    -e MAX_CONCURRENT_EXERCISES="5" `
    -e REQUIRE_HUMAN_APPROVAL="true" `
    -v "${pwd}/data:/app/data" `
    -v "${pwd}/config:/app/config" `
    -v "${pwd}/src:/app/src" `
    -v "${pwd}/tools:/app/tools" `
    --restart unless-stopped `
    security-orchestrator:latest

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to deploy Security Team Orchestrator" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Security Team Orchestrator deployed" -ForegroundColor Green

# Deploy monitoring and supporting services
Write-Host "📊 Deploying monitoring services..." -ForegroundColor Yellow
docker-compose -f docker/security-orchestrator/docker-compose.yml up -d kibana nginx security-monitor backup-service

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to deploy monitoring services" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Monitoring services deployed" -ForegroundColor Green

# Wait for all services to be ready
Write-Host "⏳ Waiting for all services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Initialize database
Write-Host "🗄️  Initializing database..." -ForegroundColor Yellow
docker exec security-orchestrator python scripts/migrate_database.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠️  Database initialization failed, but continuing..." -ForegroundColor Yellow
} else {
    Write-Host "✅ Database initialized" -ForegroundColor Green
}

# Create default admin user
Write-Host "👤 Creating default admin user..." -ForegroundColor Yellow
docker exec security-orchestrator python scripts/create_admin.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠️  Admin user creation failed, but continuing..." -ForegroundColor Yellow
} else {
    Write-Host "✅ Admin user created" -ForegroundColor Green
}

# Verify deployment
Write-Host "✅ Verifying deployment..." -ForegroundColor Green
Start-Sleep -Seconds 10

# Check if services are running
Write-Host ""
Write-Host "📋 Service Status:" -ForegroundColor Cyan
docker ps --filter "name=security-orchestrator" --filter "name=postgres" --filter "name=redis" --filter "name=elasticsearch" --format "table { { .Names } }\t { { .Status } }\t { { .Ports } }"

Write-Host ""
Write-Host "🎉 Enhanced Security Team Orchestrator deployment completed!" -ForegroundColor Green
Write-Host ""
Write-Host "🌐 Access Points:" -ForegroundColor Cyan
Write-Host "  • Security Orchestrator API: http://localhost:8080" -ForegroundColor White
Write-Host "  • Security Orchestrator UI: http://localhost:8080/docs" -ForegroundColor White
Write-Host "  • Grafana Dashboard: http://localhost:3000" -ForegroundColor White
Write-Host "  • Kibana Logs: http://localhost:5601" -ForegroundColor White
Write-Host "  • Prometheus Metrics: http://localhost:9090" -ForegroundColor White
Write-Host ""
Write-Host "🔧 Default Credentials:" -ForegroundColor Cyan
Write-Host "  • Grafana: admin / $($env:GRAFANA_PASSWORD ?? 'admin')" -ForegroundColor White
Write-Host "  • PostgreSQL: orchestrator / $($env:POSTGRES_PASSWORD ?? 'orchestrator_pass')" -ForegroundColor White
Write-Host ""
Write-Host "🚀 Quick Start Commands:" -ForegroundColor Cyan
Write-Host "  • View orchestrator logs:" -ForegroundColor White
Write-Host "    docker logs -f security-orchestrator" -ForegroundColor Gray
Write-Host ""
Write-Host "  • Test team status:" -ForegroundColor White
Write-Host "    curl http://localhost:8080/api/v1/teams/status" -ForegroundColor Gray
Write-Host ""
Write-Host "  • Create exercise:" -ForegroundColor White
Write-Host "    curl -X POST http://localhost:8080/api/v1/exercises -H 'Content-Type: application/json' -d '{\"name\":\"Test Exercise\",\"type\":\"collaborative_exercise\"}'" -ForegroundColor Gray
Write-Host ""
Write-Host "  • View all services:" -ForegroundColor White
Write-Host "    docker-compose -f docker/security-orchestrator/docker-compose.yml ps" -ForegroundColor Gray
Write-Host ""
Write-Host "📚 Documentation:" -ForegroundColor Cyan
Write-Host "  • Comprehensive Guide: COMPREHENSIVE_SECURITY_TEAM_GUIDE.md" -ForegroundColor White
Write-Host "  • API Documentation: http://localhost:8080/docs" -ForegroundColor White
Write-Host "  • Architecture Overview: docs/architecture.md" -ForegroundColor White
Write-Host ""
Write-Host "⚠️  Important Security Notice:" -ForegroundColor Yellow
Write-Host "  This platform is for authorized security testing only." -ForegroundColor White
Write-Host "  Ensure you have proper authorization before conducting any security assessments." -ForegroundColor White
Write-Host ""
