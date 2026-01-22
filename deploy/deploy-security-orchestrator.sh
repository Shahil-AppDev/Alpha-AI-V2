#!/bin/bash

# Enhanced Security Orchestrator Deployment Script
# This script deploys the complete security orchestrator platform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_DIR="$PROJECT_DIR/docker/security-orchestrator"
CONFIG_DIR="$PROJECT_DIR/config"

# Default values
ENVIRONMENT="production"
DOMAIN="security-orchestrator.local"
SSL_ENABLED=false
BACKUP_ENABLED=false
MONITORING_ENABLED=true
AUTO_UPDATE=false

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    # Check available disk space (minimum 50GB)
    available_space=$(df / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 52428800 ]; then
        log_warning "Less than 50GB disk space available. Deployment may fail."
    fi
    
    # Check available memory (minimum 8GB)
    available_memory=$(free -m | awk 'NR==2{printf "%.0f", $7}')
    if [ "$available_memory" -lt 8192 ]; then
        log_warning "Less than 8GB RAM available. Performance may be degraded."
    fi
    
    log_success "Prerequisites check completed"
}

setup_environment() {
    log_info "Setting up environment..."
    
    # Create necessary directories
    mkdir -p "$COMPOSE_DIR/config"
    mkdir -p "$COMPOSE_DIR/logs"
    mkdir -p "$COMPOSE_DIR/data"
    mkdir -p "$COMPOSE_DIR/nginx"
    mkdir -p "$COMPOSE_DIR/prometheus"
    mkdir -p "$COMPOSE_DIR/grafana"
    mkdir -p "$COMPOSE_DIR/backups"
    mkdir -p "$COMPOSE_DIR/monitoring/config"
    mkdir -p "$COMPOSE_DIR/tools/blackarch/config"
    mkdir -p "$COMPOSE_DIR/tools/offensive/config"
    mkdir -p "$COMPOSE_DIR/tools/defensive/config"
    mkdir -p "$COMPOSE_DIR/tools/osint/config"
    mkdir -p "$COMPOSE_DIR/tools/password/config"
    mkdir -p "$COMPOSE_DIR/tools/social/config"
    mkdir -p "$COMPOSE_DIR/tools/tooldev/workspace"
    
    # Generate environment file
    cat > "$COMPOSE_DIR/.env" << EOF
# Security Orchestrator Environment Configuration
OPENROUTER_API_KEY=${OPENROUTER_API_KEY}
POSTGRES_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)
GRAFANA_PASSWORD=$(openssl rand -base64 32)

# Domain Configuration
DOMAIN=$DOMAIN
SSL_ENABLED=$SSL_ENABLED

# Backup Configuration
BACKUP_ENABLED=$BACKUP_ENABLED
BACKUP_SCHEDULE=${BACKUP_SCHEDULE:-0 2 * * *}
S3_BUCKET=${S3_BUCKET:-}
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}

# Monitoring Configuration
MONITORING_ENABLED=$MONITORING_ENABLED

# Update Configuration
AUTO_UPDATE=$AUTO_UPDATE
UPDATE_SCHEDULE=${UPDATE_SCHEDULE:-0 3 * * 0}

# Security Configuration
ENVIRONMENT=$ENVIRONMENT
LOG_LEVEL=${LOG_LEVEL:-INFO}
MAX_CONCURRENT_TASKS=${MAX_CONCURRENT_TASKS:-10}
TASK_TIMEOUT=${TASK_TIMEOUT:-3600}
EOF
    
    # Generate configuration files
    generate_config_files
    
    log_success "Environment setup completed"
}

generate_config_files() {
    log_info "Generating configuration files..."
    
    # Main orchestrator configuration
    cat > "$COMPOSE_DIR/config/orchestrator.yaml" << EOF
orchestrator:
  name: "Security Orchestrator"
  version: "1.0.0"
  environment: "$ENVIRONMENT"
  debug: false
  log_level: "$LOG_LEVEL"

openrouter:
  api_key: "\${OPENROUTER_API_KEY}"
  models:
    reasoning: "anthropic/claude-3-opus"
    planning: "mistralai/mistral-7b-instruct"
    analysis: "google/palm-2"
    coding: "codellama/codellama-34b-instruct"
  timeout: 60
  max_tokens: 4000

agents:
  max_concurrent: ${MAX_CONCURRENT_TASKS}
  default_timeout: ${TASK_TIMEOUT}
  retry_attempts: 3
  retry_delay: 5

tasks:
  max_queue_size: 1000
  priority_levels: 5
  auto_distribute: true
  cleanup_completed: true
  cleanup_interval: 3600

resources:
  cpu_limit: 80
  memory_limit: 80
  network_limit: 100
  disk_limit: 90

monitoring:
  enabled: $MONITORING_ENABLED
  metrics_interval: 60
  alert_thresholds:
    cpu: 90
    memory: 90
    disk: 85
    task_failure_rate: 10
    agent_offline_count: 3

security:
  encryption_at_rest: true
  encryption_in_transit: true
  audit_logging: true
  session_timeout: 3600
  max_login_attempts: 5
  password_policy:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_symbols: true

backup:
  enabled: $BACKUP_ENABLED
  schedule: "$BACKUP_SCHEDULE"
  retention_days: 30
  compress: true
  encrypt: true

updates:
  auto_update: $AUTO_UPDATE
  schedule: "$UPDATE_SCHEDULE"
  notify_updates: true
  backup_before_update: true
EOF

    # Agent configuration
    cat > "$COMPOSE_DIR/config/agents.yaml" << EOF
agents:
  offensive:
    count: 2
    risk_tolerance: "high"
    tools:
      - "metasploit"
      - "nmap"
      - "sqlmap"
      - "nikto"
      - "gobuster"
      - "hydra"
      - "john"
      - "hashcat"
    capabilities:
      - "exploitation"
      - "payload_generation"
      - "vulnerability_scanning"
      - "privilege_escalation"
      - "lateral_movement"
      - "persistence"
    resources:
      cpu: 70
      memory: "8GB"
      gpu: false

  defensive:
    count: 2
    risk_tolerance: "medium"
    tools:
      - "snort"
      - "wireshark"
      - "volatility"
      - "ossec"
      - "suricata"
    capabilities:
      - "threat_detection"
      - "incident_response"
      - "forensics"
      - "monitoring"
      - "analysis"
      - "mitigation"
    resources:
      cpu: 50
      memory: "4GB"
      gpu: false

  osint:
    count: 1
    risk_tolerance: "low"
    tools:
      - "maltego"
      - "theharvester"
      - "spiderfoot"
      - "recon-ng"
      - "dnsrecon"
    capabilities:
      - "data_collection"
      - "analysis"
      - "reporting"
      - "reconnaissance"
      - "intelligence_gathering"
    resources:
      cpu: 30
      memory: "2GB"
      gpu: false

  social_engineering:
    count: 1
    risk_tolerance: "medium"
    tools:
      - "gophish"
      - "king_phisher"
      - "setoolkit"
      - "evilginx"
    capabilities:
      - "phishing"
      - "pretexting"
      - "baiting"
      - "impersonation"
      - "psychological_manipulation"
    resources:
      cpu: 40
      memory: "3GB"
      gpu: false

  password_cracking:
    count: 2
    risk_tolerance: "medium"
    tools:
      - "hashcat"
      - "john_the_ripper"
      - "hydra"
      - "medusa"
    capabilities:
      - "brute_force"
      - "dictionary_attack"
      - "rainbow_tables"
      - "hash_cracking"
      - "credential_recovery"
    resources:
      cpu: 90
      memory: "16GB"
      gpu: true

  tool_development:
    count: 1
    risk_tolerance: "high"
    tools:
      - "python"
      - "metasploit_framework"
      - "custom_compilers"
      - "debuggers"
    capabilities:
      - "malware_creation"
      - "exploit_development"
      - "tool_modification"
      - "automation"
      - "customization"
    resources:
      cpu: 60
      memory: "6GB"
      gpu: false
EOF

    # Tools configuration
    cat > "$COMPOSE_DIR/config/tools.yaml" << EOF
tools:
  metasploit:
    enabled: true
    config_file: "/opt/metasploit-framework/config/database.yml"
    workspace: "default"
    auto_update: false
    
  nmap:
    enabled: true
    default_options: "-sS -sV -O"
    timing_template: "T4"
    
  sqlmap:
    enabled: true
    default_options: "--batch --random-agent"
    risk_level: 1
    level: 1
    
  nikto:
    enabled: true
    default_options: "-Tuning 9"
    
  hashcat:
    enabled: true
    workload_profile: 3
    optimized_kernel_enable: true
    
  john:
    enabled: true
    format: "all"
    
  hydra:
    enabled: true
    threads: 16
    wait_time: 5
    
  wireshark:
    enabled: true
    interface: "any"
    capture_filter: ""
    
  snort:
    enabled: true
    config_file: "/etc/snort/snort.conf"
    interface: "eth0"
    
  theharvester:
    enabled: true
    sources: "baidu,bing,google,duckduckgo"
    limit: 500
    
  spiderfoot:
    enabled: true
    modules: "all"
    
  gophish:
    enabled: true
    listen_url: "https://localhost:3333"
    
  setoolkit:
    enabled: true
    webattack: true
    payload: "custom"
EOF

    # Nginx configuration
    cat > "$COMPOSE_DIR/nginx/nginx.conf" << EOF
events {
    worker_connections 1024;
}

http {
    upstream security-orchestrator {
        server security-orchestrator:8080;
    }
    
    server {
        listen 80;
        server_name $DOMAIN;
        
        # Redirect to HTTPS if SSL is enabled
        if ($SSL_ENABLED = true) {
            return 301 https://\$server_name\$request_uri;
        }
        
        location / {
            proxy_pass http://security-orchestrator;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }
    
EOF

    if [ "$SSL_ENABLED" = true ]; then
        cat >> "$COMPOSE_DIR/nginx/nginx.conf" << EOF
    server {
        listen 443 ssl http2;
        server_name $DOMAIN;
        
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        
        location / {
            proxy_pass http://security-orchestrator;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }
EOF
    fi

    cat >> "$COMPOSE_DIR/nginx/nginx.conf" << EOF
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Hide server version
    server_tokens off;
}
EOF

    # Prometheus configuration
    cat > "$COMPOSE_DIR/prometheus/prometheus.yml" << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'security-orchestrator'
    static_configs:
      - targets: ['security-orchestrator:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s
    
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']
    
  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
    
  - job_name: 'elasticsearch'
    static_configs:
      - targets: ['elasticsearch:9200']
    
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['security-monitor:9100']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF

    # Grafana provisioning
    mkdir -p "$COMPOSE_DIR/grafana/provisioning/datasources"
    cat > "$COMPOSE_DIR/grafana/provisioning/datasources/prometheus.yml" << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF

    log_success "Configuration files generated"
}

deploy_services() {
    log_info "Deploying Security Orchestrator services..."
    
    cd "$COMPOSE_DIR"
    
    # Pull latest images
    log_info "Pulling Docker images..."
    docker-compose pull
    
    # Build custom images
    log_info "Building custom images..."
    docker-compose build --no-cache
    
    # Start services
    log_info "Starting services..."
    docker-compose up -d
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 30
    
    # Check service health
    check_service_health
    
    log_success "Services deployed successfully"
}

check_service_health() {
    log_info "Checking service health..."
    
    # Check main orchestrator
    if curl -f http://localhost:8080/health &> /dev/null; then
        log_success "Security Orchestrator is healthy"
    else
        log_error "Security Orchestrator is not responding"
        return 1
    fi
    
    # Check database
    if docker-compose exec -T postgres pg_isready -U orchestrator &> /dev/null; then
        log_success "PostgreSQL is healthy"
    else
        log_error "PostgreSQL is not ready"
        return 1
    fi
    
    # Check Redis
    if docker-compose exec -T redis redis-cli ping &> /dev/null; then
        log_success "Redis is healthy"
    else
        log_error "Redis is not ready"
        return 1
    fi
    
    # Check Elasticsearch
    if curl -f http://localhost:9200/_cluster/health &> /dev/null; then
        log_success "Elasticsearch is healthy"
    else
        log_warning "Elasticsearch is not ready (may still be initializing)"
    fi
    
    log_success "Health check completed"
}

setup_ssl() {
    if [ "$SSL_ENABLED" = true ]; then
        log_info "Setting up SSL certificates..."
        
        # Create SSL directory
        mkdir -p "$COMPOSE_DIR/nginx/ssl"
        
        # Generate self-signed certificate (for development)
        if [ "$ENVIRONMENT" = "development" ]; then
            openssl req -x509 -newkey rsa:4096 -keyout "$COMPOSE_DIR/nginx/ssl/key.pem" \
                -out "$COMPOSE_DIR/nginx/ssl/cert.pem" -days 365 -nodes \
                -subj "/C=US/ST=State/L=City/O=Security Orchestrator/CN=$DOMAIN"
            log_success "Self-signed SSL certificate generated"
        else
            log_warning "Please provide your own SSL certificates in $COMPOSE_DIR/nginx/ssl/"
            log_warning "Expected files: cert.pem and key.pem"
        fi
    fi
}

initialize_database() {
    log_info "Initializing database..."
    
    cd "$COMPOSE_DIR"
    
    # Run database migrations
    docker-compose exec -T security-orchestrator python scripts/migrate_database.py
    
    # Create default admin user
    docker-compose exec -T security-orchestrator python scripts/create_admin.py
    
    log_success "Database initialized"
}

setup_monitoring() {
    if [ "$MONITORING_ENABLED" = true ]; then
        log_info "Setting up monitoring..."
        
        # Import default dashboards
        cd "$COMPOSE_DIR"
        docker-compose exec -T grafana bash -c "
            curl -X POST \
                -H 'Content-Type: application/json' \
                -H 'Authorization: Bearer \$(cat /etc/grafana/secrets/admin_password)' \
                -d @/etc/grafana/provisioning/dashboards/security-orchestrator.json \
                http://localhost:3000/api/dashboards/db
        " || log_warning "Could not import default dashboards"
        
        log_success "Monitoring setup completed"
    fi
}

run_tests() {
    log_info "Running deployment tests..."
    
    cd "$COMPOSE_DIR"
    
    # Test API connectivity
    if curl -f http://localhost:8080/api/v1/status &> /dev/null; then
        log_success "API connectivity test passed"
    else
        log_error "API connectivity test failed"
        return 1
    fi
    
    # Test agent registration
    if docker-compose exec -T security-orchestrator python scripts/test_agents.py; then
        log_success "Agent registration test passed"
    else
        log_error "Agent registration test failed"
        return 1
    fi
    
    # Test task execution
    if docker-compose exec -T security-orchestrator python scripts/test_tasks.py; then
        log_success "Task execution test passed"
    else
        log_error "Task execution test failed"
        return 1
    fi
    
    log_success "All tests passed"
}

print_deployment_info() {
    log_success "Deployment completed successfully!"
    echo
    echo "=== Security Orchestrator Information ==="
    echo "Domain: $DOMAIN"
    echo "Environment: $ENVIRONMENT"
    echo "SSL Enabled: $SSL_ENABLED"
    echo "Monitoring Enabled: $MONITORING_ENABLED"
    echo
    echo "=== Service URLs ==="
    echo "Security Orchestrator: http://$DOMAIN"
    if [ "$SSL_ENABLED" = true ]; then
        echo "Security Orchestrator (HTTPS): https://$DOMAIN"
    fi
    echo "Grafana: http://$DOMAIN:3000"
    echo "Kibana: http://$DOMAIN:5601"
    echo "Prometheus: http://$DOMAIN:9090"
    echo
    echo "=== Service Credentials ==="
    echo "Grafana Password: $(grep GRAFANA_PASSWORD "$COMPOSE_DIR/.env" | cut -d'=' -f2)"
    echo "PostgreSQL Password: $(grep POSTGRES_PASSWORD "$COMPOSE_DIR/.env" | cut -d'=' -f2)"
    echo "Redis Password: $(grep REDIS_PASSWORD "$COMPOSE_DIR/.env" | cut -d'=' -f2)"
    echo
    echo "=== Next Steps ==="
    echo "1. Access the Security Orchestrator web interface"
    echo "2. Configure your OpenRouter API key"
    echo "3. Initialize and register security agents"
    echo "4. Start your first security assessment"
    echo
    echo "=== Useful Commands ==="
    echo "View logs: docker-compose -f $COMPOSE_DIR/docker-compose.yml logs -f"
    echo "Check status: docker-compose -f $COMPOSE_DIR/docker-compose.yml ps"
    echo "Stop services: docker-compose -f $COMPOSE_DIR/docker-compose.yml down"
    echo "Update services: docker-compose -f $COMPOSE_DIR/docker-compose.yml pull && docker-compose -f $COMPOSE_DIR/docker-compose.yml up -d"
    echo
}

cleanup() {
    log_info "Cleaning up..."
    
    cd "$COMPOSE_DIR"
    
    # Stop and remove containers
    docker-compose down -v --remove-orphans
    
    # Remove unused images
    docker image prune -f
    
    # Remove unused volumes (be careful with this)
    # docker volume prune -f
    
    log_success "Cleanup completed"
}

# Main deployment function
main() {
    echo "=== Enhanced Security Orchestrator Deployment ==="
    echo
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --ssl)
                SSL_ENABLED=true
                shift
                ;;
            --monitoring)
                MONITORING_ENABLED="$2"
                shift 2
                ;;
            --backup)
                BACKUP_ENABLED="$2"
                shift 2
                ;;
            --auto-update)
                AUTO_UPDATE="$2"
                shift 2
                ;;
            --cleanup)
                cleanup
                exit 0
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo
                echo "Options:"
                echo "  --environment ENV     Set environment (development|production)"
                echo "  --domain DOMAIN       Set domain name"
                echo "  --ssl                 Enable SSL"
                echo "  --monitoring ENABLE   Enable monitoring (true|false)"
                echo "  --backup ENABLE       Enable backup (true|false)"
                echo "  --auto-update ENABLE  Enable auto-update (true|false)"
                echo "  --cleanup             Clean up deployment"
                echo "  --help                Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Validate environment
    if [ "$ENVIRONMENT" != "development" ] && [ "$ENVIRONMENT" != "production" ]; then
        log_error "Environment must be 'development' or 'production'"
        exit 1
    fi
    
    # Check if OpenRouter API key is set
    if [ -z "$OPENROUTER_API_KEY" ]; then
        log_error "OPENROUTER_API_KEY environment variable is required"
        echo "Please set it with: export OPENROUTER_API_KEY=your-api-key"
        exit 1
    fi
    
    # Start deployment
    check_prerequisites
    setup_environment
    setup_ssl
    deploy_services
    initialize_database
    setup_monitoring
    run_tests
    print_deployment_info
}

# Run main function
main "$@"
