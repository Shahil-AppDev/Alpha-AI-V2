#!/bin/bash

# HackerAI Platform Deployment Script
# Automated deployment for VPS/Cloud environments

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
CONFIG_DIR="$PROJECT_DIR/config"
DATA_DIR="$PROJECT_DIR/data"
LOG_DIR="$PROJECT_DIR/logs"

# Default values
ENVIRONMENT="production"
DOMAIN="localhost"
SSL_ENABLED=false
INSTALL_TOOLS=true
ENABLE_GPU=false
ENABLE_K8S=false

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
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root for security reasons"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check Git
    if ! command -v git &> /dev/null; then
        log_error "Git is not installed"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

install_system_dependencies() {
    log_info "Installing system dependencies..."
    
    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            # Ubuntu/Debian
            sudo apt-get update
            sudo apt-get install -y curl wget git htop jq unzip
        elif command -v yum &> /dev/null; then
            # CentOS/RHEL
            sudo yum update -y
            sudo yum install -y curl wget git htop jq unzip
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            sudo pacman -Syu --noconfirm --needed curl wget git htop jq unzip
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew update
            brew install curl wget git htop jq
        else
            log_error "Homebrew is not installed on macOS"
            exit 1
        fi
    fi
    
    log_success "System dependencies installed"
}

setup_directories() {
    log_info "Setting up directories..."
    
    # Create necessary directories
    mkdir -p "$DATA_DIR"/{osint,network,web,password,exploit,wireless,forensics,malware}
    mkdir -p "$DATA_DIR"/{reports,sessions,captures,hashes,wordlists,evidence}
    mkdir -p "$CONFIG_DIR"/{tools,ssl,nginx,prometheus,grafana}
    mkdir -p "$LOG_DIR"
    mkdir -p "$PROJECT_DIR"/docker/{tools,nginx}
    
    # Set permissions
    chmod 755 "$DATA_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 755 "$LOG_DIR"
    
    log_success "Directories created"
}

generate_secrets() {
    log_info "Generating secrets..."
    
    # Generate random passwords
    POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    MINIO_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    JWT_SECRET=$(openssl rand -base64 64)
    API_KEY=$(openssl rand -hex 32)
    
    # Create environment file
    cat > "$PROJECT_DIR/.env" << EOF
# HackerAI Platform Environment Configuration
# Generated on $(date)

# Database Configuration
POSTGRES_DB=hackerai
POSTGRES_USER=hackerai
POSTGRES_PASSWORD=$POSTGRES_PASSWORD

# Redis Configuration
REDIS_PASSWORD=$REDIS_PASSWORD

# MinIO Configuration
MINIO_ROOT_USER=hackerai
MINIO_ROOT_PASSWORD=$MINIO_PASSWORD

# API Configuration
HACKERAI_API_KEY=$API_KEY
JWT_SECRET=$JWT_SECRET
HACKERAI_ENV=$ENVIRONMENT
HACKERAI_DOMAIN=$DOMAIN

# Security
SSL_ENABLED=$SSL_ENABLED
ENABLE_HTTPS=$SSL_ENABLED

# Features
INSTALL_TOOLS=$INSTALL_TOOLS
ENABLE_GPU=$ENABLE_GPU
ENABLE_K8S=$ENABLE_K8S

# Performance
HACKERAI_MAX_CONCURRENT_TOOLS=10
HACKERAI_WORKER_PROCESSES=4

# Logging
HACKERAI_LOG_LEVEL=INFO
LOG_FILE_PATH=$LOG_DIR/hackerai.log

# Paths
HACKERAI_DATA_DIR=$DATA_DIR
HACKERAI_CONFIG_DIR=$CONFIG_DIR
HACKERAI_LOG_DIR=$LOG_DIR
EOF
    
    chmod 600 "$PROJECT_DIR/.env"
    log_success "Secrets generated and saved to .env"
}

setup_nginx() {
    log_info "Setting up Nginx configuration..."
    
    cat > "$CONFIG_DIR/nginx/nginx.conf" << EOF
events {
    worker_connections 1024;
}

http {
    upstream hackerai_backend {
        server hackerai-platform:8080;
    }
    
    server {
        listen 80;
        server_name $DOMAIN;
        
        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
        
        # Rate limiting
        limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
        
        location / {
            proxy_pass http://hackerai_backend;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            
            # Apply rate limiting to API
            limit_req zone=api burst=20 nodelay;
        }
        
        location /health {
            proxy_pass http://hackerai_backend/health;
            access_log off;
        }
    }
EOF
    
    if [[ "$SSL_ENABLED" == "true" ]]; then
        cat >> "$CONFIG_DIR/nginx/nginx.conf" << EOF
    
    server {
        listen 443 ssl http2;
        server_name $DOMAIN;
        
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
        ssl_prefer_server_ciphers off;
        
        location / {
            proxy_pass http://hackerai_backend;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }
EOF
    fi
    
    log_success "Nginx configuration created"
}

setup_prometheus() {
    log_info "Setting up Prometheus configuration..."
    
    cat > "$CONFIG_DIR/prometheus/prometheus.yml" << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "hackerai_rules.yml"

scrape_configs:
  - job_name: 'hackerai-platform'
    static_configs:
      - targets: ['hackerai-platform:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s
    
  - job_name: 'hackerai-redis'
    static_configs:
      - targets: ['hackerai-redis:6379']
    
  - job_name: 'hackerai-postgres'
    static_configs:
      - targets: ['hackerai-postgres:5432']
      
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF
    
    # Create alert rules
    cat > "$CONFIG_DIR/prometheus/hackerai_rules.yml" << EOF
groups:
  - name: hackerai_alerts
    rules:
      - alert: HackerAIDown
        expr: up{job="hackerai-platform"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "HackerAI platform is down"
          description: "HackerAI platform has been down for more than 1 minute."
      
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ \$value }} errors per second."
      
      - alert: TooManyFailedTools
        expr: increase(tool_executions_failed_total[5m]) > 10
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Too many failed tool executions"
          description: "More than 10 tools have failed in the last 5 minutes."
EOF
    
    log_success "Prometheus configuration created"
}

setup_grafana() {
    log_info "Setting up Grafana configuration..."
    
    # Create datasources
    mkdir -p "$CONFIG_DIR/grafana/datasources"
    cat > "$CONFIG_DIR/grafana/datasources/prometheus.yml" << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF
    
    # Create dashboard configuration
    mkdir -p "$CONFIG_DIR/grafana/dashboards"
    cat > "$CONFIG_DIR/grafana/dashboards/dashboard.yml" << EOF
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOF
    
    log_success "Grafana configuration created"
}

download_wordlists() {
    log_info "Downloading wordlists..."
    
    WORDLIST_DIR="$DATA_DIR/wordlists"
    mkdir -p "$WORDLIST_DIR"
    
    # Download SecLists
    if [[ ! -d "$WORDLIST_DIR/SecLists" ]]; then
        git clone https://github.com/danielmiessler/SecLists.git "$WORDLIST_DIR/SecLists"
    fi
    
    # Download rockyou.txt if not present
    if [[ ! -f "$WORDLIST_DIR/rockyou.txt" ]]; then
        wget -O "$WORDLIST_DIR/rockyou.txt" \
            "https://github.com/brannondorsey/naive-hashcat/raw/master/wordlists/rockyou.txt"
    fi
    
    # Create symbolic links for common wordlists
    ln -sf "$WORDLIST_DIR/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt" \
           "$WORDLIST_DIR/common.txt"
    ln -sf "$WORDLIST_DIR/SecLists/Usernames/top-usernames-shortlist.txt" \
           "$WORDLIST_DIR/usernames.txt"
    
    log_success "Wordlists downloaded"
}

deploy_docker() {
    log_info "Deploying Docker containers..."
    
    cd "$PROJECT_DIR"
    
    # Build and start services
    if [[ "$INSTALL_TOOLS" == "true" ]]; then
        log_info "Building tool containers..."
        docker-compose -f docker/hackerai-platform/docker-compose.yml build
    fi
    
    log_info "Starting core services..."
    docker-compose -f docker/hackerai-platform/docker-compose.yml up -d
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 30
    
    # Check service health
    if docker-compose -f docker/hackerai-platform/docker-compose.yml ps | grep -q "Up (healthy)"; then
        log_success "Services are healthy"
    else
        log_warning "Some services may not be fully ready yet"
    fi
    
    log_success "Docker deployment completed"
}

setup_ssl() {
    if [[ "$SSL_ENABLED" == "true" ]]; then
        log_info "Setting up SSL certificates..."
        
        SSL_DIR="$CONFIG_DIR/ssl"
        mkdir -p "$SSL_DIR"
        
        if [[ "$DOMAIN" != "localhost" ]]; then
            # Use Let's Encrypt for production domains
            if command -v certbot &> /dev/null; then
                certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos
                cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/cert.pem"
                cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$SSL_DIR/key.pem"
            else
                log_warning "Certbot not found, generating self-signed certificate"
                openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                    -keyout "$SSL_DIR/key.pem" \
                    -out "$SSL_DIR/cert.pem" \
                    -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN"
            fi
        else
            # Generate self-signed certificate for localhost
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "$SSL_DIR/key.pem" \
                -out "$SSL_DIR/cert.pem" \
                -subj "/C=US/ST=State/L=City/O=HackerAI/CN=localhost"
        fi
        
        log_success "SSL certificates setup completed"
    fi
}

run_tests() {
    log_info "Running deployment tests..."
    
    # Test API health
    if curl -f http://localhost:8080/health &> /dev/null; then
        log_success "API health check passed"
    else
        log_error "API health check failed"
        return 1
    fi
    
    # Test database connection
    if docker-compose -f docker/hackerai-platform/docker-compose.yml exec -T postgres pg_isready -U hackerai &> /dev/null; then
        log_success "Database connection test passed"
    else
        log_error "Database connection test failed"
        return 1
    fi
    
    # Test Redis connection
    if docker-compose -f docker/hackerai-platform/docker-compose.yml exec -T redis redis-cli ping &> /dev/null; then
        log_success "Redis connection test passed"
    else
        log_error "Redis connection test failed"
        return 1
    fi
    
    log_success "All deployment tests passed"
}

print_summary() {
    log_success "HackerAI Platform deployment completed!"
    echo
    echo "=== Deployment Summary ==="
    echo "Environment: $ENVIRONMENT"
    echo "Domain: $DOMAIN"
    echo "SSL Enabled: $SSL_ENABLED"
    echo "GPU Support: $ENABLE_GPU"
    echo "Kubernetes: $ENABLE_K8S"
    echo
    echo "=== Access Information ==="
    echo "API URL: http://$DOMAIN:8080"
    echo "API Documentation: http://$DOMAIN:8080/docs"
    echo "Grafana: http://$DOMAIN:3000 (admin/hackerai_admin_2024)"
    echo "Prometheus: http://$DOMAIN:9090"
    echo "MinIO Console: http://$DOMAIN:9001"
    echo
    echo "=== Configuration Files ==="
    echo "Environment: $PROJECT_DIR/.env"
    echo "Nginx: $CONFIG_DIR/nginx/nginx.conf"
    echo "Prometheus: $CONFIG_DIR/prometheus/prometheus.yml"
    echo
    echo "=== Data Directories ==="
    echo "Data: $DATA_DIR"
    echo "Logs: $LOG_DIR"
    echo "Wordlists: $DATA_DIR/wordlists"
    echo
    echo "=== Next Steps ==="
    echo "1. Update your DNS to point to this server"
    echo "2. Configure SSL certificates if using a custom domain"
    echo "3. Set up monitoring and alerting"
    echo "4. Review security configurations"
    echo "5. Start using the API at http://$DOMAIN:8080/docs"
    echo
    echo "=== Management Commands ==="
    echo "View logs: docker-compose -f docker/hackerai-platform/docker-compose.yml logs -f"
    echo "Stop services: docker-compose -f docker/hackerai-platform/docker-compose.yml down"
    echo "Update services: docker-compose -f docker/hackerai-platform/docker-compose.yml pull && docker-compose -f docker/hackerai-platform/docker-compose.yml up -d"
    echo
}

# Main deployment function
main() {
    echo "HackerAI Platform Deployment Script"
    echo "==================================="
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
            --gpu)
                ENABLE_GPU=true
                shift
                ;;
            --k8s)
                ENABLE_K8S=true
                shift
                ;;
            --no-tools)
                INSTALL_TOOLS=false
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --environment ENV    Set environment (default: production)"
                echo "  --domain DOMAIN      Set domain (default: localhost)"
                echo "  --ssl                Enable SSL"
                echo "  --gpu                Enable GPU support"
                echo "  --k8s                Enable Kubernetes"
                echo "  --no-tools           Skip tool installation"
                echo "  --help               Show this help"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Run deployment steps
    check_prerequisites
    install_system_dependencies
    setup_directories
    generate_secrets
    setup_nginx
    setup_prometheus
    setup_grafana
    download_wordlists
    setup_ssl
    deploy_docker
    
    if run_tests; then
        print_summary
    else
        log_error "Deployment tests failed"
        exit 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
