#!/bin/bash

# Deploy Alpha AI Backend to VPS
# Server: 157.180.107.154

set -e

echo "🚀 Deploying Alpha AI Backend to VPS..."

# Configuration
VPS_HOST="157.180.107.154"
VPS_USER="root"
DEPLOY_DIR="/var/www/alpha-ai"
APP_NAME="alpha-ai-backend"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}📦 Creating deployment package...${NC}"

# Create temporary deployment directory
TEMP_DIR=$(mktemp -d)
mkdir -p "$TEMP_DIR/alpha-ai"

# Copy necessary files
cp -r src "$TEMP_DIR/alpha-ai/"
cp main.py "$TEMP_DIR/alpha-ai/"
cp -r scripts "$TEMP_DIR/alpha-ai/" 2>/dev/null || true

# Create requirements.txt if not exists
if [ ! -f "src/requirements.txt" ]; then
    cat > "$TEMP_DIR/alpha-ai/requirements.txt" << EOF
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.3
python-dotenv==1.0.0
aiohttp==3.9.1
asyncio==3.4.3
paramiko==3.4.0
requests==2.31.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
EOF
else
    cp src/requirements.txt "$TEMP_DIR/alpha-ai/"
fi

# Create systemd service file
cat > "$TEMP_DIR/alpha-ai-backend.service" << EOF
[Unit]
Description=Alpha AI Backend API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DEPLOY_DIR
Environment="PATH=/usr/bin:/usr/local/bin"
ExecStart=/usr/bin/python3 -m uvicorn src.api.hackerai_api:app --host 0.0.0.0 --port 8080 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create .env file
cat > "$TEMP_DIR/alpha-ai/.env" << EOF
# Alpha AI Backend Configuration
ENVIRONMENT=production
LOG_LEVEL=INFO
API_HOST=0.0.0.0
API_PORT=8080

# Security
JWT_SECRET=\$(openssl rand -base64 32)
API_KEY=hackerai-api-key-2024

# LLM Configuration (if needed)
LLM_ENDPOINT=http://localhost:8000/generate
LLM_API_KEY=test-key
EOF

# Create archive
cd "$TEMP_DIR"
tar -czf alpha-ai-backend.tar.gz alpha-ai/ alpha-ai-backend.service

echo -e "${BLUE}📤 Uploading to VPS...${NC}"

# Upload to VPS
scp -i github-deploy-key -o StrictHostKeyChecking=no \
    alpha-ai-backend.tar.gz \
    root@$VPS_HOST:/tmp/

echo -e "${BLUE}🔧 Installing on VPS...${NC}"

# Deploy on VPS
ssh -i github-deploy-key -o StrictHostKeyChecking=no root@$VPS_HOST << 'ENDSSH'
set -e

echo "Creating deployment directory..."
mkdir -p /var/www/alpha-ai
cd /var/www

echo "Extracting files..."
tar -xzf /tmp/alpha-ai-backend.tar.gz
cp -r alpha-ai/* /var/www/alpha-ai/

echo "Installing Python dependencies..."
cd /var/www/alpha-ai
pip3 install --upgrade pip
pip3 install -r requirements.txt

echo "Setting up systemd service..."
cp /tmp/alpha-ai/alpha-ai-backend.service /etc/systemd/system/
systemctl daemon-reload

echo "Starting service..."
systemctl stop alpha-ai-backend 2>/dev/null || true
systemctl enable alpha-ai-backend
systemctl start alpha-ai-backend

echo "Checking service status..."
sleep 3
systemctl status alpha-ai-backend --no-pager

echo "Testing API..."
sleep 2
curl -f http://localhost:8080/health || echo "Health check failed"

echo "Cleaning up..."
rm -f /tmp/alpha-ai-backend.tar.gz

echo "✅ Deployment completed!"
echo "API available at: http://157.180.107.154:8080"
echo "Health check: http://157.180.107.154:8080/health"
echo "API docs: http://157.180.107.154:8080/docs"

ENDSSH

# Cleanup local temp
rm -rf "$TEMP_DIR"

echo -e "${GREEN}✅ Deployment successful!${NC}"
echo -e "${BLUE}📊 Service Information:${NC}"
echo "  - API: http://157.180.107.154:8080"
echo "  - Health: http://157.180.107.154:8080/health"
echo "  - Docs: http://157.180.107.154:8080/docs"
echo ""
echo -e "${BLUE}🔍 Useful commands:${NC}"
echo "  - Check logs: ssh -i github-deploy-key root@157.180.107.154 'journalctl -u alpha-ai-backend -f'"
echo "  - Restart: ssh -i github-deploy-key root@157.180.107.154 'systemctl restart alpha-ai-backend'"
echo "  - Status: ssh -i github-deploy-key root@157.180.107.154 'systemctl status alpha-ai-backend'"
