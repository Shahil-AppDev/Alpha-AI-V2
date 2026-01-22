#!/bin/bash

# Deploy All to Server Script
SERVER_HOST="157.180.107.154"
SERVER_USER="root"
SERVER_PATH="/var/www/alpha-ai"

echo "🚀 Starting deployment to server..."

# Test SSH connection
echo "📡 Testing SSH connection..."
if ! ssh $SERVER_USER@$SERVER_HOST "echo '✅ SSH connection successful'"; then
    echo "❌ SSH connection failed. Please check your SSH keys."
    exit 1
fi

# Setup server directories
echo "📁 Setting up server directories..."
ssh $SERVER_USER@$SERVER_HOST "
mkdir -p $SERVER_PATH/{frontend,backend,tools,logs}
chown -R www-data:www-data $SERVER_PATH
"

# Deploy frontend
echo "🎨 Deploying frontend..."
if [ -d "frontend" ]; then
    cd frontend
    npm ci
    npm run build
    
    # Copy frontend files
    scp -r out/* $SERVER_USER@$SERVER_HOST:$SERVER_PATH/frontend/
    ssh $SERVER_USER@$SERVER_HOST "chown -R www-data:www-data $SERVER_PATH/frontend"
    cd ..
    echo "✅ Frontend deployed successfully"
else
    echo "⚠️ Frontend directory not found"
fi

# Deploy backend
echo "⚙️ Deploying backend..."
if [ -d "apps/backend" ]; then
    cd apps/backend
    npm ci
    npm run build
    
    # Copy backend files
    scp -r dist/* $SERVER_USER@$SERVER_HOST:$SERVER_PATH/backend/
    scp package.json $SERVER_USER@$SERVER_HOST:$SERVER_PATH/backend/
    ssh $SERVER_USER@$SERVER_HOST "
    cd $SERVER_PATH/backend
    npm ci --production
    "
    cd ..
    echo "✅ Backend deployed successfully"
else
    echo "⚠️ Backend directory not found"
fi

# Deploy security tools
echo "🔐 Deploying security tools..."
if [ -d "tools" ]; then
    scp -r tools $SERVER_USER@$SERVER_HOST:$SERVER_PATH/
    echo "✅ Tools deployed successfully"
fi

# Deploy other security tool directories
tool_dirs=("PowerSploit" "binwalk" "gophish" "hashcat" "john" "metasploit-framework" "mimikatz" "recon-ng" "spiderfoot" "sqlmap" "thc-hydra" "zaproxy")

for tool in "${tool_dirs[@]}"; do
    if [ -d "$tool" ]; then
        echo "   Deploying $tool..."
        scp -r $tool $SERVER_USER@$SERVER_HOST:$SERVER_PATH/
    fi
done

# Setup Python dependencies for security tools
echo "🐍 Setting up Python dependencies..."
ssh $SERVER_USER@$SERVER_HOST "
apt update && apt install -y python3 python3-pip python3-venv
cd $SERVER_PATH
python3 -m venv venv
source venv/bin/activate
pip install requests beautifulsoup4 flask numpy pandas scikit-learn
"

# Setup PM2 for backend
echo "🔄 Setting up PM2..."
ssh $SERVER_USER@$SERVER_HOST "
cd $SERVER_PATH/backend
pm2 stop alpha-ai-backend 2>/dev/null || true
pm2 start dist/main.js --name alpha-ai-backend
pm2 save
pm2 startup
"

# Setup Nginx configuration
echo "🌐 Setting up Nginx..."
ssh $SERVER_USER@$SERVER_HOST "
cat > /etc/nginx/sites-available/alpha-ai << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Frontend
    location / {
        root $SERVER_PATH/frontend;
        index index.html;
        try_files \$uri \$uri/ /index.html;
    }
    
    # Backend API
    location /api {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
    
    # Security tools interface (optional)
    location /tools {
        root $SERVER_PATH;
        autoindex on;
    }
}
EOF

ln -sf /etc/nginx/sites-available/alpha-ai /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
"

# Setup firewall
echo "🔥 Setting up firewall..."
ssh $SERVER_USER@$SERVER_HOST "
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3001/tcp
ufw --force enable
"

# Start services
echo "▶️ Starting services..."
ssh $SERVER_USER@$SERVER_HOST "
systemctl start nginx
systemctl enable nginx
pm2 restart alpha-ai-backend
"

echo "🎉 Deployment completed successfully!"
echo "📋 Deployment Summary:"
echo "   • Frontend: http://$SERVER_HOST/"
echo "   • Backend API: http://$SERVER_HOST/api"
echo "   • Security Tools: http://$SERVER_HOST/tools"
echo "   • PM2 Status: ssh $SERVER_USER@$SERVER_HOST 'pm2 status'"
