#!/bin/bash
# VPS Setup Script for AI Agent Orchestrator
# Run this script on a fresh Kali Linux VPS

set -e

echo "========================================="
echo "AI Agent Orchestrator - VPS Setup"
echo "========================================="

# Update system
echo "[1/8] Updating system packages..."
apt-get update
apt-get upgrade -y

# Install Python and dependencies
echo "[2/8] Installing Python and dependencies..."
apt-get install -y python3 python3-pip python3-venv git

# Install security tools
echo "[3/8] Installing security tools..."
apt-get install -y \
    nmap \
    metasploit-framework \
    wireshark \
    tshark \
    burpsuite \
    suricata \
    john \
    hydra \
    sqlmap \
    nikto

# Create orchestrator user
echo "[4/8] Creating orchestrator user..."
if ! id "orchestrator" &>/dev/null; then
    useradd -m -s /bin/bash orchestrator
    usermod -aG sudo orchestrator
fi

# Create directories
echo "[5/8] Creating directories..."
mkdir -p /opt/orchestrator
mkdir -p /var/log/orchestrator
mkdir -p /backup/orchestrator

# Set permissions
chown -R orchestrator:orchestrator /opt/orchestrator
chown -R orchestrator:orchestrator /var/log/orchestrator
chown -R orchestrator:orchestrator /backup/orchestrator

# Clone repository (replace with your repo URL)
echo "[6/8] Cloning repository..."
cd /opt
if [ ! -d "orchestrator" ]; then
    git clone https://github.com/Shahil-AppDev/Alpha-AI-V2.git orchestrator-repo
    cp -r orchestrator-repo/orchestrator/* /opt/orchestrator/
fi

# Install Python dependencies
echo "[7/8] Installing Python dependencies..."
cd /opt/orchestrator
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Setup cron jobs
echo "[8/8] Setting up cron jobs..."
cp deployment/crontab.example /tmp/orchestrator-cron
sed -i "s|/path/to/orchestrator|/opt/orchestrator|g" /tmp/orchestrator-cron
crontab -u orchestrator /tmp/orchestrator-cron

# Create systemd service
echo "Creating systemd service..."
cat > /etc/systemd/system/orchestrator.service <<EOF
[Unit]
Description=AI Agent Orchestrator
After=network.target

[Service]
Type=simple
User=orchestrator
WorkingDirectory=/opt/orchestrator
ExecStart=/opt/orchestrator/venv/bin/python3 /opt/orchestrator/orchestrator_main.py production
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable orchestrator
systemctl start orchestrator

# Configure firewall
echo "Configuring firewall..."
ufw allow 22/tcp
ufw allow 8000/tcp
ufw --force enable

echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Edit configuration: /opt/orchestrator/config/default_config.py"
echo "2. Check service status: systemctl status orchestrator"
echo "3. View logs: tail -f /var/log/orchestrator/platform.log"
echo "4. Access API: http://your-vps-ip:8000"
echo ""
echo "Security tools will update daily at 2 AM"
echo "========================================="
