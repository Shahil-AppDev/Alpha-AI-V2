# 🦞 OpenClaw AI Assistant - Integration Guide

## Overview

OpenClaw is a personal AI assistant that has been installed on the Qatar One VPS server to provide AI capabilities for all security agents. It runs as a local service and can be integrated with the backend API to provide intelligent responses and automation.

## Installation Details

### Server Information
- **Server IP:** 157.180.107.154
- **Installation Path:** `/var/www/qatar-one/openclaw`
- **Version:** 2026.2.1
- **Gateway Port:** 18789 (localhost only)
- **Service Name:** `openclaw-gateway.service`

### Configuration
```bash
# OpenClaw configuration
Mode: local
Port: 18789
Auth: Token-based authentication
Token: 46d0aec7fabdba9ee356c5a8a930f334cc59b2963df620fa8b25e92f9c47ec01
```

## Service Management

### Systemd Service
OpenClaw runs as a systemd service for automatic startup and management.

```bash
# Check service status
systemctl status openclaw-gateway

# Start service
systemctl start openclaw-gateway

# Stop service
systemctl stop openclaw-gateway

# Restart service
systemctl restart openclaw-gateway

# View logs
tail -f /var/log/openclaw-gateway.log
journalctl -u openclaw-gateway -f
```

### Service Configuration
Location: `/etc/systemd/system/openclaw-gateway.service`

```ini
[Unit]
Description=OpenClaw AI Assistant Gateway
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/qatar-one/openclaw
ExecStart=/usr/bin/openclaw gateway run --bind loopback --port 18789
Restart=always
RestartSec=10
StandardOutput=append:/var/log/openclaw-gateway.log
StandardError=append:/var/log/openclaw-gateway.log

[Install]
WantedBy=multi-user.target
```

## API Integration

### Gateway Endpoint
OpenClaw gateway is accessible at: `ws://127.0.0.1:18789`

### Authentication
All requests require the authentication token in the headers:
```
Authorization: Bearer 46d0aec7fabdba9ee356c5a8a930f334cc59b2963df620fa8b25e92f9c47ec01
```

### Using OpenClaw CLI

```bash
# Send a message to the AI assistant
openclaw agent --message "Analyze this security vulnerability" --thinking high

# Send a message to a specific channel (if configured)
openclaw message send --to +1234567890 --message "Security alert"

# Check gateway status
openclaw channels status --probe

# View configuration
openclaw config get gateway.mode
openclaw config get gateway.port
```

## Integration with Qatar One Backend

### Example NestJS Integration

Create a new service to communicate with OpenClaw:

```typescript
// apps/backend/src/modules/openclaw/openclaw.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { WebSocket } from 'ws';

@Injectable()
export class OpenClawService {
  private readonly logger = new Logger(OpenClawService.name);
  private ws: WebSocket;
  private readonly gatewayUrl = 'ws://127.0.0.1:18789';
  private readonly token = process.env.OPENCLAW_TOKEN;

  async connect() {
    this.ws = new WebSocket(this.gatewayUrl, {
      headers: {
        Authorization: `Bearer ${this.token}`,
      },
    });

    this.ws.on('open', () => {
      this.logger.log('Connected to OpenClaw gateway');
    });

    this.ws.on('message', (data) => {
      this.logger.log(`Received: ${data}`);
    });

    this.ws.on('error', (error) => {
      this.logger.error(`WebSocket error: ${error.message}`);
    });
  }

  async sendMessage(message: string): Promise<string> {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error('WebSocket not connected'));
        return;
      }

      this.ws.send(JSON.stringify({ message }));

      this.ws.once('message', (data) => {
        resolve(data.toString());
      });
    });
  }

  async analyzeSecurityThreat(threat: string): Promise<any> {
    const message = `Analyze this security threat and provide recommendations: ${threat}`;
    return this.sendMessage(message);
  }

  async generateExploit(vulnerability: string): Promise<any> {
    const message = `Generate an exploit for this vulnerability: ${vulnerability}`;
    return this.sendMessage(message);
  }
}
```

### Environment Variables

Add to `apps/backend/.env`:
```env
OPENCLAW_TOKEN=46d0aec7fabdba9ee356c5a8a930f334cc59b2963df620fa8b25e92f9c47ec01
OPENCLAW_GATEWAY_URL=ws://127.0.0.1:18789
```

## Features

### AI Agent Capabilities
- **Natural Language Processing:** Understand and respond to security queries
- **Code Analysis:** Analyze code snippets for vulnerabilities
- **Exploit Generation:** Generate payloads and exploit templates
- **Threat Intelligence:** Provide security recommendations
- **Automation:** Execute security tasks and workflows

### Supported Models
- **Anthropic Claude Opus 4.5** (default)
- **OpenAI GPT models**
- Custom model configurations

## Usage Examples

### 1. Security Analysis
```bash
openclaw agent --message "Analyze this SQL injection vulnerability in the authentication module" --thinking high
```

### 2. Exploit Development
```bash
openclaw agent --message "Generate a reverse shell payload for Linux x64" --thinking high
```

### 3. Threat Assessment
```bash
openclaw agent --message "Assess the risk level of CVE-2024-1234" --thinking high
```

## Monitoring

### Check Gateway Status
```bash
# View real-time logs
tail -f /var/log/openclaw-gateway.log

# Check if gateway is listening
ss -ltnp | grep 18789

# View systemd service status
systemctl status openclaw-gateway
```

### Log Files
- **Service logs:** `/var/log/openclaw-gateway.log`
- **OpenClaw logs:** `/tmp/openclaw/openclaw-YYYY-MM-DD.log`
- **Canvas logs:** `/root/.openclaw/canvas/`

## Troubleshooting

### Gateway Not Starting
```bash
# Check logs for errors
journalctl -u openclaw-gateway -n 50

# Verify configuration
openclaw config get gateway.mode
openclaw config get gateway.port
openclaw config get gateway.auth.token

# Restart service
systemctl restart openclaw-gateway
```

### Connection Issues
```bash
# Verify gateway is listening
ss -ltnp | grep 18789

# Test connection
curl -H "Authorization: Bearer YOUR_TOKEN" http://127.0.0.1:18789/health
```

### Token Issues
```bash
# Regenerate token
openssl rand -hex 32 > /tmp/new-token.txt
openclaw config set gateway.auth.token $(cat /tmp/new-token.txt)
systemctl restart openclaw-gateway
```

## Security Considerations

1. **Token Security:** The authentication token is stored in the OpenClaw config. Keep it secure.
2. **Local Only:** Gateway is bound to localhost (127.0.0.1) for security.
3. **Firewall:** Port 18789 is not exposed externally.
4. **Logs:** Sensitive data may appear in logs - review log rotation policies.

## Next Steps

1. **Configure AI Models:** Set up Anthropic or OpenAI API keys
2. **Create Integration Module:** Build NestJS module to communicate with OpenClaw
3. **Add Chat Interface:** Integrate OpenClaw responses into the dashboard chat
4. **Configure Channels:** Set up messaging channels (WhatsApp, Telegram, etc.)
5. **Create Automation Workflows:** Build security automation using OpenClaw

## Resources

- **OpenClaw Documentation:** https://docs.openclaw.ai
- **GitHub Repository:** https://github.com/openclaw/openclaw
- **Discord Community:** https://discord.gg/clawd
- **Getting Started:** https://docs.openclaw.ai/start/getting-started

## Support

For issues or questions:
1. Check the logs: `/var/log/openclaw-gateway.log`
2. Review OpenClaw documentation
3. Join the Discord community
4. Open an issue on GitHub

---

**Installation Date:** 2026-02-03  
**Installed By:** Shahil AppDev  
**Server:** qatar-one.app (157.180.107.154)
