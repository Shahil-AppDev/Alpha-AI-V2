import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { WebSocket } from 'ws';


interface ToolContext {
  name: string;
  description: string;
  execute: (params: any) => Promise<any>;
}

@Injectable()
export class OpenClawService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(OpenClawService.name);
  private ws: WebSocket;
  private readonly gatewayUrl = process.env.OPENCLAW_GATEWAY_URL || 'ws://127.0.0.1:18789';
  private readonly token = process.env.OPENCLAW_TOKEN;
  private reconnectInterval: NodeJS.Timeout;
  private messageQueue: Map<string, (response: any) => void> = new Map();
  private tools: Map<string, ToolContext> = new Map();

  async onModuleInit() {
    this.registerSecurityTools();
    // Attempting OpenClaw connection
    this.logger.log('Initializing OpenClaw connection...');
    this.connect();
  }

  async onModuleDestroy() {
    if (this.reconnectInterval) {
      clearInterval(this.reconnectInterval);
    }
    if (this.ws) {
      this.ws.close();
    }
  }

  private registerSecurityTools() {
    // Network Scanner
    this.registerTool({
      name: 'network_scan',
      description: 'Scan networks and hosts for open ports, services, and vulnerabilities',
      execute: async () => {
        return {
          tool: 'network_scan',
          status: 'available',
          description: 'Network scanning tool for security assessment',
        };
      },
    });

    // Code Analysis
    this.registerTool({
      name: 'code_analysis',
      description: 'Analyze code snippets for security vulnerabilities using static analysis',
      execute: async () => {
        return {
          tool: 'code_analysis',
          status: 'available',
          description: 'Static code analysis for vulnerability detection',
        };
      },
    });

    // Exploit Tools
    this.registerTool({
      name: 'exploit_tools',
      description: 'Generate reverse shell payloads and adapt exploit templates',
      execute: async () => {
        return {
          tool: 'exploit_tools',
          status: 'available',
          description: 'Exploit generation and payload creation',
        };
      },
    });

    // Password Cracker
    this.registerTool({
      name: 'password_cracker',
      description: 'Crack password hashes using various algorithms and wordlists',
      execute: async () => {
        return {
          tool: 'password_cracker',
          status: 'available',
          description: 'Password hash cracking with Hashcat',
        };
      },
    });

    // AnyDesk Backdoor
    this.registerTool({
      name: 'anydesk_backdoor',
      description: 'Remote desktop backdoor tool for penetration testing',
      execute: async () => {
        return {
          tool: 'anydesk_backdoor',
          status: 'available',
          description: 'Remote access tool for security assessment',
        };
      },
    });

    // RustDesk
    this.registerTool({
      name: 'rustdesk',
      description: 'Open-source remote desktop solution with self-hosting capabilities',
      execute: async () => {
        return {
          tool: 'rustdesk',
          status: 'available',
          description: 'Self-hosted remote desktop solution',
        };
      },
    });

    // Reverse Engineer
    this.registerTool({
      name: 'reverse_engineer',
      description: 'Advanced JavaScript code analysis, deobfuscation, and pattern detection',
      execute: async () => {
        return {
          tool: 'reverse_engineer',
          status: 'available',
          description: 'JavaScript reverse engineering and analysis',
        };
      },
    });

    // BeEF Security
    this.registerTool({
      name: 'beef_security',
      description: 'Browser security testing for educational awareness training',
      execute: async () => {
        return {
          tool: 'beef_security',
          status: 'available',
          description: 'Browser exploitation framework for security testing',
        };
      },
    });

    // Defensive Security Training
    this.registerTool({
      name: 'defensive_security',
      description: 'Educational threat analysis and defensive strategy training',
      execute: async () => {
        return {
          tool: 'defensive_security',
          status: 'available',
          description: 'Defensive security training and threat analysis',
        };
      },
    });

    this.logger.log(`Registered ${this.tools.size} security tools with OpenClaw`);
  }

  private registerTool(tool: ToolContext) {
    this.tools.set(tool.name, tool);
  }

  async connect() {
    try {
      this.ws = new WebSocket(this.gatewayUrl);

      this.ws.on('open', () => {
        this.logger.log('Connected to OpenClaw gateway');
        
        // Send connect message with auth token according to OpenClaw protocol
        const connectMessage = {
          type: 'connect',
          params: {
            auth: {
              token: this.token,
            },
          },
        };
        this.ws.send(JSON.stringify(connectMessage));
      });

      this.ws.on('message', (data) => {
        this.handleMessage(data.toString());
      });

      this.ws.on('error', (error) => {
        this.logger.error(`WebSocket error: ${error.message}`);
      });

      this.ws.on('close', () => {
        this.logger.warn('Disconnected from OpenClaw gateway. Reconnecting...');
        this.scheduleReconnect();
      });
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Failed to connect to OpenClaw: ${err.message}`);
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect() {
    if (!this.reconnectInterval) {
      this.reconnectInterval = setInterval(() => {
        this.logger.log('Attempting to reconnect to OpenClaw gateway...');
        this.connect();
      }, 5000);
    }
  }

  private handleMessage(data: string) {
    try {
      const message = JSON.parse(data);
      this.logger.debug(`Received message: ${JSON.stringify(message)}`);

      // Handle authentication challenge
      if (message.type === 'event' && message.event === 'connect.challenge') {
        this.logger.log('Received OpenClaw authentication challenge');
        const challengeResponse = {
          type: 'connect.response',
          params: {
            auth: {
              token: this.token,
              nonce: message.payload?.nonce,
            },
          },
        };
        this.ws.send(JSON.stringify(challengeResponse));
        this.logger.debug('Sent challenge response');
        return;
      }

      // Handle authenticated confirmation
      if (message.type === 'event' && message.event === 'connect.authenticated') {
        this.logger.log('Successfully authenticated with OpenClaw gateway');
        this.sendToolsManifest();
        return;
      }

      // Handle connection errors
      if (message.type === 'error') {
        this.logger.error(`OpenClaw error: ${message.error || 'Unknown error'}`);
        return;
      }

      if (message.id && this.messageQueue.has(message.id)) {
        const resolver = this.messageQueue.get(message.id);
        resolver(message);
        this.messageQueue.delete(message.id);
      }
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Failed to parse message: ${err.message}`);
    }
  }

  private sendToolsManifest() {
    const manifest = {
      type: 'tools_manifest',
      tools: Array.from(this.tools.values()).map(tool => ({
        name: tool.name,
        description: tool.description,
      })),
    };

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(manifest));
      this.logger.log('Sent tools manifest to OpenClaw');
    }
  }

  async sendMessage(message: string, context?: any): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error('WebSocket not connected'));
        return;
      }

      const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const payload = {
        id: messageId,
        message,
        context,
        timestamp: new Date().toISOString(),
      };

      this.messageQueue.set(messageId, resolve);

      this.ws.send(JSON.stringify(payload));

      setTimeout(() => {
        if (this.messageQueue.has(messageId)) {
          this.messageQueue.delete(messageId);
          reject(new Error('Message timeout'));
        }
      }, 30000);
    });
  }

  async chat(message: string, userId?: string): Promise<any> {
    try {
      const context = {
        userId,
        availableTools: Array.from(this.tools.keys()),
        timestamp: new Date().toISOString(),
      };

      const response = await this.sendMessage(message, context);
      return {
        success: true,
        message: response.response || response.message,
        timestamp: new Date(),
      };
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Chat error: ${err.message}`);
      return {
        success: false,
        error: err.message,
        timestamp: new Date(),
      };
    }
  }

  async executeToolCommand(toolName: string, params: any): Promise<any> {
    const tool = this.tools.get(toolName);
    if (!tool) {
      throw new Error(`Tool not found: ${toolName}`);
    }

    try {
      const result = await tool.execute(params);
      return {
        success: true,
        tool: toolName,
        result,
      };
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Tool execution error: ${err.message}`);
      return {
        success: false,
        tool: toolName,
        error: err.message,
      };
    }
  }

  getAvailableTools(): string[] {
    return Array.from(this.tools.keys());
  }

  isConnected(): boolean {
    return this.ws && this.ws.readyState === WebSocket.OPEN;
  }
}
