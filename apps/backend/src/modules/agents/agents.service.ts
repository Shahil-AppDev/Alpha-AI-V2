import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import axios from 'axios';

export interface Agent {
  id: string;
  name: string;
  type: 'red-team' | 'blue-team' | 'purple-team' | 'black-hat' | 'llm-agent';
  status: 'active' | 'standby' | 'offline';
  model: string;
  description: string;
  capabilities: string[];
  stats: {
    tasksCompleted: number;
    successRate: number;
    lastActivity: Date;
  };
}

interface MixtralRequest {
  model: string;
  messages: Array<{ role: string; content: string }>;
  temperature?: number;
  max_tokens?: number;
}

interface MixtralResponse {
  choices: Array<{
    message: {
      role: string;
      content: string;
    };
  }>;
}

@Injectable()
export class AgentsService implements OnModuleInit {
  private readonly logger = new Logger(AgentsService.name);
  private agents: Map<string, Agent> = new Map();
  private readonly mixtralApiUrl = process.env.MIXTRAL_API_URL || 'http://localhost:8000/v1/chat/completions';
  private readonly mixtralModel = 'mixtralai/Mixtral-8x22B-Instruct-v0.1';

  async onModuleInit() {
    this.initializeAgents();
    this.logger.log('Agents initialized with Mixtral 22B');
  }

  private initializeAgents() {
    const agents: Agent[] = [
      {
        id: 'red-team-1',
        name: 'Red Team Agent',
        type: 'red-team',
        status: 'active',
        model: this.mixtralModel,
        description: 'Offensive security operations and penetration testing',
        capabilities: [
          'Network penetration testing',
          'Vulnerability exploitation',
          'Social engineering',
          'Payload generation',
          'Attack simulation',
        ],
        stats: {
          tasksCompleted: 87,
          successRate: 87,
          lastActivity: new Date(),
        },
      },
      {
        id: 'blue-team-1',
        name: 'Blue Team Agent',
        type: 'blue-team',
        status: 'active',
        model: this.mixtralModel,
        description: 'Defensive security operations and threat detection',
        capabilities: [
          'Threat detection',
          'Incident response',
          'Security monitoring',
          'Log analysis',
          'Defense strategy',
        ],
        stats: {
          tasksCompleted: 234,
          successRate: 92,
          lastActivity: new Date(),
        },
      },
      {
        id: 'purple-team-1',
        name: 'Purple Team Agent',
        type: 'purple-team',
        status: 'standby',
        model: this.mixtralModel,
        description: 'Collaborative security testing and validation',
        capabilities: [
          'Joint exercises',
          'Attack validation',
          'Defense validation',
          'Gap analysis',
          'Improvement recommendations',
        ],
        stats: {
          tasksCompleted: 18,
          successRate: 92,
          lastActivity: new Date(Date.now() - 2 * 60 * 60 * 1000),
        },
      },
      {
        id: 'black-hat-1',
        name: 'Black Hat Agent',
        type: 'black-hat',
        status: 'offline',
        model: this.mixtralModel,
        description: 'Advanced threat simulation and adversarial testing',
        capabilities: [
          'Advanced persistent threats',
          'Zero-day exploitation',
          'Malware analysis',
          'Threat intelligence',
          'Attack chain simulation',
        ],
        stats: {
          tasksCompleted: 67,
          successRate: 89,
          lastActivity: new Date(Date.now() - 24 * 60 * 60 * 1000),
        },
      },
      {
        id: 'llm-agent-1',
        name: 'LLM Agent',
        type: 'llm-agent',
        status: 'active',
        model: this.mixtralModel,
        description: 'AI-powered security analysis and automation',
        capabilities: [
          'Code analysis',
          'Vulnerability assessment',
          'Report generation',
          'Natural language queries',
          'Automated recommendations',
        ],
        stats: {
          tasksCompleted: 156,
          successRate: 94,
          lastActivity: new Date(),
        },
      },
    ];

    agents.forEach((agent) => {
      this.agents.set(agent.id, agent);
    });

    this.logger.log(`Initialized ${agents.length} agents with Mixtral 22B`);
  }

  async callMixtral(prompt: string, systemPrompt?: string): Promise<string> {
    try {
      const messages = [];
      
      if (systemPrompt) {
        messages.push({
          role: 'system',
          content: systemPrompt,
        });
      }

      messages.push({
        role: 'user',
        content: prompt,
      });

      const request: MixtralRequest = {
        model: this.mixtralModel,
        messages,
        temperature: 0.7,
        max_tokens: 2000,
      };

      this.logger.debug(`Calling Mixtral API: ${this.mixtralApiUrl}`);

      const response = await axios.post<MixtralResponse>(
        this.mixtralApiUrl,
        request,
        {
          headers: {
            'Content-Type': 'application/json',
          },
          timeout: 30000,
        },
      );

      if (response.data.choices && response.data.choices.length > 0) {
        return response.data.choices[0].message.content;
      }

      throw new Error('No response from Mixtral');
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Mixtral API error: ${err.message}`);
      throw new Error(`Failed to call Mixtral: ${err.message}`);
    }
  }

  async executeAgentTask(agentId: string, task: string): Promise<any> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    if (agent.status === 'offline') {
      throw new Error(`Agent is offline: ${agent.name}`);
    }

    const systemPrompt = this.getAgentSystemPrompt(agent);

    try {
      const response = await this.callMixtral(task, systemPrompt);

      agent.stats.tasksCompleted++;
      agent.stats.lastActivity = new Date();

      return {
        agentId: agent.id,
        agentName: agent.name,
        task,
        response,
        timestamp: new Date(),
      };
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Agent task execution failed: ${err.message}`);
      throw error;
    }
  }

  private getAgentSystemPrompt(agent: Agent): string {
    const basePrompt = `You are ${agent.name}, a specialized security agent with the following capabilities: ${agent.capabilities.join(', ')}.`;

    const rolePrompts = {
      'red-team': `${basePrompt} Your role is to think like an attacker and identify vulnerabilities, exploitation paths, and security weaknesses. Provide detailed offensive security analysis and recommendations.`,
      'blue-team': `${basePrompt} Your role is to defend systems and detect threats. Analyze security events, provide defensive strategies, and recommend security improvements.`,
      'purple-team': `${basePrompt} Your role is to bridge offensive and defensive security. Validate attacks and defenses, identify gaps, and provide collaborative security improvements.`,
      'black-hat': `${basePrompt} Your role is to simulate advanced persistent threats and sophisticated attacks. Think like a highly skilled adversary and identify complex attack chains.`,
      'llm-agent': `${basePrompt} Your role is to provide AI-powered security analysis, code review, vulnerability assessment, and automated security recommendations using advanced language understanding.`,
    };

    return rolePrompts[agent.type] || basePrompt;
  }

  getAllAgents(): Agent[] {
    return Array.from(this.agents.values());
  }

  getAgent(agentId: string): Agent | undefined {
    return this.agents.get(agentId);
  }

  updateAgentStatus(agentId: string, status: 'active' | 'standby' | 'offline'): Agent {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    agent.status = status;
    this.logger.log(`Agent ${agent.name} status updated to ${status}`);
    return agent;
  }

  getAgentStats() {
    const agents = this.getAllAgents();
    return {
      total: agents.length,
      active: agents.filter((a) => a.status === 'active').length,
      standby: agents.filter((a) => a.status === 'standby').length,
      offline: agents.filter((a) => a.status === 'offline').length,
      totalTasks: agents.reduce((sum, a) => sum + a.stats.tasksCompleted, 0),
      averageSuccessRate: agents.reduce((sum, a) => sum + a.stats.successRate, 0) / agents.length,
      model: this.mixtralModel,
    };
  }
}
