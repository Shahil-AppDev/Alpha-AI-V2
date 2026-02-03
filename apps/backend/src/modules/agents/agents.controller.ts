import { Controller, Get, Post, Body, Param, UseGuards, Patch } from '@nestjs/common';
import { AgentsService } from './agents.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';

@Controller('api/agents')
@UseGuards(JwtAuthGuard)
export class AgentsController {
  constructor(private agentsService: AgentsService) {}

  @Get()
  getAllAgents() {
    return {
      agents: this.agentsService.getAllAgents(),
      stats: this.agentsService.getAgentStats(),
    };
  }

  @Get('stats')
  getStats() {
    return this.agentsService.getAgentStats();
  }

  @Get(':id')
  getAgent(@Param('id') id: string) {
    const agent = this.agentsService.getAgent(id);
    if (!agent) {
      return { error: 'Agent not found' };
    }
    return agent;
  }

  @Post(':id/execute')
  async executeTask(@Param('id') id: string, @Body() body: { task: string }) {
    try {
      const result = await this.agentsService.executeAgentTask(id, body.task);
      return {
        success: true,
        result,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  @Patch(':id/status')
  updateStatus(
    @Param('id') id: string,
    @Body() body: { status: 'active' | 'standby' | 'offline' },
  ) {
    try {
      const agent = this.agentsService.updateAgentStatus(id, body.status);
      return {
        success: true,
        agent,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }
}
