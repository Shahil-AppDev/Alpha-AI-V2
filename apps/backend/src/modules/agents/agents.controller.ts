import { Body, Controller, Get, Param, Patch, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { AgentsService } from './agents.service';

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
      const err = error as Error;
      return {
        success: false,
        error: err.message,
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
      const err = error as Error;
      return {
        success: false,
        error: err.message,
      };
    }
  }
}
