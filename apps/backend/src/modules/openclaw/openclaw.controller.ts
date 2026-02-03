import { Controller, Post, Get, Body, UseGuards, Request } from '@nestjs/common';
import { OpenClawService } from './openclaw.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';

@Controller('api/openclaw')
@UseGuards(JwtAuthGuard)
export class OpenClawController {
  constructor(private openClawService: OpenClawService) {}

  @Post('chat')
  async chat(@Body() body: { message: string }, @Request() req) {
    return this.openClawService.chat(body.message, req.user.userId);
  }

  @Get('tools')
  async getTools() {
    return {
      tools: this.openClawService.getAvailableTools(),
      connected: this.openClawService.isConnected(),
    };
  }

  @Post('tool/execute')
  async executeTool(@Body() body: { tool: string; params: any }) {
    return this.openClawService.executeToolCommand(body.tool, body.params);
  }

  @Get('status')
  async getStatus() {
    return {
      connected: this.openClawService.isConnected(),
      timestamp: new Date(),
    };
  }
}
