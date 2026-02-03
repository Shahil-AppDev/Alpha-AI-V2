import { Logger } from '@nestjs/common';
import {
    OnGatewayConnection,
    OnGatewayDisconnect,
    SubscribeMessage,
    WebSocketGateway,
    WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { OpenClawService } from './openclaw.service';

@WebSocketGateway({
  cors: {
    origin: '*',
  },
  namespace: '/openclaw',
})
export class OpenClawGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(OpenClawGateway.name);

  constructor(private openClawService: OpenClawService) {}

  handleConnection(client: Socket) {
    this.logger.log(`Client connected: ${client.id}`);
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected: ${client.id}`);
  }

  @SubscribeMessage('chat')
  async handleChat(client: Socket, payload: { message: string; userId?: string }) {
    this.logger.log(`Chat message from ${client.id}: ${payload.message}`);

    try {
      const response = await this.openClawService.chat(payload.message, payload.userId);
      client.emit('chat_response', response);
      return response;
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Chat error: ${err.message}`);
      client.emit('chat_error', { error: err.message });
      return { success: false, error: err.message };
    }
  }

  @SubscribeMessage('get_tools')
  async handleGetTools(client: Socket) {
    const tools = this.openClawService.getAvailableTools();
    client.emit('tools_list', { tools });
    return { tools };
  }

  @SubscribeMessage('execute_tool')
  async handleExecuteTool(client: Socket, payload: { tool: string; params: any }) {
    try {
      const result = await this.openClawService.executeToolCommand(payload.tool, payload.params);
      client.emit('tool_result', result);
      return result;
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Tool execution error: ${err.message}`);
      client.emit('tool_error', { error: err.message });
      return { success: false, error: err.message };
    }
  }
}
