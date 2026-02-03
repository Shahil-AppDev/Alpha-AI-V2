import { Logger } from '@nestjs/common';
import {
    OnGatewayConnection,
    OnGatewayDisconnect,
    SubscribeMessage,
    WebSocketGateway,
    WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { AgentsService } from './agents.service';

@WebSocketGateway({
  cors: {
    origin: '*',
  },
  namespace: '/agents',
})
export class AgentsGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(AgentsGateway.name);

  constructor(private agentsService: AgentsService) {}

  handleConnection(client: Socket) {
    this.logger.log(`Client connected to agents gateway: ${client.id}`);
    
    const agents = this.agentsService.getAllAgents();
    client.emit('agents_list', { agents });
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected from agents gateway: ${client.id}`);
  }

  @SubscribeMessage('get_agents')
  handleGetAgents(client: Socket) {
    const agents = this.agentsService.getAllAgents();
    const stats = this.agentsService.getAgentStats();
    client.emit('agents_list', { agents, stats });
    return { agents, stats };
  }

  @SubscribeMessage('execute_agent_task')
  async handleExecuteTask(client: Socket, payload: { agentId: string; task: string }) {
    try {
      const result = await this.agentsService.executeAgentTask(payload.agentId, payload.task);
      client.emit('agent_task_result', { success: true, result });
      
      this.server.emit('agent_activity', {
        agentId: payload.agentId,
        activity: 'task_completed',
        timestamp: new Date(),
      });
      
      return { success: true, result };
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Agent task execution error: ${err.message}`);
      client.emit('agent_task_error', { error: err.message });
      return { success: false, error: err.message };
    }
  }

  @SubscribeMessage('update_agent_status')
  handleUpdateStatus(
    client: Socket,
    payload: { agentId: string; status: 'active' | 'standby' | 'offline' },
  ) {
    try {
      const agent = this.agentsService.updateAgentStatus(payload.agentId, payload.status);
      
      this.server.emit('agent_status_updated', {
        agentId: payload.agentId,
        status: payload.status,
        timestamp: new Date(),
      });
      
      return { success: true, agent };
    } catch (error) {
      const err = error as Error;
      this.logger.error(`Agent status update error: ${err.message}`);
      return { success: false, error: err.message };
    }
  }
}
