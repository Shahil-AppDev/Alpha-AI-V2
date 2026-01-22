"""Intelligent Agent Manager with learning capabilities"""

import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional

from ..models.learning_models import AgentLearningModel
from ..utils.data_structures import AgentProfile


class AgentCommunicationHub:
    """Hub for agent communication"""
    
    def __init__(self):
        self.agents: Dict[str, Any] = {}
        self.message_queue: List[Dict] = []
    
    def register_agent(self, agent_id: str):
        """Register an agent"""
        self.agents[agent_id] = {
            'status': 'registered',
            'last_message': None
        }
    
    def initialize_agent_communication(self, agent_id: str):
        """Initialize agent communication"""
        if agent_id in self.agents:
            self.agents[agent_id]['status'] = 'active'
    
    def get_agent_status(self, agent_id: str) -> Optional[Dict]:
        """Get agent communication status"""
        return self.agents.get(agent_id)
    
    def send_message(self, sender_id: str, receiver_id: str, message: Dict) -> bool:
        """Send message between agents"""
        if sender_id in self.agents and receiver_id in self.agents:
            self.message_queue.append({
                'from': sender_id,
                'to': receiver_id,
                'message': message,
                'timestamp': datetime.now()
            })
            return True
        return False
    
    def broadcast_message(self, sender_id: str, message: Dict, filters: Optional[Dict] = None) -> int:
        """Broadcast message to multiple agents"""
        count = 0
        for agent_id in self.agents:
            if agent_id != sender_id:
                if self.send_message(sender_id, agent_id, message):
                    count += 1
        return count


class AlphaAIV2Agent:
    """Alpha AI V2 Agent implementation"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.agent_id = config.get('agent_id', str(uuid.uuid4()))
        self.tasks: List[str] = []
        self.performance_metrics = {
            'tasks_completed': 0,
            'tasks_failed': 0,
            'success_rate': 0,
            'avg_response_time': 0
        }
    
    def assign_task(self, task_data: Dict):
        """Assign a task to this agent"""
        self.tasks.append(task_data['task_id'])
    
    def get_performance_metrics(self) -> Dict:
        """Get performance metrics"""
        if self.performance_metrics['tasks_completed'] + self.performance_metrics['tasks_failed'] > 0:
            total = self.performance_metrics['tasks_completed'] + self.performance_metrics['tasks_failed']
            self.performance_metrics['success_rate'] = (
                self.performance_metrics['tasks_completed'] / total * 100
            )
        return self.performance_metrics


class SpecializedAIAgent(AlphaAIV2Agent):
    """Specialized AI Agent"""
    pass


class ThirdPartyAIAdapter(AlphaAIV2Agent):
    """Third-party AI adapter"""
    pass


class IntelligentAgentManager:
    """Intelligent Agent Manager with enhanced capabilities"""
    
    def __init__(self):
        self.agents: Dict[str, Any] = {}
        self.agent_configs: Dict[str, Dict] = {}
        self.agent_status: Dict[str, Dict] = {}
        self.agent_profiles: Dict[str, AgentProfile] = {}
        self.agent_learning: Dict[str, AgentLearningModel] = {}
        self.agent_communication = AgentCommunicationHub()
    
    def register_agent(self, agent_id: str, agent_type: str, config: Dict) -> str:
        """Register a new AI agent with enhanced capabilities"""
        if not self._validate_agent_config(config):
            raise ValueError("Invalid agent configuration")
        
        self.agent_profiles[agent_id] = AgentProfile(
            agent_id=agent_id,
            capabilities=config.get('capabilities', []),
            preferences=config.get('preferences', {}),
            learning_style=config.get('learning_style', 'default'),
            communication_protocols=config.get('communication_protocols', ['default']),
            last_updated=datetime.now()
        )
        
        self.agent_learning[agent_id] = AgentLearningModel(agent_id)
        self.agent_communication.register_agent(agent_id)
        
        self.agents[agent_id] = None
        self.agent_configs[agent_id] = config
        self.agent_status[agent_id] = {
            'status': 'registered',
            'last_heartbeat': None,
            'tasks': [],
            'resources': {},
            'performance_metrics': {},
            'learning_progress': {},
            'completed_tasks': []
        }
        
        return agent_id
    
    def initialize_agent(self, agent_id: str):
        """Initialize an agent instance with enhanced capabilities"""
        if agent_id not in self.agents:
            raise ValueError(f"Agent {agent_id} not registered")
        
        config = self.agent_configs[agent_id]
        config['agent_id'] = agent_id
        
        if config['type'] == 'alpha_ai_v2':
            self.agents[agent_id] = AlphaAIV2Agent(config)
        elif config['type'] == 'specialized':
            self.agents[agent_id] = SpecializedAIAgent(config)
        elif config['type'] == 'third_party':
            self.agents[agent_id] = ThirdPartyAIAdapter(config)
        else:
            raise ValueError(f"Unknown agent type: {config['type']}")
        
        self.agent_communication.initialize_agent_communication(agent_id)
        self.agent_status[agent_id]['status'] = 'initialized'
        self._update_agent_performance_metrics(agent_id)
        
        return self.agents[agent_id]
    
    def _validate_agent_config(self, config: Dict) -> bool:
        """Validate agent configuration with enhanced checks"""
        required_fields = ['type', 'version', 'capabilities']
        for field in required_fields:
            if field not in config:
                return False
        
        if not isinstance(config['capabilities'], list):
            return False
        
        if 'communication_protocols' in config:
            valid_protocols = ['default', 'grpc', 'websockets', 'rest']
            for protocol in config['communication_protocols']:
                if protocol not in valid_protocols:
                    return False
        
        return True
    
    def _update_agent_performance_metrics(self, agent_id: str):
        """Update performance metrics for an agent"""
        if agent_id in self.agents and self.agents[agent_id] is not None:
            metrics = self.agents[agent_id].get_performance_metrics()
            self.agent_status[agent_id]['performance_metrics'] = metrics
    
    def get_agent_profile(self, agent_id: str) -> Optional[AgentProfile]:
        """Get the profile of an agent"""
        return self.agent_profiles.get(agent_id)
    
    def update_agent_profile(self, agent_id: str, profile_update: Dict) -> bool:
        """Update the profile of an agent"""
        if agent_id in self.agent_profiles:
            for key, value in profile_update.items():
                setattr(self.agent_profiles[agent_id], key, value)
            self.agent_profiles[agent_id].last_updated = datetime.now()
            return True
        return False
    
    def get_agent_learning_status(self, agent_id: str) -> Optional[AgentLearningModel]:
        """Get the learning status of an agent"""
        return self.agent_learning.get(agent_id)
    
    def update_agent_learning(self, agent_id: str, learning_data: Dict) -> bool:
        """Update the learning model of an agent"""
        if agent_id in self.agent_learning:
            self.agent_learning[agent_id].update(learning_data)
            return True
        return False
    
    def enable_agent_learning(self, agent_id: str, learning_config: Dict) -> bool:
        """Enable learning for an agent"""
        if agent_id in self.agent_learning:
            self.agent_learning[agent_id].enable_learning(learning_config)
            return True
        return False
    
    def disable_agent_learning(self, agent_id: str) -> bool:
        """Disable learning for an agent"""
        if agent_id in self.agent_learning:
            self.agent_learning[agent_id].disable_learning()
            return True
        return False
    
    def get_agent_communication_status(self, agent_id: str) -> Optional[Dict]:
        """Get the communication status of an agent"""
        return self.agent_communication.get_agent_status(agent_id)
    
    def send_agent_message(self, sender_id: str, receiver_id: str, message: Dict) -> bool:
        """Send a message between agents"""
        return self.agent_communication.send_message(sender_id, receiver_id, message)
    
    def broadcast_agent_message(self, sender_id: str, message: Dict, filters: Optional[Dict] = None) -> int:
        """Broadcast a message to multiple agents"""
        return self.agent_communication.broadcast_message(sender_id, message, filters)
    
    def update_agent_status(self, agent_id: str, status_update: Dict) -> bool:
        """Update agent status"""
        if agent_id in self.agent_status:
            self.agent_status[agent_id].update(status_update)
            return True
        return False
    
    def get_agent_status(self, agent_id: str) -> Optional[Dict]:
        """Get agent status"""
        return self.agent_status.get(agent_id)
    
    def list_agents(self) -> List[str]:
        """List all registered agents"""
        return list(self.agents.keys())
    
    def remove_agent(self, agent_id: str) -> bool:
        """Remove an agent"""
        if agent_id in self.agents:
            del self.agents[agent_id]
            del self.agent_configs[agent_id]
            del self.agent_status[agent_id]
            if agent_id in self.agent_profiles:
                del self.agent_profiles[agent_id]
            if agent_id in self.agent_learning:
                del self.agent_learning[agent_id]
            return True
        return False
