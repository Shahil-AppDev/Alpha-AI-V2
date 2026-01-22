"""
Enhanced AI Agent Orchestrator - Main Entry Point
Comprehensive system for managing AI agents with advanced capabilities
"""

from typing import Dict, Optional
from .core.agent_manager import IntelligentAgentManager
from .core.task_distributor import AdvancedTaskDistributor
from .core.resource_manager import DynamicResourceManager
from .core.monitoring_system import AIPoweredMonitoringSystem
from .core.security_module import EnterpriseGradeSecurityModule
from .core.knowledge_graph import KnowledgeGraph
from .core.ml_engine import MachineLearningEngine
from .core.event_architecture import EventDrivenArchitecture


class EnhancedOrchestrator:
    """Enhanced AI Agent Orchestrator with comprehensive capabilities"""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the enhanced orchestrator"""
        self.config = config or {}
        
        self.agent_manager = IntelligentAgentManager()
        self.resource_manager = DynamicResourceManager()
        self.knowledge_graph = KnowledgeGraph()
        
        self.task_distributor = AdvancedTaskDistributor(
            self.agent_manager,
            self.resource_manager,
            self.knowledge_graph
        )
        
        self.security_module = EnterpriseGradeSecurityModule(
            self.agent_manager,
            self.task_distributor,
            self.knowledge_graph
        )
        
        self.monitoring_system = AIPoweredMonitoringSystem(
            self.agent_manager,
            self.task_distributor,
            self.resource_manager,
            self.knowledge_graph
        )
        
        self.event_architecture = EventDrivenArchitecture(
            self.agent_manager,
            self.task_distributor,
            self.resource_manager,
            self.knowledge_graph,
            self.security_module
        )
        
        self.ml_engine = MachineLearningEngine()
        
        self._initialized = False
    
    def initialize(self, security_policies: Optional[Dict] = None):
        """Initialize the orchestrator with security policies"""
        if security_policies:
            self.security_module.load_security_policies(security_policies)
        
        self.event_architecture.publish_event('system.startup', {'status': 'running'})
        
        self._initialized = True
        return True
    
    def start_monitoring(self):
        """Start the monitoring system"""
        if not self._initialized:
            raise RuntimeError("Orchestrator must be initialized before starting monitoring")
        
        self.monitoring_system.start_monitoring()
        return True
    
    def register_agent(self, agent_id: str, agent_type: str, config: Dict) -> str:
        """Register a new agent"""
        is_valid, message = self.security_module.validate_agent(agent_id, config)
        if not is_valid:
            raise ValueError(f"Agent validation failed: {message}")
        
        registered_id = self.agent_manager.register_agent(agent_id, agent_type, config)
        
        self.event_architecture.publish_event('agent.registered', {
            'agent_id': registered_id,
            'agent_type': agent_type
        })
        
        return registered_id
    
    def initialize_agent(self, agent_id: str):
        """Initialize an agent"""
        agent = self.agent_manager.initialize_agent(agent_id)
        
        self.event_architecture.publish_event('agent.initialized', {
            'agent_id': agent_id
        })
        
        return agent
    
    def register_resource(self, resource_id: str, resource_type: str, config: Dict) -> str:
        """Register a new resource"""
        registered_id = self.resource_manager.register_resource(resource_id, resource_type, config)
        
        self.event_architecture.publish_event('resource.registered', {
            'resource_id': registered_id,
            'resource_type': resource_type
        })
        
        return registered_id
    
    def add_task(self, task_data: Dict, priority: Optional[int] = None) -> str:
        """Add a new task"""
        is_valid, message = self.security_module.validate_task(task_data)
        if not is_valid:
            raise ValueError(f"Task validation failed: {message}")
        
        task_id = self.task_distributor.add_task(task_data, priority)
        
        self.event_architecture.publish_event('task.created', {
            'task_id': task_id,
            'type': task_data.get('type', 'custom')
        })
        
        self.event_architecture.publish_event('task.queued', {
            'task_id': task_id
        })
        
        return task_id
    
    def distribute_tasks(self):
        """Distribute tasks to agents"""
        self.task_distributor.distribute_tasks()
    
    def create_ml_model(self, model_id: str, model_type: str, config: Dict) -> str:
        """Create a new machine learning model"""
        return self.ml_engine.create_model(model_id, model_type, config)
    
    def train_ml_model(self, model_id: str, training_data: list) -> bool:
        """Train a machine learning model"""
        return self.ml_engine.train_model(model_id, training_data)
    
    def get_system_status(self) -> Dict:
        """Get overall system status"""
        return {
            'agents': {
                'total': len(self.agent_manager.list_agents()),
                'status': {
                    agent_id: status['status']
                    for agent_id, status in self.agent_manager.agent_status.items()
                }
            },
            'tasks': {
                'queued': self.task_distributor.task_queue.size(),
                'history': len(self.task_distributor.task_history)
            },
            'resources': {
                'total': len(self.resource_manager.resources),
                'available': len(self.resource_manager.get_available_resources())
            },
            'alerts': {
                'total': len(self.monitoring_system.alerts),
                'new': len([a for a in self.monitoring_system.alerts if a['status'] == 'new'])
            },
            'ml_models': {
                'total': len(self.ml_engine.list_models())
            }
        }
    
    def shutdown(self):
        """Shutdown the orchestrator"""
        self.event_architecture.publish_event('system.shutdown', {'status': 'shutting_down'})
        self._initialized = False
        return True


def create_orchestrator(config: Optional[Dict] = None) -> EnhancedOrchestrator:
    """Factory function to create an orchestrator instance"""
    return EnhancedOrchestrator(config)


if __name__ == "__main__":
    orchestrator = create_orchestrator()
    
    security_policies = {
        'agent_validation': {
            'signature_required': True,
            'certificate_required': True,
            'permission_levels': ['basic', 'advanced', 'admin'],
            'identity_verification': True
        },
        'task_validation': {
            'authorization_required': True,
            'safety_checks': ['malicious_content', 'resource_exhaustion', 'data_integrity'],
            'resource_limits': {
                'cpu': 80,
                'memory': 80,
                'storage': 90
            }
        },
        'access_control': {
            'default_permissions': {
                'basic': ['agent.register', 'agent.heartbeat'],
                'advanced': ['agent.register', 'agent.heartbeat', 'task.create', 'task.execute'],
                'admin': ['*']
            }
        }
    }
    
    orchestrator.initialize(security_policies)
    orchestrator.start_monitoring()
    
    print("Enhanced AI Agent Orchestrator initialized successfully!")
    print(f"System Status: {orchestrator.get_system_status()}")
