"""Event-Driven Architecture for the orchestrator"""

import uuid
import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable

from ..models.learning_models import EventLearningModel
from ..utils.data_structures import EventBus


class EventDrivenArchitecture:
    """Event-Driven Architecture for managing events"""
    
    def __init__(self, agent_manager, task_distributor, resource_manager, knowledge_graph, security_module):
        self.agent_manager = agent_manager
        self.task_distributor = task_distributor
        self.resource_manager = resource_manager
        self.knowledge_graph = knowledge_graph
        self.security_module = security_module
        self.event_bus = EventBus()
        self.event_handlers: Dict[str, List[Callable]] = {}
        self.event_history: List[Dict] = []
        self.event_learning = EventLearningModel()
        
        self._initialize_event_driven_architecture()
    
    def _initialize_event_driven_architecture(self):
        """Initialize the event-driven architecture"""
        self._register_default_event_handlers()
        self.event_learning.initialize()
    
    def _register_default_event_handlers(self):
        """Register default event handlers"""
        self.register_event_handler('agent.registered', self._handle_agent_registered)
        self.register_event_handler('agent.initialized', self._handle_agent_initialized)
        self.register_event_handler('agent.heartbeat', self._handle_agent_heartbeat)
        self.register_event_handler('agent.status.changed', self._handle_agent_status_changed)
        
        self.register_event_handler('task.created', self._handle_task_created)
        self.register_event_handler('task.queued', self._handle_task_queued)
        self.register_event_handler('task.assigned', self._handle_task_assigned)
        self.register_event_handler('task.completed', self._handle_task_completed)
        self.register_event_handler('task.failed', self._handle_task_failed)
        
        self.register_event_handler('resource.registered', self._handle_resource_registered)
        self.register_event_handler('resource.allocated', self._handle_resource_allocated)
        self.register_event_handler('resource.released', self._handle_resource_released)
        self.register_event_handler('resource.heartbeat', self._handle_resource_heartbeat)
        
        self.register_event_handler('security.event', self._handle_security_event)
        self.register_event_handler('security.alert', self._handle_security_alert)
        
        self.register_event_handler('system.startup', self._handle_system_startup)
        self.register_event_handler('system.shutdown', self._handle_system_shutdown)
    
    def register_event_handler(self, event_type: str, handler: Callable) -> bool:
        """Register an event handler for a specific event type"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        
        self.event_handlers[event_type].append(handler)
        self.event_bus.subscribe(event_type, handler)
        return True
    
    def unregister_event_handler(self, event_type: str, handler: Callable) -> bool:
        """Unregister an event handler for a specific event type"""
        if event_type in self.event_handlers:
            if handler in self.event_handlers[event_type]:
                self.event_handlers[event_type].remove(handler)
                self.event_bus.unsubscribe(event_type, handler)
                return True
        return False
    
    def publish_event(self, event_type: str, event_data: Dict) -> str:
        """Publish an event to the event bus"""
        event = {
            'event_id': str(uuid.uuid4()),
            'type': event_type,
            'data': event_data,
            'timestamp': datetime.now(),
            'processed': False
        }
        
        self.event_bus.publish(event)
        self._log_event(event)
        self.event_learning.update_event(event)
        
        return event['event_id']
    
    def _handle_agent_registered(self, event: Dict):
        """Handle agent registered event"""
        agent_id = event['data'].get('agent_id')
        if agent_id:
            self.knowledge_graph.add_agent(agent_id, {
                'status': 'registered',
                'last_updated': datetime.now()
            })
            
            self.security_module.audit_access(
                subject='system',
                resource=f'agent_{agent_id}',
                action='register',
                result='success'
            )
    
    def _handle_agent_initialized(self, event: Dict):
        """Handle agent initialized event"""
        agent_id = event['data'].get('agent_id')
        if agent_id:
            self.knowledge_graph.update_agent_status(agent_id, 'initialized')
            
            self.security_module.audit_access(
                subject='system',
                resource=f'agent_{agent_id}',
                action='initialize',
                result='success'
            )
    
    def _handle_agent_heartbeat(self, event: Dict):
        """Handle agent heartbeat event"""
        agent_id = event['data'].get('agent_id')
        if agent_id:
            self.agent_manager.update_agent_status(agent_id, {'last_heartbeat': datetime.now()})
            self.knowledge_graph.update_agent_status(agent_id, 'active')
    
    def _handle_agent_status_changed(self, event: Dict):
        """Handle agent status changed event"""
        agent_id = event['data'].get('agent_id')
        status = event['data'].get('status')
        if agent_id and status:
            self.knowledge_graph.update_agent_status(agent_id, status)
            
            self.security_module.audit_access(
                subject='system',
                resource=f'agent_{agent_id}',
                action='status_change',
                result=status
            )
    
    def _handle_task_created(self, event: Dict):
        """Handle task created event"""
        task_id = event['data'].get('task_id')
        if task_id:
            self.knowledge_graph.add_task(task_id, {
                'status': 'created',
                'last_updated': datetime.now()
            })
            
            self.security_module.audit_access(
                subject='system',
                resource=f'task_{task_id}',
                action='create',
                result='success'
            )
    
    def _handle_task_queued(self, event: Dict):
        """Handle task queued event"""
        task_id = event['data'].get('task_id')
        if task_id:
            self.knowledge_graph.update_task_status(task_id, 'queued')
    
    def _handle_task_assigned(self, event: Dict):
        """Handle task assigned event"""
        task_id = event['data'].get('task_id')
        agent_id = event['data'].get('agent_id')
        if task_id and agent_id:
            self.knowledge_graph.update_task_status(task_id, 'assigned', agent_id)
            
            rel_id = f"agent_task_{agent_id}_{task_id}"
            self.knowledge_graph.add_relationship(
                rel_id,
                'assigned_to',
                agent_id,
                task_id,
                {'type': 'task_assignment'}
            )
            
            self.security_module.audit_access(
                subject=f'agent_{agent_id}',
                resource=f'task_{task_id}',
                action='assign',
                result='success'
            )
    
    def _handle_task_completed(self, event: Dict):
        """Handle task completed event"""
        task_id = event['data'].get('task_id')
        agent_id = event['data'].get('agent_id')
        if task_id and agent_id:
            self.knowledge_graph.update_task_status(task_id, 'completed', agent_id)
            
            self.security_module.audit_access(
                subject=f'agent_{agent_id}',
                resource=f'task_{task_id}',
                action='complete',
                result='success'
            )
    
    def _handle_task_failed(self, event: Dict):
        """Handle task failed event"""
        task_id = event['data'].get('task_id')
        agent_id = event['data'].get('agent_id')
        reason = event['data'].get('reason', 'unknown')
        if task_id:
            self.knowledge_graph.update_task_status(task_id, 'failed')
            
            if reason != 'unknown':
                self.security_module._generate_security_event(
                    'task_failed',
                    f"Task {task_id} failed with reason: {reason}",
                    6
                )
            
            self.security_module.audit_access(
                subject=f'agent_{agent_id}' if agent_id else 'system',
                resource=f'task_{task_id}',
                action='complete',
                result='failed'
            )
    
    def _handle_resource_registered(self, event: Dict):
        """Handle resource registered event"""
        resource_id = event['data'].get('resource_id')
        if resource_id:
            self.knowledge_graph.add_resource(resource_id, {
                'status': 'registered',
                'last_updated': datetime.now()
            })
            
            self.security_module.audit_access(
                subject='system',
                resource=f'resource_{resource_id}',
                action='register',
                result='success'
            )
    
    def _handle_resource_allocated(self, event: Dict):
        """Handle resource allocated event"""
        resource_id = event['data'].get('resource_id')
        agent_id = event['data'].get('agent_id')
        if resource_id and agent_id:
            self.knowledge_graph.update_resource_status(resource_id, 'allocated')
            
            rel_id = f"agent_resource_{agent_id}_{resource_id}"
            self.knowledge_graph.add_relationship(
                rel_id,
                'allocated_to',
                resource_id,
                agent_id,
                {'type': 'resource_allocation'}
            )
            
            self.security_module.audit_access(
                subject=f'agent_{agent_id}',
                resource=f'resource_{resource_id}',
                action='allocate',
                result='success'
            )
    
    def _handle_resource_released(self, event: Dict):
        """Handle resource released event"""
        resource_id = event['data'].get('resource_id')
        if resource_id:
            self.knowledge_graph.update_resource_status(resource_id, 'available')
            
            self.security_module.audit_access(
                subject='system',
                resource=f'resource_{resource_id}',
                action='release',
                result='success'
            )
    
    def _handle_resource_heartbeat(self, event: Dict):
        """Handle resource heartbeat event"""
        resource_id = event['data'].get('resource_id')
        if resource_id:
            self.resource_manager.update_resource_status(resource_id, {'last_heartbeat': datetime.now()})
            self.knowledge_graph.update_resource_status(resource_id, 'active')
    
    def _handle_security_event(self, event: Dict):
        """Handle security event"""
        event_id = event['data'].get('event_id')
        if event_id:
            self.knowledge_graph.add_security_event(event_id, {
                'status': 'new',
                'last_updated': datetime.now()
            })
    
    def _handle_security_alert(self, event: Dict):
        """Handle security alert"""
        alert_id = event['data'].get('alert_id')
        if alert_id:
            self.knowledge_graph.add_alert(alert_id, {
                'status': 'new',
                'last_updated': datetime.now()
            })
    
    def _handle_system_startup(self, event: Dict):
        """Handle system startup event"""
        self.knowledge_graph.update_system_status('running')
        
        self.security_module.audit_access(
            subject='system',
            resource='system',
            action='startup',
            result='success'
        )
    
    def _handle_system_shutdown(self, event: Dict):
        """Handle system shutdown event"""
        self.knowledge_graph.update_system_status('shutting_down')
        
        self.security_module.audit_access(
            subject='system',
            resource='system',
            action='shutdown',
            result='success'
        )
    
    def _log_event(self, event: Dict):
        """Log an event to the event history"""
        self.event_history.append(event)
        
        if len(self.event_history) > 10000:
            self.event_history = self.event_history[-10000:]
    
    def get_event_history(self, event_type: Optional[str] = None, 
                         start_time: Optional[datetime] = None, 
                         end_time: Optional[datetime] = None) -> List[Dict]:
        """Get event history with filtering"""
        filtered_events = self.event_history
        
        if event_type:
            filtered_events = [e for e in filtered_events if e['type'] == event_type]
        if start_time:
            filtered_events = [e for e in filtered_events if e['timestamp'] >= start_time]
        if end_time:
            filtered_events = [e for e in filtered_events if e['timestamp'] <= end_time]
        
        return filtered_events
    
    def get_event_learning_insights(self, event_type: Optional[str] = None) -> Dict:
        """Get learning insights for specific event types or all events"""
        if event_type:
            return self.event_learning.get_insights(event_type)
        else:
            return self.event_learning.get_insights()
    
    def register_custom_event_handler(self, event_type: str, handler: Callable) -> bool:
        """Register a custom event handler for a specific event type"""
        return self.register_event_handler(event_type, handler)
    
    def unregister_custom_event_handler(self, event_type: str, handler: Callable) -> bool:
        """Unregister a custom event handler for a specific event type"""
        return self.unregister_event_handler(event_type, handler)
    
    def publish_custom_event(self, event_type: str, event_data: Dict) -> str:
        """Publish a custom event to the event bus"""
        return self.publish_event(event_type, event_data)
    
    def get_event_handlers(self, event_type: Optional[str] = None) -> Any:
        """Get event handlers for a specific event type or all event types"""
        if event_type:
            return self.event_handlers.get(event_type, [])
        else:
            return self.event_handlers
    
    def get_event_types(self) -> List[str]:
        """Get all registered event types"""
        return list(self.event_handlers.keys())
    
    def get_event_count(self, event_type: Optional[str] = None) -> int:
        """Get the count of events for a specific event type or all events"""
        if event_type:
            return len([e for e in self.event_history if e['type'] == event_type])
        else:
            return len(self.event_history)
    
    def clear_event_history(self, event_type: Optional[str] = None) -> bool:
        """Clear the event history for a specific event type or all events"""
        if event_type:
            self.event_history = [e for e in self.event_history if e['type'] != event_type]
        else:
            self.event_history = []
        return True
