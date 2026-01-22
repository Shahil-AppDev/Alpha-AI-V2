"""Knowledge Graph system for the orchestrator"""

from datetime import datetime
from typing import Dict, List, Any, Optional

from ..models.learning_models import KnowledgeLearningModel


class KnowledgeGraph:
    """Knowledge Graph for managing relationships and knowledge"""
    
    def __init__(self):
        self.entity_index: Dict[str, Dict] = {}
        self.relationship_index: Dict[str, Dict] = {}
        self.knowledge_base: Dict[str, Any] = {}
        self.knowledge_learning = KnowledgeLearningModel()
        
        self._initialize_entity_types()
        self._initialize_relationship_types()
        self.knowledge_learning.initialize()
    
    def _initialize_entity_types(self):
        """Initialize entity types"""
        entity_types = ['agent', 'task', 'resource', 'capability', 'security_event', 'alert']
        for entity_type in entity_types:
            self.entity_index[entity_type] = {'instances': {}}
    
    def _initialize_relationship_types(self):
        """Initialize relationship types"""
        relationship_types = [
            'has_capability', 'requires_capability', 'requires_resource',
            'depends_on', 'assigned_to', 'allocated_to'
        ]
        for rel_type in relationship_types:
            self.relationship_index[rel_type] = {'instances': {}}
    
    def add_agent(self, agent_id: str, properties: Dict):
        """Add an agent to the knowledge graph"""
        self.entity_index['agent']['instances'][agent_id] = {
            'id': agent_id,
            'type': 'agent',
            'properties': properties,
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        return agent_id
    
    def add_task(self, task_id: str, properties: Dict):
        """Add a task to the knowledge graph"""
        self.entity_index['task']['instances'][task_id] = {
            'id': task_id,
            'type': 'task',
            'properties': properties,
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        return task_id
    
    def add_resource(self, resource_id: str, properties: Dict):
        """Add a resource to the knowledge graph"""
        self.entity_index['resource']['instances'][resource_id] = {
            'id': resource_id,
            'type': 'resource',
            'properties': properties,
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        return resource_id
    
    def add_capability(self, capability_id: str, properties: Dict):
        """Add a capability to the knowledge graph"""
        self.entity_index['capability']['instances'][capability_id] = {
            'id': capability_id,
            'type': 'capability',
            'properties': properties,
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        return capability_id
    
    def add_security_event(self, event_id: str, properties: Dict):
        """Add a security event to the knowledge graph"""
        self.entity_index['security_event']['instances'][event_id] = {
            'id': event_id,
            'type': 'security_event',
            'properties': properties,
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        return event_id
    
    def add_alert(self, alert_id: str, properties: Dict):
        """Add an alert to the knowledge graph"""
        self.entity_index['alert']['instances'][alert_id] = {
            'id': alert_id,
            'type': 'alert',
            'properties': properties,
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        return alert_id
    
    def add_relationship(self, relationship_id: str, relationship_type: str, 
                        source_id: str, target_id: str, properties: Optional[Dict] = None):
        """Add a relationship between entities"""
        if relationship_type not in self.relationship_index:
            self.relationship_index[relationship_type] = {'instances': {}}
        
        self.relationship_index[relationship_type]['instances'][relationship_id] = {
            'id': relationship_id,
            'type': relationship_type,
            'source': source_id,
            'target': target_id,
            'properties': properties or {},
            'created_at': datetime.now()
        }
        return relationship_id
    
    def update_agent_status(self, agent_id: str, status: str):
        """Update agent status in knowledge graph"""
        if 'agent' in self.entity_index and agent_id in self.entity_index['agent']['instances']:
            self.entity_index['agent']['instances'][agent_id]['properties']['status'] = status
            self.entity_index['agent']['instances'][agent_id]['updated_at'] = datetime.now()
            return True
        return False
    
    def update_task_status(self, task_id: str, status: str, agent_id: Optional[str] = None):
        """Update task status in knowledge graph"""
        if 'task' in self.entity_index and task_id in self.entity_index['task']['instances']:
            self.entity_index['task']['instances'][task_id]['properties']['status'] = status
            self.entity_index['task']['instances'][task_id]['updated_at'] = datetime.now()
            if agent_id:
                self.entity_index['task']['instances'][task_id]['properties']['agent_id'] = agent_id
            return True
        return False
    
    def update_resource_status(self, resource_id: str, status: str):
        """Update resource status in knowledge graph"""
        if 'resource' in self.entity_index and resource_id in self.entity_index['resource']['instances']:
            self.entity_index['resource']['instances'][resource_id]['properties']['status'] = status
            self.entity_index['resource']['instances'][resource_id]['updated_at'] = datetime.now()
            return True
        return False
    
    def update_system_status(self, status: str):
        """Update system status"""
        self.knowledge_base['system_status'] = status
        self.knowledge_base['last_updated'] = datetime.now()
    
    def update_alert(self, alert: Dict):
        """Update alert in knowledge graph"""
        alert_id = alert.get('alert_id')
        if alert_id:
            self.add_alert(alert_id, alert)
    
    def update_task_relationships(self, task):
        """Update task relationships in knowledge graph"""
        if hasattr(task, 'task_id'):
            task_id = task.task_id
            if task_id in self.entity_index.get('task', {}).get('instances', {}):
                self.knowledge_learning.update_task_relationships(task)
                return True
        return False
    
    def get_relevant_knowledge(self, entity, entity_type: Optional[str] = None, depth: int = 2) -> Dict:
        """Get relevant knowledge about an entity"""
        if hasattr(entity, 'task_id'):
            entity_id = entity.task_id
            entity_type = 'task'
        else:
            entity_id = str(entity)
        
        if entity_type is None:
            for etype, entities in self.entity_index.items():
                if entity_id in entities['instances']:
                    entity_type = etype
                    break
        
        if entity_type and entity_id in self.entity_index.get(entity_type, {}).get('instances', {}):
            return {
                'entity': self.entity_index[entity_type]['instances'][entity_id],
                'direct_relationships': self._get_direct_relationships(entity_id, entity_type),
                'indirect_relationships': []
            }
        
        return {'entity': None, 'direct_relationships': [], 'indirect_relationships': []}
    
    def _get_direct_relationships(self, entity_id: str, entity_type: str) -> List[Dict]:
        """Get direct relationships for an entity"""
        relationships = []
        
        for rel_type, rel_data in self.relationship_index.items():
            for rel_id, rel in rel_data['instances'].items():
                if rel['source'] == entity_id:
                    relationships.append({
                        'relationship_id': rel_id,
                        'relationship_type': rel_type,
                        'target_id': rel['target'],
                        'target_type': self._get_entity_type(rel['target']),
                        'properties': rel['properties']
                    })
                elif rel['target'] == entity_id:
                    relationships.append({
                        'relationship_id': rel_id,
                        'relationship_type': rel_type,
                        'source_id': rel['source'],
                        'source_type': self._get_entity_type(rel['source']),
                        'properties': rel['properties']
                    })
        
        return relationships
    
    def _get_entity_type(self, entity_id: str) -> Optional[str]:
        """Get the type of an entity"""
        for etype, entities in self.entity_index.items():
            if entity_id in entities['instances']:
                return etype
        return None
    
    def calculate_agent_task_affinity(self, agent_id: str, task) -> float:
        """Calculate the affinity between an agent and a task"""
        score = 0
        
        if hasattr(task, 'required_capabilities'):
            agent_capabilities = self._get_agent_capabilities(agent_id)
            task_capabilities = task.required_capabilities
            
            for cap in task_capabilities:
                if cap in agent_capabilities:
                    score += 10
        
        self.knowledge_learning.update_agent_task_affinity(agent_id, task, score)
        
        return score
    
    def _get_agent_capabilities(self, agent_id: str) -> List[str]:
        """Get an agent's capabilities from the knowledge graph"""
        capabilities = []
        
        if 'agent' in self.entity_index and agent_id in self.entity_index['agent']['instances']:
            for rel_type, rel_data in self.relationship_index.items():
                if rel_type == 'has_capability':
                    for rel_id, rel in rel_data['instances'].items():
                        if rel['source'] == agent_id:
                            capabilities.append(rel['target'])
        
        return capabilities
    
    def get_knowledge_learning_insights(self) -> Dict:
        """Get learning insights from the knowledge graph"""
        return self.knowledge_learning.get_insights()
    
    def update_knowledge_base(self, knowledge_updates: Dict) -> bool:
        """Update the knowledge base with new information"""
        self.knowledge_base.update(knowledge_updates)
        self.knowledge_learning.update_knowledge_base(knowledge_updates)
        return True
    
    def query_knowledge_graph(self, query: Dict) -> Dict:
        """Query the knowledge graph with a structured query"""
        return {
            'results': [],
            'query': query,
            'timestamp': datetime.now()
        }
    
    def export_knowledge_graph(self, format: str = 'json') -> Dict:
        """Export the knowledge graph to a specific format"""
        return {
            'format': format,
            'data': {
                'entities': self.entity_index,
                'relationships': self.relationship_index,
                'knowledge_base': self.knowledge_base
            },
            'timestamp': datetime.now()
        }
