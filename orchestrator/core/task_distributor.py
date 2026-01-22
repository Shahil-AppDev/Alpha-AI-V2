"""Advanced Task Distributor with templates and learning"""

import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional

from ..models.learning_models import TaskLearningModel
from ..utils.data_structures import Task, PriorityQueue


class AdvancedTaskDistributor:
    """Advanced Task Distributor with enhanced capabilities"""
    
    def __init__(self, agent_manager, resource_manager, knowledge_graph=None):
        self.agent_manager = agent_manager
        self.resource_manager = resource_manager
        self.knowledge_graph = knowledge_graph
        self.task_queue = PriorityQueue()
        self.task_history: List[Dict] = []
        self.task_dependencies: Dict[str, List[str]] = {}
        self.task_templates: Dict[str, Dict] = {}
        self.task_learning = TaskLearningModel()
        
        self._load_task_templates()
    
    def _load_task_templates(self):
        """Load predefined task templates"""
        self.task_templates = {
            'question_answering': {
                'description': 'Answer a question based on provided context',
                'parameters': ['question', 'context'],
                'required_capabilities': ['text_processing', 'question_answering'],
                'resource_requirements': {'cpu': 20, 'memory': 30},
                'priority': 1
            },
            'web_search': {
                'description': 'Perform a web search for information',
                'parameters': ['query', 'max_results'],
                'required_capabilities': ['web_search'],
                'resource_requirements': {'cpu': 10, 'memory': 20},
                'priority': 2
            },
            'data_analysis': {
                'description': 'Analyze data and provide insights',
                'parameters': ['data', 'analysis_type'],
                'required_capabilities': ['data_analysis'],
                'resource_requirements': {'cpu': 40, 'memory': 50},
                'priority': 1
            },
            'code_generation': {
                'description': 'Generate code based on specifications',
                'parameters': ['specification', 'language'],
                'required_capabilities': ['code_generation'],
                'resource_requirements': {'cpu': 30, 'memory': 40},
                'priority': 2
            }
        }
    
    def add_task(self, task_data: Dict, priority: Optional[int] = None) -> str:
        """Add a new task to the queue with enhanced capabilities"""
        task_type = task_data.get('type')
        
        if task_type and task_type in self.task_templates:
            task_template = self.task_templates[task_type]
            task = Task(
                task_id=str(uuid.uuid4()),
                type=task_type,
                action=task_template['description'],
                parameters=task_data.get('parameters', {}),
                priority=priority if priority is not None else task_template['priority'],
                dependencies=task_data.get('dependencies', []),
                metadata=task_data.get('metadata', {}),
                resource_requirements=task_template['resource_requirements'],
                required_capabilities=task_template['required_capabilities']
            )
        else:
            task = Task(
                task_id=str(uuid.uuid4()),
                type=task_data.get('type', 'custom'),
                action=task_data['action'],
                parameters=task_data.get('parameters', {}),
                priority=priority if priority is not None else 0,
                dependencies=task_data.get('dependencies', []),
                metadata=task_data.get('metadata', {}),
                resource_requirements=task_data.get('resource_requirements', {}),
                required_capabilities=task_data.get('required_capabilities', [])
            )
        
        self.task_queue.add(task)
        
        if task.dependencies:
            for dep in task.dependencies:
                if dep not in self.task_dependencies:
                    self.task_dependencies[dep] = []
                self.task_dependencies[dep].append(task.task_id)
        
        self.task_history.append({
            'task_id': task.task_id,
            'status': 'queued',
            'timestamp': datetime.now(),
            'type': task.type
        })
        
        self.task_learning.update(task)
        
        return task.task_id
    
    def distribute_tasks(self):
        """Distribute tasks to appropriate agents with enhanced logic"""
        while not self.task_queue.empty():
            task = self.task_queue.get()
            
            if not self._check_task_dependencies(task):
                self.task_queue.add(task)
                continue
            
            best_agent = self._select_agent_for_task(task)
            
            if best_agent:
                self.agent_manager.update_agent_status(
                    best_agent,
                    {'tasks': self.agent_manager.agent_status[best_agent]['tasks'] + [task.task_id]}
                )
                
                self._send_task_to_agent(best_agent, task)
                self._update_task_history(task.task_id, 'assigned', best_agent)
                self.task_learning.update(task, best_agent)
                
                if self.knowledge_graph:
                    self.knowledge_graph.update_task_relationships(task)
            else:
                self._update_task_history(task.task_id, 'failed', reason='no_suitable_agent')
                self.task_learning.update(task, None, success=False)
    
    def _check_task_dependencies(self, task: Task) -> bool:
        """Check if all task dependencies are met"""
        if not task.dependencies:
            return True
        
        for dep in task.dependencies:
            dep_task = next((t for t in self.task_history if t['task_id'] == dep), None)
            if not dep_task or dep_task.get('status') != 'completed':
                return False
        
        return True
    
    def _select_agent_for_task(self, task: Task) -> Optional[str]:
        """Select the best agent for a given task with enhanced selection logic"""
        available_agents = []
        
        for agent_id, status in self.agent_manager.agent_status.items():
            if (status['status'] in ['ready', 'initialized'] and
                self._agent_can_perform_task(agent_id, task)):
                available_agents.append(agent_id)
        
        if not available_agents:
            return None
        
        best_agent = None
        best_score = -1
        
        for agent_id in available_agents:
            score = self._calculate_agent_score(agent_id, task)
            if score > best_score:
                best_score = score
                best_agent = agent_id
        
        return best_agent
    
    def _agent_can_perform_task(self, agent_id: str, task: Task) -> bool:
        """Check if an agent can perform a specific task"""
        agent_profile = self.agent_manager.get_agent_profile(agent_id)
        if not agent_profile:
            return False
        
        if not all(cap in agent_profile.capabilities for cap in task.required_capabilities):
            return False
        
        return True
    
    def _calculate_agent_score(self, agent_id: str, task: Task) -> float:
        """Calculate a score for how well an agent can perform a task"""
        status = self.agent_manager.agent_status[agent_id]
        profile = self.agent_manager.get_agent_profile(agent_id)
        
        score = 0
        
        if all(cap in profile.capabilities for cap in task.required_capabilities):
            score += 30
        
        if len(status.get('tasks', [])) < 3:
            score += 20
        
        if status.get('performance_metrics', {}).get('success_rate', 0) > 80:
            score += 20
        
        if all(dep in status.get('completed_tasks', []) for dep in task.dependencies):
            score += 10
        
        if task.type in profile.preferences.get('preferred_tasks', []):
            score += 5
        
        if self.knowledge_graph:
            kg_score = self.knowledge_graph.calculate_agent_task_affinity(agent_id, task)
            score += kg_score
        
        return max(0, min(100, score))
    
    def _send_task_to_agent(self, agent_id: str, task: Task) -> bool:
        """Send a task to a specific agent with enhanced communication"""
        agent = self.agent_manager.agents[agent_id]
        if agent:
            task_data = {
                'task_id': task.task_id,
                'type': task.type,
                'action': task.action,
                'parameters': task.parameters,
                'dependencies': task.dependencies,
                'metadata': task.metadata,
                'resource_requirements': task.resource_requirements,
                'required_capabilities': task.required_capabilities,
                'knowledge_context': self.knowledge_graph.get_relevant_knowledge(task) if self.knowledge_graph else {}
            }
            
            agent.assign_task(task_data)
            return True
        return False
    
    def _update_task_history(self, task_id: str, status: str, agent_id: Optional[str] = None, reason: Optional[str] = None):
        """Update the task history with enhanced information"""
        for entry in self.task_history:
            if entry['task_id'] == task_id:
                entry['status'] = status
                entry['timestamp'] = datetime.now()
                if agent_id:
                    entry['agent_id'] = agent_id
                if reason:
                    entry['reason'] = reason
                return
        
        self.task_history.append({
            'task_id': task_id,
            'status': status,
            'timestamp': datetime.now(),
            'agent_id': agent_id,
            'reason': reason
        })
    
    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """Get the status of a specific task"""
        for entry in reversed(self.task_history):
            if entry['task_id'] == task_id:
                return entry
        return None
    
    def get_task_learning_insights(self, task_type: Optional[str] = None) -> Dict:
        """Get learning insights about tasks"""
        return self.task_learning.get_insights(task_type)
    
    def create_task_template(self, template_data: Dict) -> str:
        """Create a new task template"""
        template_id = str(uuid.uuid4())
        self.task_templates[template_id] = template_data
        return template_id
    
    def update_task_template(self, template_id: str, updates: Dict) -> bool:
        """Update an existing task template"""
        if template_id in self.task_templates:
            self.task_templates[template_id].update(updates)
            return True
        return False
    
    def delete_task_template(self, template_id: str) -> bool:
        """Delete a task template"""
        if template_id in self.task_templates:
            del self.task_templates[template_id]
            return True
        return False
    
    def get_task_forecasts(self) -> Dict:
        """Get task forecasts"""
        return {}
