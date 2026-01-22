"""Data structures for the orchestrator"""

import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class Task:
    """Task data structure"""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = "custom"
    action: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    resource_requirements: Dict[str, int] = field(default_factory=dict)
    required_capabilities: List[str] = field(default_factory=list)
    status: str = "pending"
    created_at: datetime = field(default_factory=datetime.now)
    assigned_to: Optional[str] = None


@dataclass
class AgentProfile:
    """Agent profile data structure"""
    agent_id: str
    capabilities: List[str] = field(default_factory=list)
    preferences: Dict[str, Any] = field(default_factory=dict)
    learning_style: str = "default"
    communication_protocols: List[str] = field(default_factory=lambda: ["default"])
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class ResourceAllocation:
    """Resource allocation data structure"""
    resource_id: str
    agent_id: str
    amount: int
    duration: Optional[int] = None
    allocated_at: datetime = field(default_factory=datetime.now)


@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = ""
    message: str = ""
    severity: int = 5
    timestamp: datetime = field(default_factory=datetime.now)
    context: Dict[str, Any] = field(default_factory=dict)
    status: str = "new"


@dataclass
class Alert:
    """Alert data structure"""
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    status: str = "new"
    severity: int = 5
    context: Dict[str, Any] = field(default_factory=dict)
    processed: bool = False


class PriorityQueue:
    """Priority queue for tasks"""
    
    def __init__(self):
        self.queue: List[Task] = []
    
    def add(self, task: Task):
        """Add a task to the queue"""
        self.queue.append(task)
        self.queue.sort(key=lambda t: t.priority, reverse=True)
    
    def get(self) -> Optional[Task]:
        """Get the highest priority task"""
        if self.queue:
            return self.queue.pop(0)
        return None
    
    def empty(self) -> bool:
        """Check if queue is empty"""
        return len(self.queue) == 0
    
    def size(self) -> int:
        """Get queue size"""
        return len(self.queue)


class ResourcePool:
    """Resource pool for managing resources"""
    
    def __init__(self, pool_id: str, resource_type: str, config: Optional[Dict] = None):
        self.pool_id = pool_id
        self.resource_type = resource_type
        self.config = config or {}
        self.resources: Dict[str, Dict] = {}
        self.allocations: Dict[str, ResourceAllocation] = {}
    
    def add_resource(self, resource_id: str, capacity: int):
        """Add a resource to the pool"""
        self.resources[resource_id] = {
            'capacity': capacity,
            'available': capacity,
            'allocated': 0
        }
    
    def update_resource(self, resource_id: str, status_update: Dict):
        """Update resource status"""
        if resource_id in self.resources:
            self.resources[resource_id].update(status_update)
    
    def get_available_resources(self) -> List[str]:
        """Get list of available resources"""
        return [
            rid for rid, res in self.resources.items()
            if res['available'] > 0
        ]
    
    def can_allocate(self, resource_id: str, amount: int) -> bool:
        """Check if allocation is possible"""
        if resource_id in self.resources:
            return self.resources[resource_id]['available'] >= amount
        return False
    
    def allocate(self, resource_id: str, agent_id: str, amount: int, duration: Optional[int] = None):
        """Allocate resource to agent"""
        if self.can_allocate(resource_id, amount):
            self.resources[resource_id]['available'] -= amount
            self.resources[resource_id]['allocated'] += amount
            
            allocation_id = f"{resource_id}_{agent_id}"
            self.allocations[allocation_id] = ResourceAllocation(
                resource_id=resource_id,
                agent_id=agent_id,
                amount=amount,
                duration=duration
            )
            return True
        return False
    
    def release(self, resource_id: str):
        """Release allocated resource"""
        allocations_to_remove = []
        for alloc_id, allocation in self.allocations.items():
            if allocation.resource_id == resource_id:
                self.resources[resource_id]['available'] += allocation.amount
                self.resources[resource_id]['allocated'] -= allocation.amount
                allocations_to_remove.append(alloc_id)
        
        for alloc_id in allocations_to_remove:
            del self.allocations[alloc_id]
    
    def get_allocated_to_agent(self, agent_id: str) -> int:
        """Get total allocated to specific agent"""
        total = 0
        for allocation in self.allocations.values():
            if allocation.agent_id == agent_id:
                total += allocation.amount
        return total
    
    def update(self, updates: Dict):
        """Update pool configuration"""
        self.config.update(updates)


class EventBus:
    """Event bus for event-driven architecture"""
    
    def __init__(self):
        self.events: List[Dict] = []
        self.subscribers: Dict[str, List] = {}
    
    def publish(self, event: Dict):
        """Publish an event"""
        self.events.append(event)
        
        event_type = event.get('type', '')
        if event_type in self.subscribers:
            for handler in self.subscribers[event_type]:
                try:
                    handler(event)
                except Exception as e:
                    print(f"Error in event handler: {e}")
    
    def subscribe(self, event_type: str, handler):
        """Subscribe to an event type"""
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(handler)
    
    def unsubscribe(self, event_type: str, handler):
        """Unsubscribe from an event type"""
        if event_type in self.subscribers:
            if handler in self.subscribers[event_type]:
                self.subscribers[event_type].remove(handler)
