"""Dynamic Resource Manager with forecasting"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from ..models.learning_models import ResourceLearningModel
from ..utils.data_structures import ResourcePool


class DynamicResourceManager:
    """Dynamic Resource Manager with enhanced capabilities"""
    
    def __init__(self):
        self.resources: Dict[str, Dict] = {}
        self.resource_history: List[Dict] = []
        self.resource_pools: Dict[str, ResourcePool] = {}
        self.resource_forecast: Dict[str, Dict] = {}
        self.resource_learning = ResourceLearningModel()
        
        self._initialize_resource_pools()
    
    def _initialize_resource_pools(self):
        """Initialize resource pools"""
        self.resource_pools = {
            'cpu': ResourcePool('cpu', 'CPU Cores'),
            'memory': ResourcePool('memory', 'Memory'),
            'storage': ResourcePool('storage', 'Storage'),
            'gpu': ResourcePool('gpu', 'GPU'),
            'bandwidth': ResourcePool('bandwidth', 'Network Bandwidth')
        }
    
    def register_resource(self, resource_id: str, resource_type: str, config: Dict) -> str:
        """Register a new resource with enhanced capabilities"""
        if resource_type not in self.resource_pools:
            raise ValueError(f"Unknown resource type: {resource_type}")
        
        self.resources[resource_id] = {
            'type': resource_type,
            'config': config,
            'status': 'registered',
            'usage': 0,
            'last_heartbeat': None,
            'capacity': config.get('capacity', 100),
            'performance_metrics': {},
            'forecast': {}
        }
        
        self.resource_pools[resource_type].add_resource(resource_id, config.get('capacity', 100))
        
        return resource_id
    
    def update_resource_status(self, resource_id: str, status_update: Dict) -> bool:
        """Update the status of a resource with enhanced capabilities"""
        if resource_id in self.resources:
            self.resources[resource_id].update(status_update)
            self.resources[resource_id]['last_heartbeat'] = datetime.now()
            
            resource_type = self.resources[resource_id]['type']
            if resource_type in self.resource_pools:
                self.resource_pools[resource_type].update_resource(resource_id, status_update)
            
            self._update_resource_forecast(resource_id)
            self.resource_learning.update(resource_id, status_update)
            
            return True
        return False
    
    def _update_resource_forecast(self, resource_id: str):
        """Update the forecast for a resource"""
        if resource_id in self.resources:
            historical_data = self._get_resource_usage_history(resource_id)
            forecast = self.resource_learning.forecast(resource_id, historical_data)
            
            self.resources[resource_id]['forecast'] = forecast
            self.resource_forecast[resource_id] = forecast
    
    def _get_resource_usage_history(self, resource_id: str) -> List[Dict]:
        """Get historical usage data for a resource"""
        return [
            {'timestamp': datetime.now() - timedelta(hours=i), 'usage': 30 + (i * 5) % 50}
            for i in range(1, 6)
        ]
    
    def get_available_resources(self, resource_type: Optional[str] = None) -> List[str]:
        """Get a list of available resources with enhanced filtering"""
        if resource_type:
            if resource_type in self.resource_pools:
                return self.resource_pools[resource_type].get_available_resources()
            return []
        else:
            available = []
            for pool in self.resource_pools.values():
                available.extend(pool.get_available_resources())
            return available
    
    def get_agent_resources(self, agent_id: str) -> Dict[str, int]:
        """Get resources allocated to an agent"""
        resources = {
            'cpu': 0,
            'memory': 0,
            'storage': 0,
            'bandwidth': 0,
            'gpu': 0
        }
        
        for resource_type, pool in self.resource_pools.items():
            resources[resource_type] = pool.get_allocated_to_agent(agent_id)
        
        return resources
    
    def allocate_resource(self, resource_id: str, agent_id: str, amount: int, duration: Optional[int] = None) -> bool:
        """Allocate a portion of a resource to an agent"""
        if resource_id in self.resources:
            resource = self.resources[resource_id]
            resource_type = resource['type']
            
            if resource_type in self.resource_pools:
                if self.resource_pools[resource_type].can_allocate(resource_id, amount):
                    self.resource_pools[resource_type].allocate(resource_id, agent_id, amount, duration)
                    
                    resource['usage'] += amount
                    resource['status'] = 'allocated'
                    resource['assigned_to'] = agent_id
                    resource['allocation_duration'] = duration
                    
                    self._update_resource_forecast(resource_id)
                    
                    return True
        
        return False
    
    def release_resource(self, resource_id: str) -> bool:
        """Release a resource"""
        if resource_id in self.resources:
            resource = self.resources[resource_id]
            resource_type = resource['type']
            
            if resource_type in self.resource_pools:
                self.resource_pools[resource_type].release(resource_id)
                
                resource['usage'] = 0
                resource['status'] = 'available'
                if 'assigned_to' in resource:
                    del resource['assigned_to']
                if 'allocation_duration' in resource:
                    del resource['allocation_duration']
                
                self._update_resource_forecast(resource_id)
                
                return True
        
        return False
    
    def get_resource_usage(self, resource_id: str) -> Optional[Dict]:
        """Get the current usage of a resource"""
        if resource_id in self.resources:
            return {
                'usage': self.resources[resource_id]['usage'],
                'capacity': self.resources[resource_id]['capacity'],
                'percentage': self.resources[resource_id]['usage'] / self.resources[resource_id]['capacity'] * 100
            }
        return None
    
    def get_resource_forecast(self, resource_id: str) -> Optional[Dict]:
        """Get the forecast for a resource"""
        return self.resource_forecast.get(resource_id)
    
    def get_resource_learning_insights(self, resource_type: Optional[str] = None) -> Dict:
        """Get learning insights about resources"""
        return self.resource_learning.get_insights(resource_type)
    
    def optimize_resource_allocation(self):
        """Optimize resource allocation based on forecasts and learning"""
        pass
    
    def create_resource_pool(self, pool_id: str, resource_type: str, config: Dict) -> bool:
        """Create a new resource pool"""
        if pool_id not in self.resource_pools:
            self.resource_pools[pool_id] = ResourcePool(pool_id, resource_type, config)
            return True
        return False
    
    def update_resource_pool(self, pool_id: str, updates: Dict) -> bool:
        """Update an existing resource pool"""
        if pool_id in self.resource_pools:
            self.resource_pools[pool_id].update(updates)
            return True
        return False
    
    def delete_resource_pool(self, pool_id: str) -> bool:
        """Delete a resource pool"""
        if pool_id in self.resource_pools:
            del self.resource_pools[pool_id]
            return True
        return False
