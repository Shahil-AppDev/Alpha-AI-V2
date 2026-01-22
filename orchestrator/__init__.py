"""
Enhanced AI Agent Orchestrator
A comprehensive system for managing AI agents with advanced capabilities
"""

from .core.agent_manager import IntelligentAgentManager
from .core.task_distributor import AdvancedTaskDistributor
from .core.resource_manager import DynamicResourceManager
from .core.monitoring_system import AIPoweredMonitoringSystem
from .core.security_module import EnterpriseGradeSecurityModule
from .core.knowledge_graph import KnowledgeGraph
from .core.ml_engine import MachineLearningEngine
from .core.event_architecture import EventDrivenArchitecture

__version__ = "2.0.0"
__all__ = [
    'IntelligentAgentManager',
    'AdvancedTaskDistributor',
    'DynamicResourceManager',
    'AIPoweredMonitoringSystem',
    'EnterpriseGradeSecurityModule',
    'KnowledgeGraph',
    'MachineLearningEngine',
    'EventDrivenArchitecture'
]
