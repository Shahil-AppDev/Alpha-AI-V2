"""
Enhanced Cybersecurity Platform with Kali Tools Integration
AI-powered security platform with automated updates and comprehensive monitoring
"""

from .core.platform import CybersecurityPlatform
from .core.update_system import AutomatedUpdateSystem
from .tools.kali_integration import KaliToolsIntegration
from .ai.ai_integration import AIIntegration
from .monitoring.security_monitoring import SecurityMonitoring

__version__ = "1.0.0"
__all__ = [
    'CybersecurityPlatform',
    'AutomatedUpdateSystem',
    'KaliToolsIntegration',
    'AIIntegration',
    'SecurityMonitoring'
]
