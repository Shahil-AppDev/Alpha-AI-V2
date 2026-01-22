"""
Cybersecurity Platform Core
Main platform orchestrator for Kali tools, AI models, and security monitoring
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

from ..tools.kali_integration import KaliToolsIntegration
from ..ai.ai_integration import AIIntegration
from ..monitoring.security_monitoring import SecurityMonitoring
from .update_system import AutomatedUpdateSystem
from ..api.gateway import APIGateway


class CybersecurityPlatform:
    """Main cybersecurity platform with Kali tools and AI integration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        self.tools: Dict[str, Any] = {}
        self.ai_models: Dict[str, Any] = {}
        self.services: Dict[str, Any] = {}
        
        self.kali_tools_integration: Optional[KaliToolsIntegration] = None
        self.ai_integration: Optional[AIIntegration] = None
        self.security_monitoring: Optional[SecurityMonitoring] = None
        self.update_system: Optional[AutomatedUpdateSystem] = None
        self.api_gateway: Optional[APIGateway] = None
        
        self.status = {
            'state': 'initialized',
            'started_at': None,
            'uptime': 0,
            'tools_count': 0,
            'ai_models_count': 0,
            'active_scans': 0
        }
        
        self._initialize_core_components()
    
    def _initialize_core_components(self):
        """Initialize all core components of the platform"""
        self.logger.info("Initializing cybersecurity platform core components...")
        
        try:
            self.kali_tools_integration = KaliToolsIntegration(self)
            self.kali_tools_integration.initialize()
            self.tools = self.kali_tools_integration.tools
            self.status['tools_count'] = len(self.tools)
            
            self.ai_integration = AIIntegration(self)
            self.ai_integration.initialize()
            self.ai_models = self.ai_integration.ai_models
            self.status['ai_models_count'] = len(self.ai_models)
            
            self.security_monitoring = SecurityMonitoring(self)
            self.security_monitoring.initialize()
            
            self.update_system = AutomatedUpdateSystem(self)
            self.update_system.initialize()
            
            self.api_gateway = APIGateway(self)
            
            self.services = {
                'kali_tools': self.kali_tools_integration,
                'ai_integration': self.ai_integration,
                'security_monitoring': self.security_monitoring,
                'update_system': self.update_system,
                'api_gateway': self.api_gateway
            }
            
            self.logger.info("Core components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize core components: {e}")
            raise
    
    def start(self):
        """Start the platform and all its components"""
        self.logger.info("Starting cybersecurity platform...")
        
        try:
            for tool_name, tool in self.tools.items():
                if hasattr(tool, 'start'):
                    tool.start()
                    self.logger.debug(f"Started tool: {tool_name}")
            
            for model_name, model in self.ai_models.items():
                if hasattr(model, 'start'):
                    model.start()
                    self.logger.debug(f"Started AI model: {model_name}")
            
            self.security_monitoring.start()
            self.api_gateway.start()
            self.update_system.start()
            
            self.status['state'] = 'running'
            self.status['started_at'] = datetime.now()
            
            self.logger.info("Cybersecurity platform started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start platform: {e}")
            self.status['state'] = 'error'
            raise
    
    def stop(self):
        """Stop the platform and all its components"""
        self.logger.info("Stopping cybersecurity platform...")
        
        try:
            self.update_system.stop()
            self.api_gateway.stop()
            self.security_monitoring.stop()
            
            for model_name, model in reversed(list(self.ai_models.items())):
                if hasattr(model, 'stop'):
                    model.stop()
                    self.logger.debug(f"Stopped AI model: {model_name}")
            
            for tool_name, tool in reversed(list(self.tools.items())):
                if hasattr(tool, 'stop'):
                    tool.stop()
                    self.logger.debug(f"Stopped tool: {tool_name}")
            
            self.status['state'] = 'stopped'
            
            self.logger.info("Cybersecurity platform stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping platform: {e}")
    
    def get_tool(self, tool_name: str) -> Optional[Any]:
        """Get a specific tool by name"""
        return self.tools.get(tool_name)
    
    def list_tools(self) -> list:
        """List all available tools"""
        return list(self.tools.keys())
    
    def get_ai_model(self, model_name: str) -> Optional[Any]:
        """Get a specific AI model by name"""
        return self.ai_models.get(model_name)
    
    def list_ai_models(self) -> list:
        """List all available AI models"""
        return list(self.ai_models.keys())
    
    def get_service(self, service_name: str) -> Optional[Any]:
        """Get a specific service by name"""
        return self.services.get(service_name)
    
    def get_config(self, section: Optional[str] = None, key: Optional[str] = None) -> Any:
        """Get configuration values"""
        if section is None:
            return self.config
        if key is None:
            return self.config.get(section, {})
        return self.config.get(section, {}).get(key)
    
    def set_config(self, section: str, key: str, value: Any) -> bool:
        """Set configuration values"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
        return True
    
    def get_status(self) -> Dict[str, Any]:
        """Get platform status"""
        if self.status['started_at']:
            self.status['uptime'] = (datetime.now() - self.status['started_at']).total_seconds()
        
        return {
            **self.status,
            'tools': {name: getattr(tool, 'status', 'unknown') for name, tool in self.tools.items()},
            'ai_models': {name: getattr(model, 'status', 'unknown') for name, model in self.ai_models.items()},
            'monitoring': self.security_monitoring.get_monitoring_status() if self.security_monitoring else {},
            'updates': self.update_system.get_update_status() if self.update_system else {}
        }
    
    def execute_scan(self, scan_type: str, target: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        """Execute a security scan"""
        self.logger.info(f"Executing {scan_type} scan on target: {target}")
        
        options = options or {}
        results = {
            'scan_type': scan_type,
            'target': target,
            'started_at': datetime.now(),
            'status': 'running'
        }
        
        try:
            if scan_type == 'nmap':
                tool = self.get_tool('nmap')
                if tool:
                    results['data'] = tool.scan(target, options)
                else:
                    results['error'] = 'Nmap tool not available'
                    results['status'] = 'failed'
            
            elif scan_type == 'vulnerability':
                model = self.get_ai_model('ai_vulnerability_scanner')
                if model:
                    results['data'] = model.scan(target, options)
                else:
                    results['error'] = 'AI vulnerability scanner not available'
                    results['status'] = 'failed'
            
            elif scan_type == 'intrusion_detection':
                model = self.get_ai_model('ai_intrusion_detection')
                if model:
                    results['data'] = model.analyze(target, options)
                else:
                    results['error'] = 'AI intrusion detection not available'
                    results['status'] = 'failed'
            
            else:
                results['error'] = f'Unknown scan type: {scan_type}'
                results['status'] = 'failed'
            
            if 'error' not in results:
                results['status'] = 'completed'
            
            results['completed_at'] = datetime.now()
            results['duration'] = (results['completed_at'] - results['started_at']).total_seconds()
            
        except Exception as e:
            self.logger.error(f"Scan execution failed: {e}")
            results['error'] = str(e)
            results['status'] = 'error'
            results['completed_at'] = datetime.now()
        
        return results


def create_platform(config: Optional[Dict] = None) -> CybersecurityPlatform:
    """Factory function to create a platform instance"""
    if config is None:
        config = {}
    
    return CybersecurityPlatform(config)
