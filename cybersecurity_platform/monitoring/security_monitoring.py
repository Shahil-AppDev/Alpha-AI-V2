"""
Security Monitoring System
Real-time monitoring, alerting, and logging for cybersecurity platform
"""

import logging
import threading
import time
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime


class MonitoringService:
    """Base monitoring service"""
    
    def __init__(self, platform, config: Dict[str, Any]):
        self.platform = platform
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.running = False
        self.thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start the monitoring service"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            self.logger.info(f"{self.__class__.__name__} started")
    
    def stop(self):
        """Stop the monitoring service"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        self.logger.info(f"{self.__class__.__name__} stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        interval = self.config.get('interval', 60)
        
        while self.running:
            try:
                self._perform_checks()
                time.sleep(interval)
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(interval)
    
    def _perform_checks(self):
        """Perform monitoring checks"""
        pass


class SystemMonitoringService(MonitoringService):
    """System resource monitoring"""
    
    def _perform_checks(self):
        """Check system resources"""
        import psutil
        
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        if cpu_usage > 80:
            self.platform.get_service('security_monitoring').generate_alert(
                'system_monitoring',
                'high_cpu_usage',
                f'CPU usage is high: {cpu_usage}%',
                severity='medium'
            )
        
        if memory.percent > 85:
            self.platform.get_service('security_monitoring').generate_alert(
                'system_monitoring',
                'high_memory_usage',
                f'Memory usage is high: {memory.percent}%',
                severity='medium'
            )
        
        if disk.percent > 90:
            self.platform.get_service('security_monitoring').generate_alert(
                'system_monitoring',
                'high_disk_usage',
                f'Disk usage is high: {disk.percent}%',
                severity='high'
            )


class ToolMonitoringService(MonitoringService):
    """Kali tools monitoring"""
    
    def _perform_checks(self):
        """Check tool status"""
        tools = self.platform.list_tools()
        
        for tool_name in tools:
            tool = self.platform.get_tool(tool_name)
            if tool and hasattr(tool, 'status'):
                if tool.status == 'error':
                    self.platform.get_service('security_monitoring').generate_alert(
                        'tool_monitoring',
                        'tool_error',
                        f'Tool {tool_name} is in error state',
                        severity='high'
                    )


class AIModelMonitoringService(MonitoringService):
    """AI model monitoring"""
    
    def _perform_checks(self):
        """Check AI model status"""
        models = self.platform.list_ai_models()
        
        for model_name in models:
            model = self.platform.get_ai_model(model_name)
            if model and hasattr(model, 'status'):
                if model.status == 'error':
                    self.platform.get_service('security_monitoring').generate_alert(
                        'ai_model_monitoring',
                        'model_error',
                        f'AI model {model_name} is in error state',
                        severity='high'
                    )


class SecurityMonitoringService(MonitoringService):
    """Security-specific monitoring"""
    
    def _perform_checks(self):
        """Perform security checks"""
        pass


class GenericMonitoringService(MonitoringService):
    """Generic monitoring service"""
    pass


class SecurityMonitoring:
    """Main security monitoring system"""
    
    def __init__(self, platform):
        self.platform = platform
        self.logger = logging.getLogger(__name__)
        
        self.monitoring_services: Dict[str, MonitoringService] = {}
        self.monitoring_config: Dict[str, Any] = {}
        self.monitoring_status = {
            'status': 'stopped',
            'last_heartbeat': None,
            'monitoring_services': {},
            'alerts': [],
            'alert_history': []
        }
        self.alert_thresholds = {
            'high': 8,
            'medium': 5,
            'low': 3
        }
    
    def initialize(self):
        """Initialize the security monitoring system"""
        self.logger.info("Initializing security monitoring system...")
        
        self._load_monitoring_configuration()
        self._initialize_monitoring_services()
        
        self.logger.info("Security monitoring system initialized")
    
    def start(self):
        """Start the security monitoring system"""
        self.logger.info("Starting security monitoring system...")
        
        for name, service in self.monitoring_services.items():
            service.start()
        
        self.monitoring_status['status'] = 'running'
        self.monitoring_status['last_heartbeat'] = datetime.now()
        
        self.logger.info("Security monitoring system started")
    
    def stop(self):
        """Stop the security monitoring system"""
        self.logger.info("Stopping security monitoring system...")
        
        for name, service in reversed(list(self.monitoring_services.items())):
            service.stop()
        
        self.monitoring_status['status'] = 'stopped'
        
        self.logger.info("Security monitoring system stopped")
    
    def _load_monitoring_configuration(self):
        """Load monitoring configuration from platform config"""
        monitoring_config = self.platform.get_config('security_monitoring', {})
        self.monitoring_config = monitoring_config
        
        if 'monitoring_interval' not in self.monitoring_config:
            self.monitoring_config['monitoring_interval'] = 60
        
        if 'alert_thresholds' not in self.monitoring_config:
            self.monitoring_config['alert_thresholds'] = self.alert_thresholds
        
        if 'monitoring_services' not in self.monitoring_config:
            self.monitoring_config['monitoring_services'] = {
                'system_monitoring': {
                    'enabled': True,
                    'interval': 60,
                    'checks': ['cpu_usage', 'memory_usage', 'disk_usage']
                },
                'tool_monitoring': {
                    'enabled': True,
                    'interval': 120,
                    'checks': ['tool_status', 'tool_heartbeat']
                },
                'ai_model_monitoring': {
                    'enabled': True,
                    'interval': 180,
                    'checks': ['model_status', 'model_accuracy']
                }
            }
    
    def _initialize_monitoring_services(self):
        """Initialize all monitoring services"""
        for service_name, service_config in self.monitoring_config['monitoring_services'].items():
            if service_config.get('enabled', False):
                self._initialize_monitoring_service(service_name, service_config)
    
    def _initialize_monitoring_service(self, service_name: str, service_config: Dict):
        """Initialize a specific monitoring service"""
        try:
            service_class = self._get_monitoring_service_class(service_name)
            self.monitoring_services[service_name] = service_class(self.platform, service_config)
            
            self.monitoring_status['monitoring_services'][service_name] = {
                'status': 'initialized',
                'last_heartbeat': datetime.now(),
                'config': service_config
            }
            
            self.logger.info(f"Monitoring service {service_name} initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize monitoring service {service_name}: {e}")
            
            self.monitoring_status['monitoring_services'][service_name] = {
                'status': 'initialization_failed',
                'last_heartbeat': None,
                'error': str(e)
            }
    
    def _get_monitoring_service_class(self, service_name: str):
        """Get the appropriate monitoring service class"""
        service_classes = {
            'system_monitoring': SystemMonitoringService,
            'tool_monitoring': ToolMonitoringService,
            'ai_model_monitoring': AIModelMonitoringService,
            'security_monitoring': SecurityMonitoringService
        }
        
        return service_classes.get(service_name, GenericMonitoringService)
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get the current monitoring status"""
        status = self.monitoring_status.copy()
        if status.get('last_heartbeat'):
            status['last_heartbeat'] = status['last_heartbeat'].isoformat()
        
        for service_name, service_status in status.get('monitoring_services', {}).items():
            if service_status.get('last_heartbeat'):
                service_status['last_heartbeat'] = service_status['last_heartbeat'].isoformat()
        
        return status
    
    def generate_alert(self, service_name: str, alert_type: str, message: str, 
                      severity: Optional[str] = None, context: Optional[Dict] = None) -> str:
        """Generate a new alert"""
        if severity is None:
            severity = self._determine_alert_severity(alert_type)
        
        alert = {
            'alert_id': str(uuid.uuid4()),
            'timestamp': datetime.now(),
            'service': service_name,
            'type': alert_type,
            'message': message,
            'severity': severity,
            'context': context or {},
            'status': 'new',
            'acknowledged': False
        }
        
        self.monitoring_status['alerts'].append(alert)
        self.monitoring_status['alert_history'].append(alert)
        
        if len(self.monitoring_status['alert_history']) > 1000:
            self.monitoring_status['alert_history'] = self.monitoring_status['alert_history'][-1000:]
        
        self.logger.warning(f"Alert generated: [{severity}] {message}")
        
        return alert['alert_id']
    
    def _determine_alert_severity(self, alert_type: str) -> str:
        """Determine the severity of an alert based on its type"""
        critical_types = ['critical_failure', 'security_breach', 'system_crash']
        high_types = ['tool_error', 'model_error', 'high_disk_usage']
        medium_types = ['high_cpu_usage', 'high_memory_usage', 'performance_issue']
        
        if alert_type in critical_types:
            return 'critical'
        elif alert_type in high_types:
            return 'high'
        elif alert_type in medium_types:
            return 'medium'
        else:
            return 'low'
    
    def get_alerts(self, severity: Optional[str] = None, service: Optional[str] = None) -> List[Dict]:
        """Get current alerts"""
        alerts = self.monitoring_status['alerts']
        
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity]
        if service:
            alerts = [a for a in alerts if a['service'] == service]
        
        return alerts
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        for alert in self.monitoring_status['alerts']:
            if alert['alert_id'] == alert_id:
                alert['acknowledged'] = True
                alert['acknowledged_at'] = datetime.now()
                alert['status'] = 'acknowledged'
                return True
        return False
