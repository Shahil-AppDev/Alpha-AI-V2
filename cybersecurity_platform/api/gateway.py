"""
API Gateway
REST API, GraphQL, and WebSocket interfaces for the cybersecurity platform
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime


class APIGateway:
    """Main API gateway for the platform"""
    
    def __init__(self, platform):
        self.platform = platform
        self.logger = logging.getLogger(__name__)
        self.status = 'initialized'
        self.api_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'avg_response_time': 0.0
        }
    
    def start(self):
        """Start the API gateway"""
        self.status = 'running'
        self.logger.info("API Gateway started")
    
    def stop(self):
        """Stop the API gateway"""
        self.status = 'stopped'
        self.logger.info("API Gateway stopped")
    
    def handle_request(self, endpoint: str, method: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """Handle an API request"""
        self.api_stats['total_requests'] += 1
        
        try:
            if endpoint == '/scan' and method == 'POST':
                return self._handle_scan_request(data or {})
            
            elif endpoint == '/tools' and method == 'GET':
                return self._handle_list_tools()
            
            elif endpoint == '/ai-models' and method == 'GET':
                return self._handle_list_ai_models()
            
            elif endpoint == '/status' and method == 'GET':
                return self._handle_get_status()
            
            elif endpoint == '/alerts' and method == 'GET':
                return self._handle_get_alerts(data or {})
            
            elif endpoint == '/update' and method == 'POST':
                return self._handle_force_update()
            
            else:
                self.api_stats['failed_requests'] += 1
                return {
                    'success': False,
                    'error': f'Unknown endpoint: {method} {endpoint}'
                }
        
        except Exception as e:
            self.api_stats['failed_requests'] += 1
            self.logger.error(f"API request failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _handle_scan_request(self, data: Dict) -> Dict[str, Any]:
        """Handle scan request"""
        scan_type = data.get('scan_type')
        target = data.get('target')
        options = data.get('options', {})
        
        if not scan_type or not target:
            return {
                'success': False,
                'error': 'Missing required parameters: scan_type, target'
            }
        
        result = self.platform.execute_scan(scan_type, target, options)
        
        self.api_stats['successful_requests'] += 1
        
        return {
            'success': True,
            'data': result
        }
    
    def _handle_list_tools(self) -> Dict[str, Any]:
        """Handle list tools request"""
        tools = self.platform.list_tools()
        
        self.api_stats['successful_requests'] += 1
        
        return {
            'success': True,
            'data': {
                'tools': tools,
                'count': len(tools)
            }
        }
    
    def _handle_list_ai_models(self) -> Dict[str, Any]:
        """Handle list AI models request"""
        models = self.platform.list_ai_models()
        
        self.api_stats['successful_requests'] += 1
        
        return {
            'success': True,
            'data': {
                'models': models,
                'count': len(models)
            }
        }
    
    def _handle_get_status(self) -> Dict[str, Any]:
        """Handle get status request"""
        status = self.platform.get_status()
        
        self.api_stats['successful_requests'] += 1
        
        return {
            'success': True,
            'data': status
        }
    
    def _handle_get_alerts(self, data: Dict) -> Dict[str, Any]:
        """Handle get alerts request"""
        monitoring = self.platform.get_service('security_monitoring')
        
        if not monitoring:
            return {
                'success': False,
                'error': 'Monitoring service not available'
            }
        
        severity = data.get('severity')
        service = data.get('service')
        
        alerts = monitoring.get_alerts(severity, service)
        
        self.api_stats['successful_requests'] += 1
        
        return {
            'success': True,
            'data': {
                'alerts': alerts,
                'count': len(alerts)
            }
        }
    
    def _handle_force_update(self) -> Dict[str, Any]:
        """Handle force update request"""
        update_system = self.platform.get_service('update_system')
        
        if not update_system:
            return {
                'success': False,
                'error': 'Update system not available'
            }
        
        success = update_system.force_update()
        
        if success:
            self.api_stats['successful_requests'] += 1
        else:
            self.api_stats['failed_requests'] += 1
        
        return {
            'success': success,
            'message': 'Update initiated' if success else 'Update failed or already in progress'
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get API statistics"""
        return self.api_stats.copy()
