"""AI-Powered Monitoring System with anomaly detection"""

import uuid
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from ..models.learning_models import (
    MonitoringLearningModel,
    AnomalyDetectionModel,
    PredictiveAnalyticsModel
)


class AIPoweredMonitoringSystem:
    """AI-Powered Monitoring System with enhanced capabilities"""
    
    def __init__(self, agent_manager, task_distributor, resource_manager, knowledge_graph):
        self.agent_manager = agent_manager
        self.task_distributor = task_distributor
        self.resource_manager = resource_manager
        self.knowledge_graph = knowledge_graph
        self.metrics: Dict[str, Dict] = {
            'agents': {},
            'tasks': {},
            'resources': {}
        }
        self.alerts: List[Dict] = []
        self.heartbeat_interval = 30
        self.anomaly_detection = AnomalyDetectionModel()
        self.predictive_analytics = PredictiveAnalyticsModel()
        self.monitoring_learning = MonitoringLearningModel()
        
        self._initialize_monitoring_models()
    
    def _initialize_monitoring_models(self):
        """Initialize monitoring models"""
        self.anomaly_detection.initialize()
        self.predictive_analytics.initialize()
        self.monitoring_learning.initialize()
    
    def start_monitoring(self):
        """Start the monitoring system with enhanced capabilities"""
        self._start_heartbeat_monitor()
        self._start_performance_monitor()
        self._start_alert_monitor()
        self._start_anomaly_detection()
        self._start_predictive_analytics()
    
    def _start_heartbeat_monitor(self):
        """Monitor agent and resource heartbeats"""
        def heartbeat_check():
            while True:
                time.sleep(self.heartbeat_interval)
                
                for agent_id, status in self.agent_manager.agent_status.items():
                    if (status['last_heartbeat'] is None or
                        (datetime.now() - status['last_heartbeat']).seconds > self.heartbeat_interval * 2):
                        alert_id = self._generate_alert(
                            'agent_heartbeat_failed',
                            f"Agent {agent_id} has not sent a heartbeat in {self.heartbeat_interval * 2} seconds"
                        )
                        
                        self.agent_manager.update_agent_status(agent_id, {'status': 'unresponsive'})
                        
                        if self.knowledge_graph:
                            self.knowledge_graph.update_agent_status(agent_id, 'unresponsive')
                        
                        self.monitoring_learning.update_alert(alert_id)
                
                for resource_id, resource in self.resource_manager.resources.items():
                    if (resource['last_heartbeat'] is None or
                        (datetime.now() - resource['last_heartbeat']).seconds > self.heartbeat_interval * 2):
                        alert_id = self._generate_alert(
                            'resource_heartbeat_failed',
                            f"Resource {resource_id} has not sent a heartbeat in {self.heartbeat_interval * 2} seconds"
                        )
                        
                        self.resource_manager.update_resource_status(resource_id, {'status': 'unresponsive'})
                        self.monitoring_learning.update_alert(alert_id)
        
        threading.Thread(target=heartbeat_check, daemon=True).start()
    
    def _start_performance_monitor(self):
        """Monitor system performance"""
        def performance_check():
            while True:
                time.sleep(60)
                
                self._record_metrics()
                self._check_performance()
                self.predictive_analytics.update()
                self.monitoring_learning.update_metrics(self.metrics)
        
        threading.Thread(target=performance_check, daemon=True).start()
    
    def _start_alert_monitor(self):
        """Monitor and process alerts"""
        def alert_processor():
            while True:
                time.sleep(5)
                
                if self.alerts:
                    for alert in self.alerts[:]:
                        self._process_alert(alert)
                        self.alerts.remove(alert)
        
        threading.Thread(target=alert_processor, daemon=True).start()
    
    def _start_anomaly_detection(self):
        """Start anomaly detection"""
        def anomaly_detector():
            while True:
                time.sleep(60)
                
                recent_metrics = self._get_recent_metrics()
                anomalies = self.anomaly_detection.detect(recent_metrics)
                
                for anomaly in anomalies:
                    alert_id = self._generate_alert(
                        'anomaly_detected',
                        f"Anomaly detected: {anomaly.get('description', 'Unknown')}",
                        anomaly.get('severity', 5),
                        anomaly.get('context', {})
                    )
                    
                    self.monitoring_learning.update_alert(alert_id)
        
        threading.Thread(target=anomaly_detector, daemon=True).start()
    
    def _start_predictive_analytics(self):
        """Start predictive analytics"""
        def predictive_analyst():
            while True:
                time.sleep(300)
                
                metrics = self.metrics
                forecasts = self._get_forecasts()
                
                predictions = self.predictive_analytics.predict(metrics, forecasts)
                
                for prediction in predictions:
                    if prediction.get('severity', 0) >= 7:
                        alert_id = self._generate_alert(
                            'prediction',
                            f"Predicted issue: {prediction.get('description', 'Unknown')}",
                            prediction.get('severity', 5),
                            prediction.get('context', {})
                        )
                        
                        self.monitoring_learning.update_alert(alert_id)
        
        threading.Thread(target=predictive_analyst, daemon=True).start()
    
    def _get_recent_metrics(self, window_minutes: int = 60) -> Dict:
        """Get recent metrics for anomaly detection"""
        recent_metrics: Dict[str, Dict] = {
            'agents': {},
            'tasks': {},
            'resources': {}
        }
        
        cutoff_time = datetime.now() - timedelta(minutes=window_minutes)
        
        for agent_id, metrics in self.metrics['agents'].items():
            if metrics:
                recent = [m for m in metrics if m['timestamp'] >= cutoff_time]
                if recent:
                    recent_metrics['agents'][agent_id] = recent
        
        for task_id, metrics in self.metrics['tasks'].items():
            if metrics:
                recent = [m for m in metrics if m['timestamp'] >= cutoff_time]
                if recent:
                    recent_metrics['tasks'][task_id] = recent
        
        for resource_id, metrics in self.metrics['resources'].items():
            if metrics:
                recent = [m for m in metrics if m['timestamp'] >= cutoff_time]
                if recent:
                    recent_metrics['resources'][resource_id] = recent
        
        return recent_metrics
    
    def _get_forecasts(self) -> Dict:
        """Get forecasts for predictive analytics"""
        forecasts: Dict[str, Dict] = {
            'resources': {},
            'tasks': {}
        }
        
        for resource_id, resource in self.resource_manager.resources.items():
            if 'forecast' in resource:
                forecasts['resources'][resource_id] = resource['forecast']
        
        task_forecasts = self.task_distributor.get_task_forecasts()
        if task_forecasts:
            forecasts['tasks'] = task_forecasts
        
        return forecasts
    
    def _record_metrics(self):
        """Record current system metrics"""
        timestamp = datetime.now()
        
        for agent_id, status in self.agent_manager.agent_status.items():
            if agent_id not in self.metrics['agents']:
                self.metrics['agents'][agent_id] = []
            
            performance_metrics = status.get('performance_metrics', {})
            
            self.metrics['agents'][agent_id].append({
                'timestamp': timestamp,
                'status': status['status'],
                'task_count': len(status.get('tasks', [])),
                'resource_usage': status.get('resource_usage', {}),
                'performance_metrics': performance_metrics,
                'learning_progress': status.get('learning_progress', {})
            })
            
            if len(self.metrics['agents'][agent_id]) > 1000:
                self.metrics['agents'][agent_id] = self.metrics['agents'][agent_id][-1000:]
        
        for task_entry in self.task_distributor.task_history:
            task_id = task_entry['task_id']
            if task_id not in self.metrics['tasks']:
                self.metrics['tasks'][task_id] = []
            
            self.metrics['tasks'][task_id].append({
                'timestamp': timestamp,
                'status': task_entry.get('status', 'unknown'),
                'agent_id': task_entry.get('agent_id'),
                'type': task_entry.get('type', 'unknown'),
                'priority': 0
            })
            
            if len(self.metrics['tasks'][task_id]) > 1000:
                self.metrics['tasks'][task_id] = self.metrics['tasks'][task_id][-1000:]
        
        for resource_id, resource in self.resource_manager.resources.items():
            if resource_id not in self.metrics['resources']:
                self.metrics['resources'][resource_id] = []
            
            self.metrics['resources'][resource_id].append({
                'timestamp': timestamp,
                'status': resource['status'],
                'usage': resource['usage'],
                'capacity': resource['capacity'],
                'type': resource['type'],
                'forecast': resource.get('forecast', {})
            })
            
            if len(self.metrics['resources'][resource_id]) > 1000:
                self.metrics['resources'][resource_id] = self.metrics['resources'][resource_id][-1000:]
    
    def _check_performance(self):
        """Check for performance issues"""
        for agent_id, metrics in self.metrics['agents'].items():
            if not metrics:
                continue
            
            recent_metrics = metrics[-10:] if len(metrics) >= 10 else metrics
            avg_tasks = sum(m['task_count'] for m in recent_metrics) / len(recent_metrics)
            
            if avg_tasks > 10:
                alert_id = self._generate_alert(
                    'agent_overloaded',
                    f"Agent {agent_id} is overloaded with average of {avg_tasks:.1f} tasks",
                    7
                )
                self.monitoring_learning.update_alert(alert_id)
        
        for resource_id, metrics in self.metrics['resources'].items():
            if not metrics:
                continue
            
            recent_metrics = metrics[-10:] if len(metrics) >= 10 else metrics
            avg_usage = sum(m['usage'] for m in recent_metrics) / len(recent_metrics)
            avg_capacity = sum(m['capacity'] for m in recent_metrics) / len(recent_metrics)
            
            if avg_capacity > 0 and avg_usage / avg_capacity > 0.8:
                alert_id = self._generate_alert(
                    'resource_overused',
                    f"Resource {resource_id} is overused with average of {avg_usage:.1f}/{avg_capacity:.1f} usage",
                    7
                )
                self.monitoring_learning.update_alert(alert_id)
    
    def _generate_alert(self, alert_type: str, message: str, severity: int = 5, context: Optional[Dict] = None) -> str:
        """Generate a new alert"""
        alert_id = str(uuid.uuid4())
        self.alerts.append({
            'alert_id': alert_id,
            'type': alert_type,
            'message': message,
            'timestamp': datetime.now(),
            'status': 'new',
            'severity': severity,
            'context': context or {},
            'processed': False
        })
        return alert_id
    
    def _process_alert(self, alert: Dict):
        """Process an alert"""
        alert['status'] = 'processed'
        alert['processed_at'] = datetime.now()
        alert['processed'] = True
        
        self._log_alert(alert)
        
        if self.knowledge_graph:
            self.knowledge_graph.update_alert(alert)
        
        self.monitoring_learning.update_alert(alert['alert_id'])
    
    def _log_alert(self, alert: Dict):
        """Log an alert to the alert history"""
        pass
    
    def get_metrics(self, metric_type: str, entity_id: Optional[str] = None) -> Any:
        """Get system metrics"""
        if entity_id:
            if metric_type == 'agent' and entity_id in self.metrics['agents']:
                return self.metrics['agents'][entity_id]
            elif metric_type == 'task' and entity_id in self.metrics['tasks']:
                return self.metrics['tasks'][entity_id]
            elif metric_type == 'resource' and entity_id in self.metrics['resources']:
                return self.metrics['resources'][entity_id]
            return None
        else:
            return self.metrics.get(metric_type + 's', {})
    
    def get_alerts(self, alert_type: Optional[str] = None, status: Optional[str] = None, severity: Optional[int] = None) -> List[Dict]:
        """Get system alerts with enhanced filtering"""
        filtered_alerts = self.alerts
        
        if alert_type:
            filtered_alerts = [a for a in filtered_alerts if a['type'] == alert_type]
        if status:
            filtered_alerts = [a for a in filtered_alerts if a['status'] == status]
        if severity:
            filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity]
        
        return filtered_alerts
    
    def get_anomaly_detection_results(self) -> List[Dict]:
        """Get anomaly detection results"""
        return self.anomaly_detection.get_results()
    
    def get_predictive_analytics_results(self) -> List[Dict]:
        """Get predictive analytics results"""
        return self.predictive_analytics.get_results()
    
    def get_monitoring_learning_insights(self) -> Dict:
        """Get learning insights from monitoring"""
        return self.monitoring_learning.get_insights()
    
    def update_anomaly_detection_model(self, model_data: Dict):
        """Update the anomaly detection model"""
        self.anomaly_detection.update(model_data)
    
    def update_predictive_analytics_model(self, model_data: Dict):
        """Update the predictive analytics model"""
        self.predictive_analytics.update(model_data)
