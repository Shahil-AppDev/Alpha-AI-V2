"""Default configuration for the Enhanced AI Agent Orchestrator"""

DEFAULT_SECURITY_POLICIES = {
    'agent_validation': {
        'signature_required': True,
        'certificate_required': True,
        'permission_levels': ['basic', 'advanced', 'admin'],
        'identity_verification': True
    },
    'task_validation': {
        'authorization_required': True,
        'safety_checks': ['malicious_content', 'resource_exhaustion', 'data_integrity'],
        'resource_limits': {
            'cpu': 80,
            'memory': 80,
            'storage': 90
        }
    },
    'access_control': {
        'default_permissions': {
            'basic': ['agent.register', 'agent.heartbeat'],
            'advanced': ['agent.register', 'agent.heartbeat', 'task.create', 'task.execute'],
            'admin': ['*']
        },
        'policy_rules': [
            {
                'subject': 'agent:*',
                'resource': 'task:*',
                'action': 'create',
                'effect': 'allow',
                'conditions': {
                    'permission': 'advanced'
                }
            },
            {
                'subject': 'agent:*',
                'resource': 'task:*',
                'action': 'execute',
                'effect': 'allow',
                'conditions': {
                    'permission': 'advanced'
                }
            }
        ]
    }
}

DEFAULT_MONITORING_CONFIG = {
    'heartbeat_interval': 30,
    'performance_check_interval': 60,
    'alert_check_interval': 5,
    'anomaly_detection_interval': 60,
    'predictive_analytics_interval': 300
}

DEFAULT_RESOURCE_POOLS = {
    'cpu': {
        'type': 'cpu',
        'description': 'CPU Cores',
        'default_capacity': 100
    },
    'memory': {
        'type': 'memory',
        'description': 'Memory',
        'default_capacity': 100
    },
    'storage': {
        'type': 'storage',
        'description': 'Storage',
        'default_capacity': 100
    },
    'gpu': {
        'type': 'gpu',
        'description': 'GPU',
        'default_capacity': 100
    },
    'bandwidth': {
        'type': 'bandwidth',
        'description': 'Network Bandwidth',
        'default_capacity': 100
    }
}

DEFAULT_TASK_TEMPLATES = {
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
