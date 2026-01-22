"""
Default Configuration for Cybersecurity Platform
Configuration par défaut pour la plateforme de cybersécurité
"""

DEFAULT_CONFIG = {
    'kali_tools': {
        'default_category': 'network',
        'nmap': {
            'category': 'network',
            'enabled': True,
            'dependencies': [],
            'version': 'latest',
            'update_frequency': 'daily'
        },
        'metasploit': {
            'category': 'exploitation',
            'enabled': True,
            'dependencies': [],
            'version': 'latest',
            'update_frequency': 'daily'
        },
        'burpsuite': {
            'category': 'web',
            'enabled': True,
            'dependencies': [],
            'version': 'latest',
            'update_frequency': 'daily'
        },
        'wireshark': {
            'category': 'network',
            'enabled': True,
            'dependencies': [],
            'version': 'latest',
            'update_frequency': 'daily'
        },
        'john': {
            'category': 'password_cracking',
            'enabled': True,
            'dependencies': [],
            'version': 'latest',
            'update_frequency': 'daily'
        }
    },
    
    'ai_models': {
        'default_category': 'vulnerability_scanning',
        'ai_vulnerability_scanner': {
            'category': 'vulnerability_scanning',
            'enabled': True,
            'dependencies': [],
            'version': 'latest',
            'update_frequency': 'daily',
            'model_type': 'vulnerability_scanner',
            'model_path': None,
            'training_data': None
        },
        'ai_intrusion_detection': {
            'category': 'intrusion_detection',
            'enabled': True,
            'dependencies': [],
            'version': 'latest',
            'update_frequency': 'daily',
            'model_type': 'intrusion_detection',
            'model_path': None,
            'training_data': None
        },
        'ai_threat_intelligence': {
            'category': 'threat_intelligence',
            'enabled': True,
            'dependencies': [],
            'version': 'latest',
            'update_frequency': 'daily',
            'model_type': 'threat_intelligence',
            'model_path': None,
            'training_data': None
        }
    },
    
    'security_monitoring': {
        'monitoring_interval': 60,
        'alert_thresholds': {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3
        },
        'monitoring_services': {
            'system_monitoring': {
                'enabled': True,
                'interval': 60,
                'checks': ['cpu_usage', 'memory_usage', 'disk_usage', 'network_usage']
            },
            'tool_monitoring': {
                'enabled': True,
                'interval': 120,
                'checks': ['tool_status', 'tool_heartbeat', 'tool_performance']
            },
            'ai_model_monitoring': {
                'enabled': True,
                'interval': 180,
                'checks': ['model_status', 'model_accuracy', 'model_performance']
            },
            'security_monitoring': {
                'enabled': True,
                'interval': 300,
                'checks': ['vulnerability_scanning', 'intrusion_detection', 'threat_intelligence']
            }
        }
    },
    
    'update_system': {
        'update_frequency': 'daily',
        'update_window': {
            'start': '02:00',
            'end': '04:00'
        },
        'auto_update': True,
        'backup_before_update': True,
        'rollback_on_failure': True
    },
    
    'api_gateway': {
        'enabled': True,
        'host': '0.0.0.0',
        'port': 8000,
        'cors_enabled': True,
        'rate_limiting': {
            'enabled': True,
            'requests_per_minute': 60
        }
    },
    
    'logging': {
        'level': 'INFO',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': '/var/log/cybersecurity_platform/platform.log',
        'max_bytes': 10485760,  # 10MB
        'backup_count': 5
    }
}


# Configuration pour environnement de production
PRODUCTION_CONFIG = {
    **DEFAULT_CONFIG,
    'logging': {
        **DEFAULT_CONFIG['logging'],
        'level': 'WARNING'
    },
    'api_gateway': {
        **DEFAULT_CONFIG['api_gateway'],
        'rate_limiting': {
            'enabled': True,
            'requests_per_minute': 30
        }
    }
}


# Configuration pour environnement de développement
DEVELOPMENT_CONFIG = {
    **DEFAULT_CONFIG,
    'logging': {
        **DEFAULT_CONFIG['logging'],
        'level': 'DEBUG'
    },
    'update_system': {
        **DEFAULT_CONFIG['update_system'],
        'auto_update': False
    }
}
