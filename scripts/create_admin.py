#!/usr/bin/env python3
"""
Admin User Creation Script for Security Team Orchestrator

This script creates the default admin user for the Security Team Orchestrator platform.
"""

import asyncio
import logging
import sys
import os
from pathlib import Path
import hashlib
import secrets

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import asyncpg
import yaml
from sqlalchemy import create_engine, MetaData, Table, Column, String, DateTime, Boolean, Text, Integer, Float, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

Base = declarative_base()

class AdminUser(Base):
    """Admin user model."""
    __tablename__ = 'admin_users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    api_key = Column(String(255), unique=True, nullable=False)
    role = Column(String(20), default='admin')
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    permissions = Column(JSON, default=lambda: ["*"])

class TeamConfiguration(Base):
    """Team configuration model."""
    __tablename__ = 'team_configurations'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    config_key = Column(String(100), unique=True, nullable=False)
    config_value = Column(JSON, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

def generate_password_hash(password: str) -> str:
    """Generate password hash."""
    salt = secrets.token_hex(32)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${password_hash.hex()}"

def generate_api_key() -> str:
    """Generate API key."""
    return f"sk-{secrets.token_urlsafe(32)}"

async def create_admin_user():
    """Create default admin user."""
    try:
        # Get database URL from environment
        database_url = os.getenv('DATABASE_URL', 'postgresql://orchestrator:orchestrator_pass@localhost:5432/orchestrator_db')
        
        logger.info("Connecting to database...")
        
        # Create engine
        engine = create_engine(database_url)
        
        # Create admin_users table if it doesn't exist
        AdminUser.metadata.create_all(engine)
        TeamConfiguration.metadata.create_all(engine)
        
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Check if admin user already exists
        existing_admin = session.query(AdminUser).filter_by(username='admin').first()
        
        if existing_admin:
            logger.info("Admin user already exists!")
            logger.info(f"Username: {existing_admin.username}")
            logger.info(f"Email: {existing_admin.email}")
            logger.info(f"API Key: {existing_admin.api_key}")
            return True
        
        # Generate default admin credentials
        default_password = os.getenv('ADMIN_PASSWORD', 'Admin123!ChangeMe')
        default_email = os.getenv('ADMIN_EMAIL', 'admin@security-orchestrator.local')
        
        # Create admin user
        admin_user = AdminUser(
            username='admin',
            email=default_email,
            password_hash=generate_password_hash(default_password),
            api_key=generate_api_key(),
            role='admin',
            is_active=True,
            permissions=["*"]
        )
        
        session.add(admin_user)
        session.commit()
        
        logger.info("✅ Admin user created successfully!")
        logger.info("")
        logger.info("🔑 Admin Credentials:")
        logger.info(f"  Username: {admin_user.username}")
        logger.info(f"  Email: {admin_user.email}")
        logger.info(f"  Password: {default_password}")
        logger.info(f"  API Key: {admin_user.api_key}")
        logger.info("")
        logger.info("⚠️  IMPORTANT: Please change the default password after first login!")
        
        return True
        
    except Exception as e:
        logger.error(f"Admin user creation failed: {e}")
        return False

async def create_default_configurations():
    """Create default team configurations."""
    try:
        database_url = os.getenv('DATABASE_URL', 'postgresql://orchestrator:orchestrator_pass@localhost:5432/orchestrator_db')
        
        logger.info("Creating default configurations...")
        
        engine = create_engine(database_url)
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Default configurations
        default_configs = [
            {
                'config_key': 'team_structure',
                'config_value': {
                    'black_hat': {
                        'max_members': 10,
                        'risk_tolerance': 'high',
                        'required_skills': ['exploitation', 'malware_development']
                    },
                    'red_team': {
                        'max_members': 15,
                        'risk_tolerance': 'medium',
                        'required_skills': ['penetration_testing', 'vulnerability_assessment']
                    },
                    'blue_team': {
                        'max_members': 20,
                        'risk_tolerance': 'low',
                        'required_skills': ['incident_response', 'threat_detection']
                    },
                    'purple_team': {
                        'max_members': 8,
                        'risk_tolerance': 'medium',
                        'required_skills': ['team_collaboration', 'strategy_development']
                    }
                },
                'description': 'Default team structure configuration'
            },
            {
                'config_key': 'exercise_settings',
                'config_value': {
                    'max_concurrent_exercises': 5,
                    'default_duration_hours': 8,
                    'require_approval': True,
                    'auto_cleanup_days': 30,
                    'notification_settings': {
                        'email_enabled': True,
                        'slack_enabled': False,
                        'teams_enabled': False
                    }
                },
                'description': 'Default exercise settings'
            },
            {
                'config_key': 'workflow_settings',
                'config_value': {
                    'max_concurrent_workflows': 10,
                    'default_timeout_minutes': 60,
                    'auto_retry_failed': True,
                    'max_retry_attempts': 3,
                    'notification_settings': {
                        'workflow_completed': True,
                        'workflow_failed': True,
                        'workflow_timeout': True
                    }
                },
                'description': 'Default workflow settings'
            },
            {
                'config_key': 'security_settings',
                'config_value': {
                    'session_timeout_minutes': 30,
                    'max_login_attempts': 5,
                    'lockout_duration_minutes': 15,
                    'password_policy': {
                        'min_length': 12,
                        'require_uppercase': True,
                        'require_lowercase': True,
                        'require_numbers': True,
                        'require_symbols': True
                    },
                    'api_rate_limit': {
                        'requests_per_minute': 100,
                        'burst_limit': 200
                    }
                },
                'description': 'Security and authentication settings'
            },
            {
                'config_key': 'monitoring_settings',
                'config_value': {
                    'metrics_enabled': True,
                    'collection_interval_seconds': 60,
                    'retention_days': 90,
                    'alert_thresholds': {
                        'cpu_usage': 90,
                        'memory_usage': 85,
                        'disk_usage': 80,
                        'response_time_ms': 5000
                    },
                    'notification_channels': {
                        'email': True,
                        'slack': False,
                        'webhook': False
                    }
                },
                'description': 'Monitoring and alerting settings'
            }
        ]
        
        for config_data in default_configs:
            # Check if configuration already exists
            existing = session.query(TeamConfiguration).filter_by(config_key=config_data['config_key']).first()
            if not existing:
                config = TeamConfiguration(**config_data)
                session.add(config)
                logger.info(f"Created configuration: {config_data['config_key']}")
        
        session.commit()
        logger.info("Default configurations created successfully!")
        
        return True
        
    except Exception as e:
        logger.error(f"Configuration creation failed: {e}")
        session.rollback()
        return False
    finally:
        session.close()

async def create_sample_team_members():
    """Create sample team members for demonstration."""
    try:
        database_url = os.getenv('DATABASE_URL', 'postgresql://orchestrator:orchestrator_pass@localhost:5432/orchestrator_db')
        
        logger.info("Creating sample team members...")
        
        engine = create_engine(database_url)
        
        # Import TeamMember model
        from migrate_database import TeamMember
        
        TeamMember.metadata.create_all(engine)
        
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Sample team members
        sample_members = [
            # Black Hat Team
            {
                'member_id': 'bh-001',
                'team_type': 'black_hat',
                'name': 'Alice Johnson',
                'role': 'Senior Ethical Hacker',
                'skills': ['exploitation', 'malware_development', 'apt_simulation'],
                'specializations': ['zero_day_research', 'custom_exploits'],
                'experience_level': 'senior'
            },
            {
                'member_id': 'bh-002',
                'team_type': 'black_hat',
                'name': 'Bob Smith',
                'role': 'Malware Analyst',
                'skills': ['reverse_engineering', 'malware_analysis', 'evasion_techniques'],
                'specializations': ['polymorphic_code', 'anti_analysis'],
                'experience_level': 'senior'
            },
            # Red Team
            {
                'member_id': 'rt-001',
                'team_type': 'red_team',
                'name': 'Carol Davis',
                'role': 'Red Team Lead',
                'skills': ['penetration_testing', 'vulnerability_assessment'],
                'specializations': ['web_application_testing', 'network_security'],
                'experience_level': 'senior'
            },
            {
                'member_id': 'rt-002',
                'team_type': 'red_team',
                'name': 'David Wilson',
                'role': 'Penetration Tester',
                'skills': ['network_penetration', 'social_engineering', 'physical_testing'],
                'specializations': ['wireless_security', 'iot_testing'],
                'experience_level': 'intermediate'
            },
            # Blue Team
            {
                'member_id': 'bt-001',
                'team_type': 'blue_team',
                'name': 'Eva Brown',
                'role': 'Blue Team Lead',
                'skills': ['incident_response', 'threat_detection'],
                'specializations': ['malware_analysis', 'digital_forensics'],
                'experience_level': 'senior'
            },
            {
                'member_id': 'bt-002',
                'team_type': 'blue_team',
                'name': 'Frank Miller',
                'role': 'Security Analyst',
                'skills': ['siem_analysis', 'log_analysis', 'threat_hunting'],
                'specializations': ['network_forensics', 'intrusion_analysis'],
                'experience_level': 'intermediate'
            },
            # Purple Team
            {
                'member_id': 'pt-001',
                'team_type': 'purple_team',
                'name': 'Grace Taylor',
                'role': 'Purple Team Lead',
                'skills': ['team_collaboration', 'strategy_development'],
                'specializations': ['exercise_planning', 'metrics_analysis'],
                'experience_level': 'senior'
            },
            {
                'member_id': 'pt-002',
                'team_type': 'purple_team',
                'name': 'Henry Anderson',
                'role': 'Security Strategist',
                'skills': ['risk_assessment', 'security_architecture'],
                'specializations': ['threat_modeling', 'compliance'],
                'experience_level': 'senior'
            }
        ]
        
        for member_data in sample_members:
            # Check if member already exists
            existing = session.query(TeamMember).filter_by(member_id=member_data['member_id']).first()
            if not existing:
                member = TeamMember(**member_data)
                session.add(member)
                logger.info(f"Created team member: {member_data['name']} ({member_data['team_type']})")
        
        session.commit()
        logger.info("Sample team members created successfully!")
        
        return True
        
    except Exception as e:
        logger.error(f"Sample team member creation failed: {e}")
        session.rollback()
        return False
    finally:
        session.close()

async def main():
    """Main function."""
    logger.info("Creating admin user and default configurations...")
    
    # Create admin user
    if not await create_admin_user():
        logger.error("Admin user creation failed!")
        sys.exit(1)
    
    # Create default configurations
    if not await create_default_configurations():
        logger.error("Default configuration creation failed!")
        sys.exit(1)
    
    # Create sample team members
    if not await create_sample_team_members():
        logger.error("Sample team member creation failed!")
        sys.exit(1)
    
    logger.info("")
    logger.info("🎉 Admin user and default configurations created successfully!")
    logger.info("")
    logger.info("📋 Next Steps:")
    logger.info("1. Log in to the web interface with the admin credentials")
    logger.info("2. Change the default password")
    logger.info("3. Configure your OpenRouter API key")
    logger.info("4. Add your team members")
    logger.info("5. Create your first security exercise")
    logger.info("")

if __name__ == "__main__":
    asyncio.run(main())
