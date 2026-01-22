#!/usr/bin/env python3
"""
Database Migration Script for Security Team Orchestrator

This script initializes and migrates the database schema for the
Security Team Orchestrator platform.
"""

import asyncio
import logging
import sys
import os
from pathlib import Path

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

class SecurityExercise(Base):
    """Security exercise model."""
    __tablename__ = 'security_exercises'
    
    exercise_id = Column(String(50), primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    exercise_type = Column(String(50), nullable=False)
    teams_involved = Column(JSON)
    objectives = Column(JSON)
    scope = Column(JSON)
    timeline = Column(JSON)
    status = Column(String(20), default='planned')
    results = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class TeamMember(Base):
    """Team member model."""
    __tablename__ = 'team_members'
    
    member_id = Column(String(50), primary_key=True)
    team_type = Column(String(20), nullable=False)
    name = Column(String(100), nullable=False)
    role = Column(String(100), nullable=False)
    skills = Column(JSON)
    specializations = Column(JSON)
    experience_level = Column(String(20))
    availability = Column(Boolean, default=True)
    current_task = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class TeamWorkflow(Base):
    """Team workflow model."""
    __tablename__ = 'team_workflows'
    
    workflow_id = Column(String(50), primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    workflow_type = Column(String(50), nullable=False)
    steps = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default='pending')
    current_step = Column(String(50))
    results = Column(JSON)
    participants = Column(JSON)

class InteractionEvent(Base):
    """Interaction event model."""
    __tablename__ = 'interaction_events'
    
    event_id = Column(String(50), primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String(50), nullable=False)
    teams_involved = Column(JSON)
    data = Column(JSON)
    outcome = Column(String(200))

class TeamMetrics(Base):
    """Team metrics model."""
    __tablename__ = 'team_metrics'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    team_type = Column(String(20), nullable=False)
    exercises_completed = Column(Integer, default=0)
    success_rate = Column(Float, default=0.0)
    response_time = Column(Float, default=0.0)
    collaboration_score = Column(Float, default=0.0)
    skill_development = Column(JSON)
    improvement_areas = Column(JSON)
    recorded_at = Column(DateTime, default=datetime.utcnow)

class ExerciseHistory(Base):
    """Exercise history model."""
    __tablename__ = 'exercise_history'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    exercise_id = Column(String(50), nullable=False)
    exercise_name = Column(String(200), nullable=False)
    executed_at = Column(DateTime, default=datetime.utcnow)
    results = Column(JSON)
    overall_result = Column(JSON)

async def create_database():
    """Create database and tables."""
    try:
        # Get database URL from environment
        database_url = os.getenv('DATABASE_URL', 'postgresql://orchestrator:orchestrator_pass@localhost:5432/orchestrator_db')
        
        logger.info("Connecting to database...")
        
        # Create engine
        engine = create_engine(database_url)
        
        logger.info("Creating tables...")
        
        # Create all tables
        Base.metadata.create_all(engine)
        
        logger.info("Database migration completed successfully!")
        
        return True
        
    except Exception as e:
        logger.error(f"Database migration failed: {e}")
        return False

async def create_indexes():
    """Create database indexes for performance."""
    try:
        database_url = os.getenv('DATABASE_URL', 'postgresql://orchestrator:orchestrator_pass@localhost:5432/orchestrator_db')
        
        logger.info("Creating database indexes...")
        
        engine = create_engine(database_url)
        
        # Create indexes
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_exercises_status ON security_exercises(status);",
            "CREATE INDEX IF NOT EXISTS idx_exercises_type ON security_exercises(exercise_type);",
            "CREATE INDEX IF NOT EXISTS idx_exercises_created ON security_exercises(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_members_team ON team_members(team_type);",
            "CREATE INDEX IF NOT EXISTS idx_members_availability ON team_members(availability);",
            "CREATE INDEX IF NOT EXISTS idx_workflows_status ON team_workflows(status);",
            "CREATE INDEX IF NOT EXISTS idx_workflows_type ON team_workflows(workflow_type);",
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON interaction_events(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_events_type ON interaction_events(event_type);",
            "CREATE INDEX IF NOT EXISTS idx_metrics_team ON team_metrics(team_type);",
            "CREATE INDEX IF NOT EXISTS idx_history_executed ON exercise_history(executed_at);"
        ]
        
        with engine.connect() as conn:
            for index_sql in indexes:
                try:
                    conn.execute(index_sql)
                    logger.info(f"Created index: {index_sql.split('idx_')[1].split(' ')[0]}")
                except Exception as e:
                    logger.warning(f"Index creation failed (may already exist): {e}")
        
        logger.info("Database indexes created successfully!")
        
        return True
        
    except Exception as e:
        logger.error(f"Index creation failed: {e}")
        return False

async def seed_default_data():
    """Seed default data."""
    try:
        database_url = os.getenv('DATABASE_URL', 'postgresql://orchestrator:orchestrator_pass@localhost:5432/orchestrator_db')
        
        logger.info("Seeding default data...")
        
        engine = create_engine(database_url)
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Create default workflow templates
        default_workflows = [
            {
                'workflow_id': 'template_collaborative_exercise',
                'name': 'Collaborative Security Exercise',
                'description': 'Standard collaborative exercise between Red and Blue teams',
                'workflow_type': 'collaborative_exercise',
                'steps': [
                    {
                        'step_id': 'planning',
                        'name': 'Exercise Planning',
                        'description': 'Plan and coordinate exercise objectives',
                        'teams_involved': ['red_team', 'blue_team', 'purple_team'],
                        'estimated_duration': 7200
                    },
                    {
                        'step_id': 'execution',
                        'name': 'Exercise Execution',
                        'description': 'Execute the security exercise',
                        'teams_involved': ['red_team', 'blue_team'],
                        'estimated_duration': 21600
                    },
                    {
                        'step_id': 'debrief',
                        'name': 'After Action Review',
                        'description': 'Conduct comprehensive debrief and analysis',
                        'teams_involved': ['red_team', 'blue_team', 'purple_team'],
                        'estimated_duration': 10800
                    }
                ]
            },
            {
                'workflow_id': 'template_incident_response',
                'name': 'Security Incident Response',
                'description': 'Coordinated incident response workflow',
                'workflow_type': 'incident_response',
                'steps': [
                    {
                        'step_id': 'detection',
                        'name': 'Threat Detection',
                        'description': 'Detect and analyze security incident',
                        'teams_involved': ['blue_team'],
                        'estimated_duration': 1800
                    },
                    {
                        'step_id': 'containment',
                        'name': 'Incident Containment',
                        'description': 'Contain and isolate affected systems',
                        'teams_involved': ['blue_team'],
                        'estimated_duration': 7200
                    },
                    {
                        'step_id': 'recovery',
                        'name': 'System Recovery',
                        'description': 'Restore systems to normal operation',
                        'teams_involved': ['blue_team'],
                        'estimated_duration': 21600
                    }
                ]
            }
        ]
        
        for workflow_data in default_workflows:
            # Check if workflow already exists
            existing = session.query(TeamWorkflow).filter_by(workflow_id=workflow_data['workflow_id']).first()
            if not existing:
                workflow = TeamWorkflow(**workflow_data)
                session.add(workflow)
                logger.info(f"Created default workflow: {workflow_data['name']}")
        
        session.commit()
        logger.info("Default data seeded successfully!")
        
        return True
        
    except Exception as e:
        logger.error(f"Data seeding failed: {e}")
        session.rollback()
        return False
    finally:
        session.close()

async def main():
    """Main migration function."""
    logger.info("Starting database migration...")
    
    # Create database and tables
    if not await create_database():
        logger.error("Database creation failed!")
        sys.exit(1)
    
    # Create indexes
    if not await create_indexes():
        logger.error("Index creation failed!")
        sys.exit(1)
    
    # Seed default data
    if not await seed_default_data():
        logger.error("Data seeding failed!")
        sys.exit(1)
    
    logger.info("Database migration completed successfully!")
    logger.info("🎉 Security Team Orchestrator database is ready!")

if __name__ == "__main__":
    asyncio.run(main())
