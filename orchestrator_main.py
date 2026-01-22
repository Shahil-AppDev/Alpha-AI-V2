#!/usr/bin/env python3
"""
Enhanced AI Security Team Orchestrator - Main Application

This is the main entry point for the Enhanced AI Security Team Orchestrator platform,
integrating Black Hat, Red Team, Blue Team, and Purple Team capabilities with
OpenRouter AI integration.
"""

import asyncio
import logging
import sys
import os
from pathlib import Path
import argparse
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/data/logs/orchestrator.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Import modules
from modules.security_orchestrator import SecurityOrchestrator
from modules.security_team_structure import SecurityTeamOrchestrator as TeamOrchestrator, TeamType, TeamMember
from modules.team_workflows import TeamWorkflowEngine
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Initialize FastAPI app
app = FastAPI(
    title="Enhanced AI Security Team Orchestrator",
    description="Enterprise-grade security team management and orchestration platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Global variables
security_orchestrator: Optional[SecurityOrchestrator] = None
team_orchestrator: Optional[TeamOrchestrator] = None
workflow_engine: Optional[TeamWorkflowEngine] = None

async def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verify API token."""
    token = credentials.credentials
    
    # Simple token validation (in production, use proper JWT validation)
    if not token.startswith("sk-"):
        raise HTTPException(status_code=401, detail="Invalid token format")
    
    return token

@app.on_event("startup")
async def startup_event():
    """Initialize the orchestrator on startup."""
    global security_orchestrator, team_orchestrator, workflow_engine
    
    logger.info("🚀 Starting Enhanced AI Security Team Orchestrator...")
    
    try:
        # Initialize configuration
        config = load_configuration()
        
        # Initialize security orchestrator
        logger.info("🧠 Initializing Security Orchestrator...")
        security_orchestrator = SecurityOrchestrator(config.get('openrouter_api_key', ''))
        await security_orchestrator.initialize()
        
        # Initialize team orchestrator
        logger.info("👥 Initializing Team Orchestrator...")
        team_orchestrator = TeamOrchestrator(config.get('teams', {}))
        await team_orchestrator.initialize()
        
        # Initialize workflow engine
        logger.info("⚙️ Initializing Workflow Engine...")
        workflow_engine = TeamWorkflowEngine(team_orchestrator)
        await workflow_engine.initialize()
        
        logger.info("✅ Enhanced AI Security Team Orchestrator initialized successfully!")
        logger.info("🌐 Server is ready to accept requests")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize orchestrator: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    global security_orchestrator, team_orchestrator, workflow_engine
    
    logger.info("🛑 Shutting down Enhanced AI Security Team Orchestrator...")
    
    try:
        if security_orchestrator:
            await security_orchestrator.shutdown()
        
        if team_orchestrator:
            # Team orchestrator cleanup if needed
            pass
        
        if workflow_engine:
            # Workflow engine cleanup if needed
            pass
        
        logger.info("✅ Shutdown completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Error during shutdown: {e}")

def load_configuration() -> Dict[str, Any]:
    """Load configuration from environment and files."""
    config = {
        'openrouter_api_key': os.getenv('OPENROUTER_API_KEY', ''),
        'database_url': os.getenv('DATABASE_URL', 'postgresql://orchestrator:orchestrator_pass@localhost:5432/orchestrator_db'),
        'redis_url': os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
        'elasticsearch_url': os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200'),
        'log_level': os.getenv('LOG_LEVEL', 'INFO'),
        'environment': os.getenv('ENVIRONMENT', 'development'),
        'max_concurrent_exercises': int(os.getenv('MAX_CONCURRENT_EXERCISES', '5')),
        'require_human_approval': os.getenv('REQUIRE_HUMAN_APPROVAL', 'true').lower() == 'true'
    }
    
    # Load team configuration
    teams_config_path = Path(__file__).parent / "config" / "security-teams" / "teams.yaml"
    if teams_config_path.exists():
        try:
            import yaml
            with open(teams_config_path, 'r') as f:
                teams_config = yaml.safe_load(f)
                config['teams'] = teams_config
        except Exception as e:
            logger.warning(f"Failed to load teams configuration: {e}")
            config['teams'] = {}
    else:
        config['teams'] = {}
    
    return config

# Health Check Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "services": {
            "security_orchestrator": security_orchestrator is not None,
            "team_orchestrator": team_orchestrator is not None,
            "workflow_engine": workflow_engine is not None
        }
    }

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Enhanced AI Security Team Orchestrator",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }

# Security Orchestrator Endpoints
@app.get("/api/v1/status")
async def get_orchestrator_status(token: str = Depends(verify_token)):
    """Get overall orchestrator status."""
    if not security_orchestrator:
        raise HTTPException(status_code=503, detail="Security orchestrator not initialized")
    
    try:
        status = await security_orchestrator.get_orchestrator_status()
        return status
    except Exception as e:
        logger.error(f"Error getting orchestrator status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/tasks")
async def add_security_task(task_data: Dict[str, Any], token: str = Depends(verify_token)):
    """Add a security task."""
    if not security_orchestrator:
        raise HTTPException(status_code=503, detail="Security orchestrator not initialized")
    
    try:
        task_id = await security_orchestrator.add_security_task(task_data)
        return {"task_id": task_id, "status": "queued"}
    except Exception as e:
        logger.error(f"Error adding security task: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/tasks/{task_id}")
async def get_task_status(task_id: str, token: str = Depends(verify_token)):
    """Get task status."""
    if not security_orchestrator:
        raise HTTPException(status_code=503, detail="Security orchestrator not initialized")
    
    try:
        status = await security_orchestrator.get_task_status(task_id)
        return status
    except Exception as e:
        logger.error(f"Error getting task status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/plan-attack")
async def plan_attack(target_info: Dict[str, Any], token: str = Depends(verify_token)):
    """Plan attack using AI."""
    if not security_orchestrator:
        raise HTTPException(status_code=503, detail="Security orchestrator not initialized")
    
    try:
        plan = await security_orchestrator.plan_attack(target_info)
        return plan
    except Exception as e:
        logger.error(f"Error planning attack: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/analyze-vulnerabilities")
async def analyze_vulnerabilities(scan_results: Dict[str, Any], token: str = Depends(verify_token)):
    """Analyze vulnerabilities using AI."""
    if not security_orchestrator:
        raise HTTPException(status_code=503, detail="Security orchestrator not initialized")
    
    try:
        analysis = await security_orchestrator.analyze_vulnerabilities(scan_results)
        return analysis
    except Exception as e:
        logger.error(f"Error analyzing vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Team Management Endpoints
@app.get("/api/v1/teams")
async def get_team_status(token: str = Depends(verify_token)):
    """Get all team status."""
    if not team_orchestrator:
        raise HTTPException(status_code=503, detail="Team orchestrator not initialized")
    
    try:
        status = await team_orchestrator.get_team_status()
        return status
    except Exception as e:
        logger.error(f"Error getting team status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/teams/{team_type}")
async def get_specific_team_status(team_type: str, token: str = Depends(verify_token)):
    """Get specific team status."""
    if not team_orchestrator:
        raise HTTPException(status_code=503, detail="Team orchestrator not initialized")
    
    try:
        team_enum = TeamType(team_type)
        status = await team_orchestrator.get_team_status(team_enum)
        return status
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid team type: {team_type}")
    except Exception as e:
        logger.error(f"Error getting team status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/teams/members")
async def add_team_member(member_data: Dict[str, Any], token: str = Depends(verify_token)):
    """Add team member."""
    if not team_orchestrator:
        raise HTTPException(status_code=503, detail="Team orchestrator not initialized")
    
    try:
        team_type = TeamType(member_data['team_type'])
        member = TeamMember(
            member_id=member_data['member_id'],
            name=member_data['name'],
            role=member_data['role'],
            skills=member_data['skills'],
            specializations=member_data['specializations'],
            experience_level=member_data['experience_level']
        )
        
        await team_orchestrator.add_team_member(team_type, member)
        return {"status": "success", "message": f"Member added to {team_type.value}"}
    except Exception as e:
        logger.error(f"Error adding team member: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Exercise Management Endpoints
@app.post("/api/v1/exercises")
async def create_exercise(exercise_data: Dict[str, Any], token: str = Depends(verify_token)):
    """Create security exercise."""
    if not team_orchestrator:
        raise HTTPException(status_code=503, detail="Team orchestrator not initialized")
    
    try:
        exercise_id = await team_orchestrator.create_exercise(exercise_data)
        return {"exercise_id": exercise_id, "status": "created"}
    except Exception as e:
        logger.error(f"Error creating exercise: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/exercises/{exercise_id}/execute")
async def execute_exercise(exercise_id: str, token: str = Depends(verify_token)):
    """Execute security exercise."""
    if not team_orchestrator:
        raise HTTPException(status_code=503, detail="Team orchestrator not initialized")
    
    try:
        result = await team_orchestrator.execute_exercise(exercise_id)
        return result
    except Exception as e:
        logger.error(f"Error executing exercise: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/exercises/history")
async def get_exercise_history(limit: int = 10, token: str = Depends(verify_token)):
    """Get exercise history."""
    if not team_orchestrator:
        raise HTTPException(status_code=503, detail="Team orchestrator not initialized")
    
    try:
        history = await team_orchestrator.get_exercise_history(limit)
        return {"history": history, "total": len(history)}
    except Exception as e:
        logger.error(f"Error getting exercise history: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Workflow Management Endpoints
@app.get("/api/v1/workflows/templates")
async def get_workflow_templates(token: str = Depends(verify_token)):
    """Get available workflow templates."""
    if not workflow_engine:
        raise HTTPException(status_code=503, detail="Workflow engine not initialized")
    
    try:
        templates = await workflow_engine.get_available_templates()
        return templates
    except Exception as e:
        logger.error(f"Error getting workflow templates: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/workflows")
async def create_workflow(workflow_data: Dict[str, Any], token: str = Depends(verify_token)):
    """Create workflow from template."""
    if not workflow_engine:
        raise HTTPException(status_code=503, detail="Workflow engine not initialized")
    
    try:
        workflow_id = await workflow_engine.create_workflow(
            workflow_data['template'],
            workflow_data.get('customizations', {})
        )
        return {"workflow_id": workflow_id, "status": "created"}
    except Exception as e:
        logger.error(f"Error creating workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/workflows/{workflow_id}/execute")
async def execute_workflow(workflow_id: str, token: str = Depends(verify_token)):
    """Execute workflow."""
    if not workflow_engine:
        raise HTTPException(status_code=503, detail="Workflow engine not initialized")
    
    try:
        result = await workflow_engine.execute_workflow(workflow_id)
        return result
    except Exception as e:
        logger.error(f"Error executing workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/workflows/{workflow_id}/status")
async def get_workflow_status(workflow_id: str, token: str = Depends(verify_token)):
    """Get workflow status."""
    if not workflow_engine:
        raise HTTPException(status_code=503, detail="Workflow engine not initialized")
    
    try:
        status = await workflow_engine.get_workflow_status(workflow_id)
        return status
    except Exception as e:
        logger.error(f"Error getting workflow status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/workflows/history")
async def get_interaction_history(limit: int = 50, token: str = Depends(verify_token)):
    """Get interaction history."""
    if not workflow_engine:
        raise HTTPException(status_code=503, detail="Workflow engine not initialized")
    
    try:
        history = await workflow_engine.get_interaction_history(limit)
        return {"history": history, "total": len(history)}
    except Exception as e:
        logger.error(f"Error getting interaction history: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Metrics Endpoints
@app.get("/api/v1/metrics")
async def get_metrics(token: str = Depends(verify_token)):
    """Get comprehensive metrics."""
    if not team_orchestrator:
        raise HTTPException(status_code=503, detail="Team orchestrator not initialized")
    
    try:
        metrics = await team_orchestrator.get_metrics()
        return metrics
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# CLI Functions
async def cli_mode():
    """Command line interface mode."""
    parser = argparse.ArgumentParser(description="Enhanced AI Security Team Orchestrator")
    parser.add_argument("--objective", help="Security objective to accomplish")
    parser.add_argument("--target", help="Target for security assessment")
    parser.add_argument("--team", choices=["black_hat", "red_team", "blue_team", "purple_team"], help="Team to use")
    parser.add_argument("--exercise-type", choices=["collaborative", "incident_response", "threat_intel"], help="Exercise type")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    
    args = parser.parse_args()
    
    if args.interactive:
        await interactive_mode()
    elif args.objective:
        await execute_objective(args)
    else:
        parser.print_help()

async def interactive_mode():
    """Interactive mode."""
    print("🚀 Enhanced AI Security Team Orchestrator - Interactive Mode")
    print("=" * 60)
    
    while True:
        try:
            command = input("\n> ").strip()
            
            if command.lower() in ['exit', 'quit']:
                break
            elif command.lower() == 'help':
                print_help()
            elif command.lower() == 'status':
                await show_status()
            elif command.startswith('exercise'):
                await create_exercise_cli(command)
            elif command.startswith('team'):
                await show_team_status(command)
            else:
                print("Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            break
    
    print("\n👋 Goodbye!")

async def execute_objective(args):
    """Execute security objective."""
    print(f"🎯 Executing objective: {args.objective}")
    
    # Initialize orchestrators
    config = load_configuration()
    
    security_orchestrator = SecurityOrchestrator(config.get('openrouter_api_key', ''))
    await security_orchestrator.initialize()
    
    team_orchestrator = TeamOrchestrator(config.get('teams', {}))
    await team_orchestrator.initialize()
    
    # Create and execute exercise based on objective
    exercise_data = {
        'name': f'CLI Exercise - {args.objective}',
        'type': args.exercise_type or 'collaborative',
        'teams': ['red_team', 'blue_team', 'purple_team'],
        'objectives': [args.objective],
        'scope': {'target': args.target} if args.target else {},
        'start_time': datetime.now().isoformat(),
        'end_time': (datetime.now() + timedelta(hours=8)).isoformat()
    }
    
    exercise_id = await team_orchestrator.create_exercise(exercise_data)
    print(f"📋 Created exercise: {exercise_id}")
    
    result = await team_orchestrator.execute_exercise(exercise_id)
    print(f"✅ Exercise completed: {result['overall_result']['overall_success']}")

def print_help():
    """Print help information."""
    print("""
Available Commands:
  help                    - Show this help message
  status                  - Show system status
  exercise create         - Create new exercise
  exercise list           - List exercises
  team status             - Show team status
  team list               - List team members
  metrics                 - Show performance metrics
  exit/quit               - Exit interactive mode
    """)

async def show_status():
    """Show system status."""
    print("📊 System Status:")
    print("  Security Orchestrator: ✅ Running" if security_orchestrator else "  Security Orchestrator: ❌ Not Running")
    print("  Team Orchestrator: ✅ Running" if team_orchestrator else "  Team Orchestrator: ❌ Not Running")
    print("  Workflow Engine: ✅ Running" if workflow_engine else "  Workflow Engine: ❌ Not Running")

async def create_exercise_cli(command):
    """Create exercise from CLI."""
    print("📝 Creating new exercise...")
    # Implementation for CLI exercise creation
    pass

async def show_team_status(command):
    """Show team status from CLI."""
    if team_orchestrator:
        status = await team_orchestrator.get_team_status()
        print("👥 Team Status:")
        for team, team_status in status.items():
            print(f"  {team.title()}: {team_status['status']}")
    else:
        print("❌ Team orchestrator not available")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Enhanced AI Security Team Orchestrator")
    parser.add_argument("--server", action="store_true", help="Run in server mode")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument("--objective", help="Security objective to accomplish")
    parser.add_argument("--target", help="Target for security assessment")
    
    args = parser.parse_args()
    
    if args.server or not any([args.cli, args.objective]):
        # Server mode (default)
        logger.info(f"🌐 Starting server on {args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    else:
        # CLI mode
        asyncio.run(cli_mode())

if __name__ == "__main__":
    main()
