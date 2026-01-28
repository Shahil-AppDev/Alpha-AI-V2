"""
HackerAI Platform REST API

FastAPI-based REST API for the Universal Tool Manager.
Provides endpoints for tool execution, management, and monitoring.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import json
import os

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from fastapi import Query
import uvicorn

# Import our modules
import sys
from pathlib import Path

# Add src directory to path
src_path = str(Path(__file__).parent.parent)
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from modules.universal_tool_manager import (
    UniversalToolManager, HackerAIPlatform, ToolCategory, ExecutionMode
)
from modules.social_osint_agent import SocialOSINTAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="HackerAI Platform API",
    description="Universal Security Tool Management Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Initialize platform
platform = HackerAIPlatform()
tool_manager = platform.tool_manager
osint_agent = SocialOSINTAgent()

# Pydantic models for API
class ToolExecutionRequest(BaseModel):
    tool_name: str = Field(..., description="Name of the tool to execute")
    target: str = Field(..., description="Target (IP, URL, domain, etc.)")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Tool parameters")
    execution_mode: Optional[str] = Field(None, description="Execution mode (native, docker, kubernetes)")

class ToolExecutionResponse(BaseModel):
    execution_id: str
    tool_name: str
    target: str
    status: str
    start_time: str
    end_time: Optional[str] = None
    output: str = ""
    error: str = ""

class ComprehensiveAssessmentRequest(BaseModel):
    target: str = Field(..., description="Target for assessment")
    categories: List[str] = Field(default=["osint", "network", "web"], description="Assessment categories")

class OSINTRequest(BaseModel):
    name: str = Field(..., description="Target name")
    email: Optional[str] = Field(None, description="Target email")
    social_profiles: Dict[str, str] = Field(default_factory=dict, description="Social media profiles")

class ToolListResponse(BaseModel):
    tools: List[Dict[str, Any]]
    total_count: int
    categories: Dict[str, int]

class SystemStatusResponse(BaseModel):
    platform_status: Dict[str, Any]
    tool_statistics: Dict[str, Any]
    execution_history: List[Dict[str, Any]]

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Simple authentication - replace with proper auth in production."""
    token = credentials.credentials
    # Simple token validation - replace with proper JWT/OAuth
    if token != "hackerai-api-key-2024":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"user": "api_user"}

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "platform": "HackerAI"
    }

# Platform status endpoints
@app.get("/api/v1/status", response_model=SystemStatusResponse, tags=["Status"])
async def get_platform_status(current_user: dict = Depends(get_current_user)):
    """Get overall platform status."""
    try:
        platform_status = platform.get_platform_status()
        execution_history = tool_manager.get_execution_history(limit=50)
        
        return SystemStatusResponse(
            platform_status=platform_status,
            tool_statistics=tool_manager.get_system_statistics(),
            execution_history=[
                {
                    "execution_id": exec.execution_id,
                    "tool_name": exec.tool_name,
                    "target": exec.target,
                    "status": exec.status,
                    "start_time": exec.start_time.isoformat(),
                    "end_time": exec.end_time.isoformat() if exec.end_time else None,
                    "duration": (exec.end_time - exec.start_time).total_seconds() if exec.end_time else None
                }
                for exec in execution_history
            ]
        )
    except Exception as e:
        logger.error(f"Error getting platform status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Tool management endpoints
@app.get("/api/v1/tools", response_model=ToolListResponse, tags=["Tools"])
async def list_tools(category: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """List all available tools."""
    try:
        if category:
            try:
                tool_category = ToolCategory(category)
                tools = tool_manager.list_tools(tool_category)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid category: {category}")
        else:
            tools = tool_manager.list_tools()
        
        categorized_tools = tool_manager.get_tools_by_category()
        
        return ToolListResponse(
            tools=[
                {
                    "name": tool.name,
                    "category": tool.category.value,
                    "description": tool.description,
                    "version": tool.version,
                    "status": tool.status.value,
                    "execution_mode": tool.execution_mode.value,
                    "total_executions": tool.total_executions,
                    "success_rate": tool.success_rate,
                    "average_execution_time": tool.average_execution_time
                }
                for tool in tools
            ],
            total_count=len(tools),
            categories={cat.value: len(tools) for cat, tools in categorized_tools.items()}
        )
    except Exception as e:
        logger.error(f"Error listing tools: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/tools/{tool_name}", tags=["Tools"])
async def get_tool_details(tool_name: str, current_user: dict = Depends(get_current_user)):
    """Get detailed information about a specific tool."""
    try:
        tool = tool_manager.get_tool(tool_name)
        if not tool:
            raise HTTPException(status_code=404, detail=f"Tool not found: {tool_name}")
        
        stats = tool_manager.get_tool_statistics(tool_name)
        
        return {
            "tool": {
                "name": tool.name,
                "category": tool.category.value,
                "description": tool.description,
                "version": tool.version,
                "executable_path": tool.executable_path,
                "docker_image": tool.docker_image,
                "parameters": tool.parameters,
                "execution_mode": tool.execution_mode.value,
                "status": tool.status.value,
                "dependencies": tool.dependencies
            },
            "statistics": stats
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting tool details: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Tool execution endpoints
@app.post("/api/v1/tools/execute", response_model=ToolExecutionResponse, tags=["Execution"])
async def execute_tool(
    request: ToolExecutionRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Execute a tool."""
    try:
        # Validate tool exists
        tool = tool_manager.get_tool(request.tool_name)
        if not tool:
            raise HTTPException(status_code=404, detail=f"Tool not found: {request.tool_name}")
        
        # Parse execution mode
        execution_mode = None
        if request.execution_mode:
            try:
                execution_mode = ExecutionMode(request.execution_mode)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid execution mode: {request.execution_mode}")
        
        # Execute tool
        execution = await tool_manager.execute_tool(
            request.tool_name,
            request.target,
            request.parameters,
            execution_mode
        )
        
        return ToolExecutionResponse(
            execution_id=execution.execution_id,
            tool_name=execution.tool_name,
            target=execution.target,
            status=execution.status,
            start_time=execution.start_time.isoformat(),
            end_time=execution.end_time.isoformat() if execution.end_time else None,
            output=execution.output,
            error=execution.error
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing tool: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/executions/{execution_id}", tags=["Execution"])
async def get_execution_status(execution_id: str, current_user: dict = Depends(get_current_user)):
    """Get status of a specific execution."""
    try:
        execution = tool_manager.executions.get(execution_id)
        if not execution:
            raise HTTPException(status_code=404, detail=f"Execution not found: {execution_id}")
        
        return {
            "execution_id": execution.execution_id,
            "tool_name": execution.tool_name,
            "target": execution.target,
            "parameters": execution.parameters,
            "execution_mode": execution.execution_mode.value,
            "status": execution.status,
            "start_time": execution.start_time.isoformat(),
            "end_time": execution.end_time.isoformat() if execution.end_time else None,
            "output": execution.output,
            "error": execution.error,
            "exit_code": execution.exit_code,
            "container_id": execution.container_id,
            "resource_usage": execution.resource_usage
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting execution status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/executions", tags=["Execution"])
async def list_executions(
    tool_name: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(get_current_user)
):
    """List execution history."""
    try:
        executions = tool_manager.get_execution_history(tool_name, limit)
        
        return {
            "executions": [
                {
                    "execution_id": exec.execution_id,
                    "tool_name": exec.tool_name,
                    "target": exec.target,
                    "status": exec.status,
                    "start_time": exec.start_time.isoformat(),
                    "end_time": exec.end_time.isoformat() if exec.end_time else None,
                    "duration": (exec.end_time - exec.start_time).total_seconds() if exec.end_time else None
                }
                for exec in executions
            ],
            "total_count": len(executions)
        }
    except Exception as e:
        logger.error(f"Error listing executions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Comprehensive assessment endpoints
@app.post("/api/v1/assess", tags=["Assessment"])
async def run_comprehensive_assessment(
    request: ComprehensiveAssessmentRequest,
    current_user: dict = Depends(get_current_user)
):
    """Run comprehensive security assessment."""
    try:
        assessment = await platform.run_comprehensive_assessment(
            request.target,
            request.categories
        )
        
        return assessment
    except Exception as e:
        logger.error(f"Error running assessment: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# OSINT endpoints
@app.post("/api/v1/osint/target", tags=["OSINT"])
async def add_osint_target(
    request: OSINTRequest,
    current_user: dict = Depends(get_current_user)
):
    """Add a new OSINT target."""
    try:
        target_id = await osint_agent.add_target(
            name=request.name,
            email=request.email,
            social_profiles=request.social_profiles
        )
        
        return {
            "success": True,
            "target_id": target_id,
            "message": f"OSINT target '{request.name}' added successfully"
        }
    except Exception as e:
        logger.error(f"Error adding OSINT target: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/osint/{target_id}/collect", tags=["OSINT"])
async def collect_osint_data(
    target_id: str,
    sources: Optional[List[str]] = None,
    current_user: dict = Depends(get_current_user)
):
    """Collect OSINT data for a target."""
    try:
        collected = await osint_agent.collect_data(target_id, sources)
        
        return {
            "success": True,
            "target_id": target_id,
            "data_count": len(collected),
            "sources": list(set(d.source.value for d in collected)),
            "data": [
                {
                    "id": d.data_id,
                    "source": d.source.value,
                    "confidence": d.confidence_score,
                    "collected_at": d.collected_at.isoformat()
                }
                for d in collected
            ]
        }
    except Exception as e:
        logger.error(f"Error collecting OSINT data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/osint/{target_id}/analyze", tags=["OSINT"])
async def analyze_osint_target(
    target_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Analyze collected OSINT data."""
    try:
        analysis = await osint_agent.analyze_target(target_id)
        
        return {
            "success": True,
            "target_id": target_id,
            "analysis_id": analysis.result_id,
            "sentiment_score": analysis.sentiment_score,
            "threat_level": analysis.threat_level.value,
            "key_findings": analysis.key_findings,
            "recommendations": analysis.recommendations,
            "created_at": analysis.created_at.isoformat()
        }
    except Exception as e:
        logger.error(f"Error analyzing OSINT target: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/osint/targets", tags=["OSINT"])
async def list_osint_targets(current_user: dict = Depends(get_current_user)):
    """List all OSINT targets."""
    try:
        targets = osint_agent.list_targets()
        
        return {
            "success": True,
            "target_count": len(targets),
            "targets": targets
        }
    except Exception as e:
        logger.error(f"Error listing OSINT targets: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Tool management endpoints
@app.post("/api/v1/tools/{tool_name}/install", tags=["Tools"])
async def install_tool(tool_name: str, current_user: dict = Depends(get_current_user)):
    """Install a tool."""
    try:
        success = await tool_manager.install_tool(tool_name)
        
        return {
            "success": success,
            "message": f"Tool {tool_name} {'installed successfully' if success else 'installation failed'}"
        }
    except Exception as e:
        logger.error(f"Error installing tool: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/tools/{tool_name}/update", tags=["Tools"])
async def update_tool(tool_name: str, current_user: dict = Depends(get_current_user)):
    """Update a tool."""
    try:
        success = await tool_manager.update_tool(tool_name)
        
        return {
            "success": success,
            "message": f"Tool {tool_name} {'updated successfully' if success else 'update failed'}"
        }
    except Exception as e:
        logger.error(f"Error updating tool: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/tools/update-all", tags=["Tools"])
async def update_all_tools(current_user: dict = Depends(get_current_user)):
    """Update all tools."""
    try:
        results = await tool_manager.update_all_tools()
        
        return {
            "success": True,
            "results": results,
            "summary": {
                "total": len(results),
                "successful": sum(1 for success in results.values() if success),
                "failed": sum(1 for success in results.values() if not success)
            }
        }
    except Exception as e:
        logger.error(f"Error updating all tools: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Category-specific endpoints
@app.get("/api/v1/categories", tags=["Tools"])
async def list_categories(current_user: dict = Depends(get_current_user)):
    """List tool categories and their tools."""
    try:
        categorized_tools = tool_manager.get_tools_by_category()
        
        return {
            "categories": {
                category.value: [
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "status": tool.status.value
                    }
                    for tool in tools
                ]
                for category, tools in categorized_tools.items()
            }
        }
    except Exception as e:
        logger.error(f"Error listing categories: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Background task endpoints
@app.post("/api/v1/tasks/scan/{target}", tags=["Tasks"])
async def start_background_scan(
    target: str,
    background_tasks: BackgroundTasks,
    categories: List[str] = Query(default=["osint", "network"]),
    current_user: dict = Depends(get_current_user)
):
    """Start a background comprehensive scan."""
    task_id = str(uuid.uuid4())
    
    # Add background task
    background_tasks.add_task(
        run_background_assessment,
        task_id,
        target,
        categories
    )
    
    return {
        "task_id": task_id,
        "target": target,
        "categories": categories,
        "status": "started",
        "message": f"Background scan started for {target}"
    }

async def run_background_assessment(task_id: str, target: str, categories: List[str]):
    """Background task for comprehensive assessment."""
    try:
        logger.info(f"Starting background assessment {task_id} for {target}")
        result = await platform.run_comprehensive_assessment(target, categories)
        
        # Store result (in a real implementation, you'd store this in a database)
        logger.info(f"Background assessment {task_id} completed for {target}")
        
    except Exception as e:
        logger.error(f"Background assessment {task_id} failed: {e}")

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "status_code": 500}
    )

# Main function
def main():
    """Main function to run the API server."""
    uvicorn.run(
        "hackerai_api:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )

if __name__ == "__main__":
    main()
