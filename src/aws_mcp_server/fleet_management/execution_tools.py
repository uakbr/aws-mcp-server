"""
Configuration Execution Tools for AWS MCP Server.

This module provides tools for integrating the configuration execution engine
with the AWS MCP Server's Model Context Protocol.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from ..tools import Tool, ToolSchema
from .configuration import ConfigManager, ConfigRegistry, ConfigType
from .configuration_executor import (
    ExecutionEngine, ExecutionScheduler, ConfigCommandRegistry,
    ConfigExecutionRegistry, ExecutionStatus
)

logger = logging.getLogger(__name__)


class ExecutionTool(Tool):
    """Base class for execution tools."""
    pass


class ListCommandsTool(ExecutionTool):
    """Tool for listing available configuration commands."""
    
    name = "list_commands"
    description = "List available configuration commands for AWS resources"
    
    schema = ToolSchema(
        properties={}
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the list commands tool."""
        try:
            commands = ConfigCommandRegistry.list_commands()
            
            return json.dumps({
                "commands": commands,
                "count": len(commands)
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing commands: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class ExecuteCommandTool(ExecutionTool):
    """Tool for executing a configuration command across targets."""
    
    name = "execute_command"
    description = "Execute a configuration command across AWS resources"
    
    schema = ToolSchema(
        properties={
            "name": {
                "type": "string",
                "description": "Name for the execution"
            },
            "config_id": {
                "type": "string",
                "description": "ID of the configuration set to use"
            },
            "targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of target resource IDs"
            },
            "command": {
                "type": "string",
                "description": "Command to execute"
            },
            "parameters": {
                "type": "object",
                "description": "Parameters for the command"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds"
            },
            "max_concurrent": {
                "type": "integer",
                "description": "Maximum concurrent executions"
            }
        },
        required=["name", "config_id", "targets", "command"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the execute command tool."""
        try:
            name = params.get("name")
            config_id = params.get("config_id")
            targets = params.get("targets", [])
            command = params.get("command")
            parameters = params.get("parameters", {})
            timeout_seconds = params.get("timeout_seconds", 300)
            max_concurrent = params.get("max_concurrent", 10)
            
            # Validate command
            if command not in ConfigCommandRegistry.list_commands():
                return json.dumps({
                    "error": f"Command not found: {command}"
                })
            
            # Validate config ID
            config_set = ConfigRegistry.get_config_set(config_id)
            if not config_set:
                return json.dumps({
                    "error": f"Configuration set not found: {config_id}"
                })
            
            # Execute command
            execution_id = await ExecutionEngine.execute_command(
                name=name,
                config_id=config_id,
                targets=targets,
                command=command,
                parameters=parameters,
                timeout_seconds=timeout_seconds,
                max_concurrent=max_concurrent
            )
            
            return json.dumps({
                "execution_id": execution_id,
                "name": name,
                "command": command,
                "targets_count": len(targets),
                "status": "pending"
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error executing command: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetExecutionStatusTool(ExecutionTool):
    """Tool for getting the status of a command execution."""
    
    name = "get_execution_status"
    description = "Get the status of a command execution"
    
    schema = ToolSchema(
        properties={
            "execution_id": {
                "type": "string",
                "description": "ID of the execution"
            },
            "include_results": {
                "type": "boolean",
                "description": "Whether to include detailed results"
            }
        },
        required=["execution_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get execution status tool."""
        try:
            execution_id = params.get("execution_id")
            include_results = params.get("include_results", True)
            
            execution = ConfigExecutionRegistry.get_execution(execution_id)
            if not execution:
                return json.dumps({
                    "error": f"Execution not found: {execution_id}"
                })
            
            # Convert to dict
            result = execution.to_dict()
            
            # Remove results if not requested
            if not include_results:
                result.pop("results", None)
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting execution status: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class ListExecutionsTool(ExecutionTool):
    """Tool for listing command executions."""
    
    name = "list_executions"
    description = "List command executions"
    
    schema = ToolSchema(
        properties={
            "status": {
                "type": "string",
                "description": "Filter by status (e.g., pending, in_progress, completed, failed)"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of executions to return"
            }
        }
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the list executions tool."""
        try:
            status_filter = params.get("status", "").upper()
            limit = params.get("limit", 50)
            
            executions = ConfigExecutionRegistry.list_executions()
            
            # Apply status filter
            if status_filter:
                try:
                    status = ExecutionStatus[status_filter]
                    executions = [
                        execution for execution in executions
                        if execution.status == status
                    ]
                except KeyError:
                    return json.dumps({
                        "error": f"Invalid status: {status_filter}"
                    })
            
            # Sort by created_at (newest first)
            executions.sort(key=lambda x: x.created_at, reverse=True)
            
            # Apply limit
            executions = executions[:limit]
            
            # Format result
            result = {
                "executions": [
                    {
                        "id": execution.id,
                        "name": execution.name,
                        "command": execution.command,
                        "status": execution.status.value,
                        "targets_count": len(execution.targets),
                        "success_count": execution.success_count,
                        "failure_count": execution.failure_count,
                        "created_at": execution.created_at.isoformat()
                    }
                    for execution in executions
                ],
                "count": len(executions)
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing executions: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class ScheduleExecutionTool(ExecutionTool):
    """Tool for scheduling a command execution."""
    
    name = "schedule_execution"
    description = "Schedule a command execution"
    
    schema = ToolSchema(
        properties={
            "name": {
                "type": "string",
                "description": "Name for the execution"
            },
            "config_id": {
                "type": "string",
                "description": "ID of the configuration set to use"
            },
            "targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of target resource IDs"
            },
            "command": {
                "type": "string",
                "description": "Command to execute"
            },
            "parameters": {
                "type": "object",
                "description": "Parameters for the command"
            },
            "execute_at": {
                "type": "string",
                "description": "ISO-8601 timestamp for when to execute"
            },
            "repeat_seconds": {
                "type": "integer",
                "description": "Interval in seconds for repeating (0 for one-time)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds"
            },
            "max_concurrent": {
                "type": "integer",
                "description": "Maximum concurrent executions"
            }
        },
        required=["name", "config_id", "targets", "command"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the schedule execution tool."""
        try:
            name = params.get("name")
            config_id = params.get("config_id")
            targets = params.get("targets", [])
            command = params.get("command")
            parameters = params.get("parameters", {})
            execute_at_str = params.get("execute_at")
            repeat_seconds = params.get("repeat_seconds", 0)
            timeout_seconds = params.get("timeout_seconds", 300)
            max_concurrent = params.get("max_concurrent", 10)
            
            # Validate command
            if command not in ConfigCommandRegistry.list_commands():
                return json.dumps({
                    "error": f"Command not found: {command}"
                })
            
            # Validate config ID
            config_set = ConfigRegistry.get_config_set(config_id)
            if not config_set:
                return json.dumps({
                    "error": f"Configuration set not found: {config_id}"
                })
            
            # Parse execute_at
            execute_at = None
            if execute_at_str:
                try:
                    execute_at = datetime.fromisoformat(execute_at_str)
                except ValueError:
                    return json.dumps({
                        "error": f"Invalid timestamp format: {execute_at_str}. Use ISO-8601 format (YYYY-MM-DDTHH:MM:SS)."
                    })
            
            # Convert repeat_seconds to None if 0
            if repeat_seconds == 0:
                repeat_seconds = None
            
            # Schedule execution
            schedule_id = await ExecutionScheduler.schedule_execution(
                name=name,
                config_id=config_id,
                targets=targets,
                command=command,
                parameters=parameters,
                execute_at=execute_at,
                repeat_seconds=repeat_seconds,
                timeout_seconds=timeout_seconds,
                max_concurrent=max_concurrent
            )
            
            return json.dumps({
                "schedule_id": schedule_id,
                "name": name,
                "command": command,
                "targets_count": len(targets),
                "execute_at": execute_at_str,
                "repeat_seconds": repeat_seconds,
                "status": "scheduled"
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error scheduling execution: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class CancelScheduledExecutionTool(ExecutionTool):
    """Tool for canceling a scheduled execution."""
    
    name = "cancel_scheduled_execution"
    description = "Cancel a scheduled execution"
    
    schema = ToolSchema(
        properties={
            "schedule_id": {
                "type": "string",
                "description": "ID of the schedule to cancel"
            }
        },
        required=["schedule_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the cancel scheduled execution tool."""
        try:
            schedule_id = params.get("schedule_id")
            
            # Cancel schedule
            result = await ExecutionScheduler.cancel_schedule(schedule_id)
            
            if not result:
                return json.dumps({
                    "error": f"Schedule not found or already completed: {schedule_id}"
                })
            
            return json.dumps({
                "schedule_id": schedule_id,
                "cancelled": True
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error canceling scheduled execution: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


# List of execution tools to register with the server
execution_tools = [
    ListCommandsTool(),
    ExecuteCommandTool(),
    GetExecutionStatusTool(),
    ListExecutionsTool(),
    ScheduleExecutionTool(),
    CancelScheduledExecutionTool(),
] 