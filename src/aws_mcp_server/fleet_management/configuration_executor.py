"""
Configuration Execution Engine for AWS Fleet Management.

This module provides capabilities to execute configuration changes
across AWS resources in parallel with error handling and result aggregation.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable, Union, Set, Tuple

from .configuration import ConfigManager, ConfigRegistry, ConfigType

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """Status of a configuration execution."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass
class ExecutionResult:
    """Result of a configuration execution on a single target."""
    target_id: str
    status: ExecutionStatus
    output: Any = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    @property
    def duration(self) -> Optional[float]:
        """Calculate the duration of the execution in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "target_id": self.target_id,
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration
        }


@dataclass
class ConfigExecution:
    """A configuration execution across multiple targets."""
    id: str
    name: str
    config_id: str
    targets: List[str]
    command: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 300
    max_concurrent: int = 10
    status: ExecutionStatus = ExecutionStatus.PENDING
    results: Dict[str, ExecutionResult] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    @property
    def duration(self) -> Optional[float]:
        """Calculate the duration of the execution in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    @property
    def success_count(self) -> int:
        """Count of successful executions."""
        return sum(1 for result in self.results.values() 
                  if result.status == ExecutionStatus.COMPLETED)
    
    @property
    def failure_count(self) -> int:
        """Count of failed executions."""
        return sum(1 for result in self.results.values() 
                  if result.status in [ExecutionStatus.FAILED, ExecutionStatus.TIMED_OUT])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "config_id": self.config_id,
            "command": self.command,
            "parameters": self.parameters,
            "targets_count": len(self.targets),
            "timeout_seconds": self.timeout_seconds,
            "max_concurrent": self.max_concurrent,
            "status": self.status.value,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "results": {
                target_id: result.to_dict() 
                for target_id, result in self.results.items()
            },
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration
        }


class ConfigCommandRegistry:
    """Registry for configuration commands."""
    
    _commands: Dict[str, Callable] = {}
    
    @classmethod
    def register_command(cls, name: str, func: Callable) -> None:
        """Register a configuration command."""
        cls._commands[name] = func
    
    @classmethod
    def get_command(cls, name: str) -> Optional[Callable]:
        """Get a configuration command."""
        return cls._commands.get(name)
    
    @classmethod
    def list_commands(cls) -> List[str]:
        """List all registered commands."""
        return list(cls._commands.keys())


class ConfigExecutionRegistry:
    """Registry for configuration executions."""
    
    _executions: Dict[str, ConfigExecution] = {}
    
    @classmethod
    def register_execution(cls, execution: ConfigExecution) -> None:
        """Register a configuration execution."""
        cls._executions[execution.id] = execution
    
    @classmethod
    def get_execution(cls, execution_id: str) -> Optional[ConfigExecution]:
        """Get a configuration execution."""
        return cls._executions.get(execution_id)
    
    @classmethod
    def list_executions(cls) -> List[ConfigExecution]:
        """List all registered executions."""
        return list(cls._executions.values())


class ExecutionEngine:
    """Engine for executing configuration commands across targets."""
    
    @classmethod
    async def execute_command(
        cls, name: str, config_id: str, targets: List[str],
        command: str, parameters: Dict[str, Any] = None,
        timeout_seconds: int = 300, max_concurrent: int = 10
    ) -> str:
        """
        Execute a command across targets.
        
        Args:
            name: Name of the execution
            config_id: ID of the configuration set to use
            targets: List of target resource IDs
            command: Command to execute
            parameters: Parameters for the command
            timeout_seconds: Timeout in seconds
            max_concurrent: Maximum concurrent executions
            
        Returns:
            Execution ID
        """
        # Create execution ID
        execution_id = f"exec-{uuid.uuid4()}"
        
        # Create execution
        execution = ConfigExecution(
            id=execution_id,
            name=name,
            config_id=config_id,
            targets=targets,
            command=command,
            parameters=parameters or {},
            timeout_seconds=timeout_seconds,
            max_concurrent=max_concurrent
        )
        
        # Register execution
        ConfigExecutionRegistry.register_execution(execution)
        
        # Start execution asynchronously
        asyncio.create_task(cls._run_execution(execution_id))
        
        return execution_id
    
    @classmethod
    async def _run_execution(cls, execution_id: str) -> None:
        """
        Run a configuration execution.
        
        Args:
            execution_id: ID of the execution to run
        """
        execution = ConfigExecutionRegistry.get_execution(execution_id)
        if not execution:
            logger.error(f"Execution not found: {execution_id}")
            return
        
        # Set execution status
        execution.status = ExecutionStatus.IN_PROGRESS
        execution.started_at = datetime.now()
        
        try:
            # Get command function
            command_func = ConfigCommandRegistry.get_command(execution.command)
            if not command_func:
                raise ValueError(f"Command not found: {execution.command}")
            
            # Get configuration
            config_set = ConfigRegistry.get_config_set(execution.config_id)
            if not config_set:
                raise ValueError(f"Configuration set not found: {execution.config_id}")
            
            # Process targets in batches
            for i in range(0, len(execution.targets), execution.max_concurrent):
                batch = execution.targets[i:i + execution.max_concurrent]
                
                # Create tasks for each target
                tasks = []
                for target_id in batch:
                    # Create result
                    result = ExecutionResult(
                        target_id=target_id,
                        status=ExecutionStatus.PENDING
                    )
                    execution.results[target_id] = result
                    
                    # Create task
                    task = cls._execute_on_target(
                        execution_id=execution_id,
                        target_id=target_id,
                        command_func=command_func,
                        config_set=config_set,
                        parameters=execution.parameters,
                        timeout_seconds=execution.timeout_seconds
                    )
                    tasks.append(task)
                
                # Run tasks and wait for all to complete
                await asyncio.gather(*tasks)
            
            # Check if all targets were processed
            if all(result.status != ExecutionStatus.PENDING 
                  for result in execution.results.values()):
                execution.status = ExecutionStatus.COMPLETED
            else:
                execution.status = ExecutionStatus.FAILED
        
        except Exception as e:
            logger.error(f"Error running execution {execution_id}: {e}", exc_info=True)
            execution.status = ExecutionStatus.FAILED
            
            # Set result for any pending targets
            for target_id in execution.targets:
                if target_id not in execution.results or \
                   execution.results[target_id].status == ExecutionStatus.PENDING:
                    execution.results[target_id] = ExecutionResult(
                        target_id=target_id,
                        status=ExecutionStatus.FAILED,
                        error=str(e)
                    )
        
        finally:
            execution.completed_at = datetime.now()
    
    @classmethod
    async def _execute_on_target(
        cls, execution_id: str, target_id: str, command_func: Callable,
        config_set: Any, parameters: Dict[str, Any], timeout_seconds: int
    ) -> None:
        """
        Execute a command on a single target.
        
        Args:
            execution_id: ID of the execution
            target_id: ID of the target
            command_func: Command function to execute
            config_set: Configuration set to use
            parameters: Parameters for the command
            timeout_seconds: Timeout in seconds
        """
        execution = ConfigExecutionRegistry.get_execution(execution_id)
        if not execution:
            logger.error(f"Execution not found: {execution_id}")
            return
        
        result = execution.results.get(target_id)
        if not result:
            logger.error(f"Result not found for target {target_id} in execution {execution_id}")
            return
        
        # Set result status
        result.status = ExecutionStatus.IN_PROGRESS
        result.start_time = datetime.now()
        
        try:
            # Create timeout
            timeout = timeout_seconds if timeout_seconds > 0 else None
            
            # Execute command with timeout
            output = await asyncio.wait_for(
                command_func(target_id, config_set, parameters),
                timeout=timeout
            )
            
            # Set result
            result.status = ExecutionStatus.COMPLETED
            result.output = output
        
        except asyncio.TimeoutError:
            # Handle timeout
            result.status = ExecutionStatus.TIMED_OUT
            result.error = f"Command timed out after {timeout_seconds} seconds"
        
        except Exception as e:
            # Handle error
            logger.error(f"Error executing command on target {target_id}: {e}", exc_info=True)
            result.status = ExecutionStatus.FAILED
            result.error = str(e)
        
        finally:
            result.end_time = datetime.now()


# Register built-in commands

async def set_tag_command(target_id: str, config_set: Any, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Set tags on a resource.
    
    Args:
        target_id: ID of the target resource
        config_set: Configuration set to use
        parameters: Command parameters (key and value)
        
    Returns:
        Result of the operation
    """
    key = parameters.get("key")
    value = parameters.get("value")
    
    if not key:
        raise ValueError("Missing required parameter: key")
    
    # This would use boto3 to actually set the tag
    # For now, we'll just simulate success
    return {
        "resource_id": target_id,
        "tag_key": key,
        "tag_value": value,
        "applied": True
    }

ConfigCommandRegistry.register_command("set_tag", set_tag_command)


async def restart_instance_command(target_id: str, config_set: Any, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Restart an EC2 instance.
    
    Args:
        target_id: ID of the target instance
        config_set: Configuration set to use
        parameters: Command parameters
        
    Returns:
        Result of the operation
    """
    # This would use boto3 to actually restart the instance
    # For now, we'll just simulate success with a delay
    await asyncio.sleep(2)
    
    return {
        "instance_id": target_id,
        "action": "restart",
        "completed": True
    }

ConfigCommandRegistry.register_command("restart_instance", restart_instance_command)


async def update_config_command(target_id: str, config_set: Any, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update configuration on a resource.
    
    Args:
        target_id: ID of the target resource
        config_set: Configuration set to use
        parameters: Configuration parameters to update
        
    Returns:
        Result of the operation
    """
    settings = parameters.get("settings", {})
    
    if not settings:
        raise ValueError("Missing required parameter: settings")
    
    # This would use appropriate AWS APIs to update configuration
    # For now, we'll just simulate success
    return {
        "resource_id": target_id,
        "updated_settings": list(settings.keys()),
        "applied": True
    }

ConfigCommandRegistry.register_command("update_config", update_config_command)


class ExecutionScheduler:
    """Scheduler for configuration executions."""
    
    _scheduled_tasks: Dict[str, asyncio.Task] = {}
    
    @classmethod
    async def schedule_execution(
        cls, name: str, config_id: str, targets: List[str],
        command: str, parameters: Dict[str, Any] = None,
        execute_at: datetime = None, repeat_seconds: int = None,
        timeout_seconds: int = 300, max_concurrent: int = 10
    ) -> str:
        """
        Schedule a configuration execution.
        
        Args:
            name: Name of the execution
            config_id: ID of the configuration set to use
            targets: List of target resource IDs
            command: Command to execute
            parameters: Parameters for the command
            execute_at: Time to execute (None for immediate)
            repeat_seconds: Interval in seconds for repeating (None for one-time)
            timeout_seconds: Timeout in seconds
            max_concurrent: Maximum concurrent executions
            
        Returns:
            Schedule ID
        """
        schedule_id = f"sched-{uuid.uuid4()}"
        
        # Create and start the scheduling task
        task = asyncio.create_task(
            cls._run_scheduled_execution(
                schedule_id=schedule_id,
                name=name,
                config_id=config_id,
                targets=targets,
                command=command,
                parameters=parameters or {},
                execute_at=execute_at,
                repeat_seconds=repeat_seconds,
                timeout_seconds=timeout_seconds,
                max_concurrent=max_concurrent
            )
        )
        
        # Store the task
        cls._scheduled_tasks[schedule_id] = task
        
        return schedule_id
    
    @classmethod
    async def cancel_schedule(cls, schedule_id: str) -> bool:
        """
        Cancel a scheduled execution.
        
        Args:
            schedule_id: ID of the schedule to cancel
            
        Returns:
            True if canceled, False if not found
        """
        if schedule_id in cls._scheduled_tasks:
            task = cls._scheduled_tasks[schedule_id]
            task.cancel()
            del cls._scheduled_tasks[schedule_id]
            return True
        return False
    
    @classmethod
    async def _run_scheduled_execution(
        cls, schedule_id: str, name: str, config_id: str, targets: List[str],
        command: str, parameters: Dict[str, Any], execute_at: datetime = None,
        repeat_seconds: int = None, timeout_seconds: int = 300, max_concurrent: int = 10
    ) -> None:
        """
        Run a scheduled execution.
        
        Args:
            schedule_id: ID of the schedule
            name: Name of the execution
            config_id: ID of the configuration set to use
            targets: List of target resource IDs
            command: Command to execute
            parameters: Parameters for the command
            execute_at: Time to execute (None for immediate)
            repeat_seconds: Interval in seconds for repeating (None for one-time)
            timeout_seconds: Timeout in seconds
            max_concurrent: Maximum concurrent executions
        """
        try:
            # Wait until execute_at if specified
            if execute_at and execute_at > datetime.now():
                wait_seconds = (execute_at - datetime.now()).total_seconds()
                if wait_seconds > 0:
                    await asyncio.sleep(wait_seconds)
            
            # Execute in a loop if repeat_seconds is specified
            while True:
                # Create an execution name with timestamp for recurring executions
                execution_name = name
                if repeat_seconds:
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    execution_name = f"{name} ({timestamp})"
                
                # Execute the command
                await ExecutionEngine.execute_command(
                    name=execution_name,
                    config_id=config_id,
                    targets=targets,
                    command=command,
                    parameters=parameters,
                    timeout_seconds=timeout_seconds,
                    max_concurrent=max_concurrent
                )
                
                # Break if not repeating
                if not repeat_seconds:
                    break
                
                # Wait for the next execution
                await asyncio.sleep(repeat_seconds)
        
        except asyncio.CancelledError:
            # Handle cancellation
            logger.info(f"Scheduled execution {schedule_id} cancelled")
        
        except Exception as e:
            # Log any errors
            logger.error(f"Error in scheduled execution {schedule_id}: {e}", exc_info=True)
        
        finally:
            # Clean up
            if schedule_id in cls._scheduled_tasks:
                del cls._scheduled_tasks[schedule_id] 