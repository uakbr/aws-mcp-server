"""
Enhanced progress reporting for AWS MCP Server operations.

This module provides advanced progress tracking capabilities for long-running
AWS operations, multi-region deployments, and resource discovery tasks.
"""

import asyncio
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class OperationType(Enum):
    """Types of operations that support progress tracking."""
    RESOURCE_DISCOVERY = "resource_discovery"
    DEPLOYMENT = "deployment"
    MULTI_REGION = "multi_region"
    BATCH_OPERATION = "batch_operation"
    MIGRATION = "migration"
    BACKUP = "backup"
    ANALYSIS = "analysis"


@dataclass
class ProgressStep:
    """Represents a single step in a progress-tracked operation."""
    name: str
    description: str
    weight: float = 1.0
    status: str = "pending"
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProgressTracker:
    """Tracks progress for complex AWS operations."""
    operation_id: str
    operation_type: OperationType
    total_steps: int
    current_step: int = 0
    steps: List[ProgressStep] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_step(self, name: str, description: str, weight: float = 1.0) -> None:
        """Add a step to the progress tracker."""
        step = ProgressStep(name=name, description=description, weight=weight)
        self.steps.append(step)
        self.total_steps = len(self.steps)
    
    def start_step(self, step_index: int) -> None:
        """Mark a step as started."""
        if 0 <= step_index < len(self.steps):
            self.steps[step_index].status = "in_progress"
            self.steps[step_index].start_time = datetime.utcnow()
            self.current_step = step_index
    
    def complete_step(self, step_index: int, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Mark a step as completed."""
        if 0 <= step_index < len(self.steps):
            self.steps[step_index].status = "completed"
            self.steps[step_index].end_time = datetime.utcnow()
            if metadata:
                self.steps[step_index].metadata.update(metadata)
    
    def fail_step(self, step_index: int, error: str) -> None:
        """Mark a step as failed."""
        if 0 <= step_index < len(self.steps):
            self.steps[step_index].status = "failed"
            self.steps[step_index].end_time = datetime.utcnow()
            self.steps[step_index].error = error
    
    def get_progress_percentage(self) -> float:
        """Calculate overall progress percentage based on weighted steps."""
        if not self.steps:
            return 0.0
        
        total_weight = sum(step.weight for step in self.steps)
        completed_weight = sum(
            step.weight for step in self.steps 
            if step.status == "completed"
        )
        
        return (completed_weight / total_weight) * 100
    
    def get_current_status(self) -> Dict[str, Any]:
        """Get current progress status."""
        return {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type.value,
            "progress_percentage": self.get_progress_percentage(),
            "current_step": self.current_step,
            "total_steps": self.total_steps,
            "current_step_name": self.steps[self.current_step].name if self.current_step < len(self.steps) else None,
            "elapsed_time": (datetime.utcnow() - self.start_time).total_seconds(),
            "status": self._get_overall_status(),
            "steps_detail": [
                {
                    "name": step.name,
                    "status": step.status,
                    "duration": (step.end_time - step.start_time).total_seconds() if step.end_time and step.start_time else None
                }
                for step in self.steps
            ]
        }
    
    def _get_overall_status(self) -> str:
        """Determine overall operation status."""
        if any(step.status == "failed" for step in self.steps):
            return "failed"
        elif all(step.status == "completed" for step in self.steps):
            return "completed"
        elif any(step.status == "in_progress" for step in self.steps):
            return "in_progress"
        else:
            return "pending"


class ProgressReporter:
    """Reports progress updates to MCP context."""
    
    def __init__(self, ctx):
        self.ctx = ctx
        self.trackers: Dict[str, ProgressTracker] = {}
    
    async def start_operation(
        self,
        operation_id: str,
        operation_type: OperationType,
        steps: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None
    ) -> ProgressTracker:
        """Start tracking a new operation."""
        tracker = ProgressTracker(
            operation_id=operation_id,
            operation_type=operation_type,
            total_steps=len(steps),
            metadata=metadata or {}
        )
        
        for step in steps:
            tracker.add_step(
                name=step["name"],
                description=step["description"],
                weight=step.get("weight", 1.0)
            )
        
        self.trackers[operation_id] = tracker
        
        await self.ctx.info(
            f"Starting {operation_type.value} operation: {operation_id} with {len(steps)} steps"
        )
        
        return tracker
    
    async def update_progress(
        self,
        operation_id: str,
        step_index: int,
        status: str,
        metadata: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ) -> None:
        """Update progress for a specific step."""
        if operation_id not in self.trackers:
            return
        
        tracker = self.trackers[operation_id]
        
        if status == "started":
            tracker.start_step(step_index)
            await self._report_progress(tracker, f"Starting: {tracker.steps[step_index].name}")
        elif status == "completed":
            tracker.complete_step(step_index, metadata)
            await self._report_progress(tracker, f"Completed: {tracker.steps[step_index].name}")
        elif status == "failed":
            tracker.fail_step(step_index, error or "Unknown error")
            await self.ctx.error(f"Failed: {tracker.steps[step_index].name} - {error}")
    
    async def _report_progress(self, tracker: ProgressTracker, message: str) -> None:
        """Report progress to MCP context."""
        status = tracker.get_current_status()
        progress_bar = self._create_progress_bar(status["progress_percentage"])
        
        await self.ctx.info(
            f"{message} | {progress_bar} {status['progress_percentage']:.1f}% | "
            f"Step {status['current_step'] + 1}/{status['total_steps']}"
        )
    
    def _create_progress_bar(self, percentage: float, width: int = 20) -> str:
        """Create a text-based progress bar."""
        filled = int((percentage / 100) * width)
        bar = "█" * filled + "░" * (width - filled)
        return f"[{bar}]"
    
    async def complete_operation(self, operation_id: str) -> Dict[str, Any]:
        """Mark an operation as complete and return summary."""
        if operation_id not in self.trackers:
            return {"error": "Operation not found"}
        
        tracker = self.trackers[operation_id]
        tracker.end_time = datetime.utcnow()
        
        summary = {
            "operation_id": operation_id,
            "operation_type": tracker.operation_type.value,
            "status": tracker._get_overall_status(),
            "total_duration": (tracker.end_time - tracker.start_time).total_seconds(),
            "steps_completed": sum(1 for step in tracker.steps if step.status == "completed"),
            "steps_failed": sum(1 for step in tracker.steps if step.status == "failed"),
            "final_progress": tracker.get_progress_percentage()
        }
        
        await self.ctx.info(
            f"Operation {operation_id} completed: {summary['status']} | "
            f"Duration: {summary['total_duration']:.2f}s | "
            f"Progress: {summary['final_progress']:.1f}%"
        )
        
        return summary


# Progress tracking decorators for common AWS operations
def track_multi_region_operation(operation_type: OperationType):
    """Decorator to track multi-region AWS operations."""
    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            ctx = kwargs.get('ctx')
            regions = kwargs.get('regions', ['us-east-1'])
            operation_id = f"{operation_type.value}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            
            if ctx:
                reporter = ProgressReporter(ctx)
                steps = [
                    {"name": f"Process {region}", "description": f"Processing resources in {region}"}
                    for region in regions
                ]
                
                tracker = await reporter.start_operation(
                    operation_id=operation_id,
                    operation_type=operation_type,
                    steps=steps
                )
                
                kwargs['progress_reporter'] = reporter
                kwargs['operation_id'] = operation_id
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def track_batch_operation(operation_type: OperationType, batch_size: int = 10):
    """Decorator to track batch AWS operations."""
    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            ctx = kwargs.get('ctx')
            items = kwargs.get('items', [])
            operation_id = f"{operation_type.value}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            
            if ctx and items:
                reporter = ProgressReporter(ctx)
                batches = [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
                steps = [
                    {"name": f"Batch {i+1}", "description": f"Processing items {i*batch_size+1}-{min((i+1)*batch_size, len(items))}"}
                    for i in range(len(batches))
                ]
                
                tracker = await reporter.start_operation(
                    operation_id=operation_id,
                    operation_type=operation_type,
                    steps=steps
                )
                
                kwargs['progress_reporter'] = reporter
                kwargs['operation_id'] = operation_id
                kwargs['batches'] = batches
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Example usage functions
async def discover_resources_with_progress(
    regions: List[str],
    resource_types: List[str],
    ctx,
    progress_callback: Optional[Callable] = None
) -> Dict[str, Any]:
    """Discover AWS resources across regions with progress tracking."""
    operation_id = f"discovery_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    reporter = ProgressReporter(ctx)
    
    # Create steps for each region/resource combination
    steps = []
    for region in regions:
        for resource_type in resource_types:
            steps.append({
                "name": f"{resource_type} in {region}",
                "description": f"Discovering {resource_type} resources in {region}",
                "weight": 1.0
            })
    
    tracker = await reporter.start_operation(
        operation_id=operation_id,
        operation_type=OperationType.RESOURCE_DISCOVERY,
        steps=steps
    )
    
    results = {}
    step_index = 0
    
    for region in regions:
        results[region] = {}
        for resource_type in resource_types:
            await reporter.update_progress(operation_id, step_index, "started")
            
            try:
                # Simulate resource discovery (replace with actual AWS API calls)
                await asyncio.sleep(0.5)  # Simulate API call
                
                # Mock results
                results[region][resource_type] = {
                    "count": 10,
                    "resources": [f"{resource_type}-{i}" for i in range(10)]
                }
                
                await reporter.update_progress(
                    operation_id, 
                    step_index, 
                    "completed",
                    metadata={"count": 10}
                )
                
                if progress_callback:
                    await progress_callback(tracker.get_current_status())
                    
            except Exception as e:
                await reporter.update_progress(
                    operation_id,
                    step_index,
                    "failed",
                    error=str(e)
                )
            
            step_index += 1
    
    summary = await reporter.complete_operation(operation_id)
    
    return {
        "operation_summary": summary,
        "results": results
    }