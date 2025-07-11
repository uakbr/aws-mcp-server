"""Celery application configuration for AWS MCP Server.

This module configures Celery for distributed task processing.
"""

import os
from datetime import timedelta
from typing import Any, Optional

from celery import Celery, Task
from celery.result import AsyncResult
from kombu import Exchange, Queue

# Get configuration from environment
REDIS_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1")
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")

# Create Celery app
app = Celery("aws_mcp_server")

# Configure Celery
app.conf.update(
    # Broker settings
    broker_url=REDIS_URL,
    result_backend=RESULT_BACKEND,
    
    # Task settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    
    # Result backend settings
    result_expires=3600,  # 1 hour
    result_persistent=True,
    result_compression="gzip",
    
    # Task execution settings
    task_track_started=True,
    task_time_limit=3600,  # 1 hour hard limit
    task_soft_time_limit=3000,  # 50 minutes soft limit
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    
    # Retry settings
    task_autoretry_for=(Exception,),
    task_retry_kwargs={"max_retries": 3, "countdown": 5},
    task_retry_backoff=True,
    task_retry_backoff_max=600,  # 10 minutes
    task_retry_jitter=True,
    
    # Queue configuration
    task_default_queue="default",
    task_default_exchange="default",
    task_default_routing_key="default",
    
    task_queues=(
        Queue("default", Exchange("default"), routing_key="default"),
        Queue("high_priority", Exchange("high_priority"), routing_key="high_priority"),
        Queue("low_priority", Exchange("low_priority"), routing_key="low_priority"),
        Queue("security", Exchange("security"), routing_key="security"),
        Queue("compliance", Exchange("compliance"), routing_key="compliance"),
        Queue("discovery", Exchange("discovery"), routing_key="discovery"),
    ),
    
    # Route specific tasks to queues
    task_routes={
        "aws_mcp_server.queue.tasks.security_*": {"queue": "security"},
        "aws_mcp_server.queue.tasks.compliance_*": {"queue": "compliance"},
        "aws_mcp_server.queue.tasks.resource_discovery_*": {"queue": "discovery"},
    },
    
    # Beat schedule for periodic tasks
    beat_schedule={
        "cleanup-old-results": {
            "task": "aws_mcp_server.queue.tasks.cleanup_old_results",
            "schedule": timedelta(hours=1),
        },
        "health-check": {
            "task": "aws_mcp_server.queue.tasks.health_check",
            "schedule": timedelta(minutes=5),
        },
    },
    
    # Worker settings
    worker_max_tasks_per_child=100,
    worker_disable_rate_limits=False,
    worker_concurrency=4,
    
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
)


class CallbackTask(Task):
    """Task with callback support."""
    
    def on_success(self, retval, task_id, args, kwargs):
        """Called on successful task completion."""
        callback_url = kwargs.get("callback_url")
        if callback_url:
            # Send success callback
            import requests
            try:
                requests.post(callback_url, json={
                    "task_id": task_id,
                    "status": "success",
                    "result": retval,
                })
            except Exception as e:
                app.logger.error(f"Failed to send success callback: {e}")
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called on task failure."""
        callback_url = kwargs.get("callback_url")
        if callback_url:
            # Send failure callback
            import requests
            try:
                requests.post(callback_url, json={
                    "task_id": task_id,
                    "status": "failure",
                    "error": str(exc),
                    "traceback": str(einfo),
                })
            except Exception as e:
                app.logger.error(f"Failed to send failure callback: {e}")


# Set default task base
app.Task = CallbackTask


def get_task_info(task_id: str) -> dict[str, Any]:
    """Get information about a task.
    
    Args:
        task_id: Task ID
        
    Returns:
        Task information dictionary
    """
    result = AsyncResult(task_id, app=app)
    
    info = {
        "task_id": task_id,
        "state": result.state,
        "ready": result.ready(),
        "successful": result.successful() if result.ready() else None,
        "failed": result.failed() if result.ready() else None,
    }
    
    if result.ready():
        if result.successful():
            info["result"] = result.result
        else:
            info["error"] = str(result.info)
            info["traceback"] = result.traceback
    else:
        # Task is pending or running
        info["info"] = result.info
    
    return info


def revoke_task(task_id: str, terminate: bool = False) -> bool:
    """Revoke a task.
    
    Args:
        task_id: Task ID
        terminate: Whether to terminate running task
        
    Returns:
        True if revoked successfully
    """
    try:
        app.control.revoke(task_id, terminate=terminate)
        return True
    except Exception as e:
        app.logger.error(f"Failed to revoke task {task_id}: {e}")
        return False


# Import tasks to register them
from . import tasks  # noqa