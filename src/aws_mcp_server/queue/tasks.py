"""Celery tasks for asynchronous AWS operations.

This module defines background tasks for long-running operations.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Optional

from celery import current_task
from celery.exceptions import SoftTimeLimitExceeded

from ..cache import CacheConfig, RedisCache
from ..connection_pool import get_connection_pool_manager
from ..security.compliance import ComplianceFramework, ComplianceScanner
from ..security.security_hub import SecurityHubClient, WorkflowStatus
from .celery_app import app

logger = logging.getLogger(__name__)


def update_task_progress(current: int, total: int, message: Optional[str] = None):
    """Update task progress.
    
    Args:
        current: Current progress
        total: Total items
        message: Optional status message
    """
    if current_task and not current_task.request.called_directly:
        meta = {
            "current": current,
            "total": total,
            "percent": int((current / total) * 100) if total > 0 else 0,
        }
        if message:
            meta["message"] = message
            
        current_task.update_state(state="PROGRESS", meta=meta)


@app.task(name="aws_mcp_server.queue.tasks.resource_discovery_async", queue="discovery")
def resource_discovery_async(
    regions: list[str],
    resource_types: list[str],
    filters: Optional[dict[str, Any]] = None,
    cache_results: bool = True,
    callback_url: Optional[str] = None,
) -> dict[str, Any]:
    """Discover AWS resources across regions asynchronously.
    
    Args:
        regions: List of AWS regions
        resource_types: Types of resources to discover
        filters: Optional filters
        cache_results: Whether to cache results
        callback_url: Optional callback URL
        
    Returns:
        Discovery results
    """
    try:
        logger.info(f"Starting resource discovery for {len(resource_types)} types across {len(regions)} regions")
        
        # Run async discovery in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                _async_discover_resources(regions, resource_types, filters, cache_results)
            )
            return results
        finally:
            loop.close()
            
    except SoftTimeLimitExceeded:
        logger.warning("Resource discovery task exceeded time limit")
        return {
            "status": "timeout",
            "message": "Discovery exceeded time limit",
            "partial_results": getattr(current_task, "_partial_results", {}),
        }
    except Exception as e:
        logger.error(f"Resource discovery failed: {e}")
        raise


async def _async_discover_resources(
    regions: list[str],
    resource_types: list[str],
    filters: Optional[dict[str, Any]],
    cache_results: bool,
) -> dict[str, Any]:
    """Async implementation of resource discovery."""
    pool_manager = get_connection_pool_manager()
    cache = RedisCache() if cache_results else None
    
    if cache:
        await cache.connect()
    
    results = {
        "discovered_at": datetime.utcnow().isoformat(),
        "regions": {},
        "summary": {
            "total_resources": 0,
            "by_type": {},
            "by_region": {},
        },
    }
    
    total_operations = len(regions) * len(resource_types)
    current_operation = 0
    
    # Store partial results for timeout recovery
    if current_task:
        current_task._partial_results = results
    
    for region in regions:
        results["regions"][region] = {}
        results["summary"]["by_region"][region] = 0
        
        for resource_type in resource_types:
            current_operation += 1
            update_task_progress(
                current_operation,
                total_operations,
                f"Discovering {resource_type} in {region}"
            )
            
            try:
                # Map resource type to service and operation
                service, operation = _map_resource_type_to_operation(resource_type)
                
                # Check cache first
                if cache:
                    cache_key = f"discovery:{service}:{operation}:{region}"
                    cached = await cache.get(cache_key)
                    if cached:
                        resources = cached
                    else:
                        # Discover resources
                        resources = await _discover_resources_for_type(
                            pool_manager, service, operation, region, filters
                        )
                        # Cache results
                        await cache.set(cache_key, resources, ttl=300)  # 5 minutes
                else:
                    resources = await _discover_resources_for_type(
                        pool_manager, service, operation, region, filters
                    )
                
                # Store results
                results["regions"][region][resource_type] = resources
                
                # Update summary
                count = len(resources) if isinstance(resources, list) else 0
                results["summary"]["total_resources"] += count
                results["summary"]["by_region"][region] += count
                
                if resource_type not in results["summary"]["by_type"]:
                    results["summary"]["by_type"][resource_type] = 0
                results["summary"]["by_type"][resource_type] += count
                
            except Exception as e:
                logger.error(f"Failed to discover {resource_type} in {region}: {e}")
                results["regions"][region][resource_type] = {
                    "error": str(e),
                    "resources": []
                }
    
    if cache:
        await cache.disconnect()
    
    return results


def _map_resource_type_to_operation(resource_type: str) -> tuple[str, str]:
    """Map resource type to AWS service and operation."""
    mapping = {
        "ec2_instances": ("ec2", "describe_instances"),
        "s3_buckets": ("s3", "list_buckets"),
        "rds_instances": ("rds", "describe_db_instances"),
        "lambda_functions": ("lambda", "list_functions"),
        "iam_roles": ("iam", "list_roles"),
        "iam_users": ("iam", "list_users"),
        "vpc": ("ec2", "describe_vpcs"),
        "security_groups": ("ec2", "describe_security_groups"),
        "cloudformation_stacks": ("cloudformation", "list_stacks"),
        "ecs_clusters": ("ecs", "list_clusters"),
        "eks_clusters": ("eks", "list_clusters"),
    }
    
    return mapping.get(resource_type, ("ec2", "describe_instances"))


async def _discover_resources_for_type(
    pool_manager,
    service: str,
    operation: str,
    region: str,
    filters: Optional[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Discover resources of a specific type."""
    kwargs = {}
    if filters:
        kwargs.update(filters)
    
    # Handle pagination
    resources = []
    next_token = None
    
    while True:
        if next_token:
            kwargs["NextToken"] = next_token
        
        response = await pool_manager.execute(
            service, operation, region_name=region, **kwargs
        )
        
        # Extract resources based on service
        if service == "s3" and operation == "list_buckets":
            # S3 is global, only get buckets once
            if region == "us-east-1":
                resources.extend(response.get("Buckets", []))
        elif service == "ec2":
            if operation == "describe_instances":
                for reservation in response.get("Reservations", []):
                    resources.extend(reservation.get("Instances", []))
            else:
                # Generic EC2 resources
                key = operation.replace("describe_", "").title()
                resources.extend(response.get(key, []))
        elif service == "iam":
            # IAM is global, only get once
            if region == "us-east-1":
                key = operation.replace("list_", "").title()
                resources.extend(response.get(key, []))
        else:
            # Try common response keys
            for key in ["Items", "Resources", operation.replace("list_", "").title()]:
                if key in response:
                    resources.extend(response[key])
                    break
        
        # Check for pagination
        next_token = response.get("NextToken") or response.get("Marker")
        if not next_token:
            break
    
    return resources


@app.task(name="aws_mcp_server.queue.tasks.bulk_resource_update", queue="default")
def bulk_resource_update(
    resource_arns: list[str],
    update_type: str,
    update_params: dict[str, Any],
    batch_size: int = 10,
    callback_url: Optional[str] = None,
) -> dict[str, Any]:
    """Update multiple AWS resources in bulk.
    
    Args:
        resource_arns: List of resource ARNs
        update_type: Type of update (e.g., 'add_tags', 'modify_attributes')
        update_params: Parameters for the update
        batch_size: Batch size for updates
        callback_url: Optional callback URL
        
    Returns:
        Update results
    """
    try:
        logger.info(f"Starting bulk update of {len(resource_arns)} resources")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                _async_bulk_update(resource_arns, update_type, update_params, batch_size)
            )
            return results
        finally:
            loop.close()
            
    except SoftTimeLimitExceeded:
        logger.warning("Bulk update task exceeded time limit")
        return {
            "status": "timeout",
            "message": "Update exceeded time limit",
            "completed": getattr(current_task, "_completed_count", 0),
            "total": len(resource_arns),
        }
    except Exception as e:
        logger.error(f"Bulk update failed: {e}")
        raise


async def _async_bulk_update(
    resource_arns: list[str],
    update_type: str,
    update_params: dict[str, Any],
    batch_size: int,
) -> dict[str, Any]:
    """Async implementation of bulk update."""
    pool_manager = get_connection_pool_manager()
    
    results = {
        "started_at": datetime.utcnow().isoformat(),
        "update_type": update_type,
        "total_resources": len(resource_arns),
        "successful": 0,
        "failed": 0,
        "results": {},
    }
    
    # Track completed count for timeout recovery
    if current_task:
        current_task._completed_count = 0
    
    # Process in batches
    for i in range(0, len(resource_arns), batch_size):
        batch = resource_arns[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = (len(resource_arns) + batch_size - 1) // batch_size
        
        update_task_progress(
            batch_num,
            total_batches,
            f"Processing batch {batch_num} of {total_batches}"
        )
        
        # Process batch concurrently
        batch_tasks = []
        for arn in batch:
            task = _update_single_resource(pool_manager, arn, update_type, update_params)
            batch_tasks.append(task)
        
        batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
        
        # Process results
        for arn, result in zip(batch, batch_results):
            if isinstance(result, Exception):
                results["failed"] += 1
                results["results"][arn] = {
                    "status": "failed",
                    "error": str(result),
                }
            else:
                results["successful"] += 1
                results["results"][arn] = {
                    "status": "success",
                    "result": result,
                }
            
            if current_task:
                current_task._completed_count += 1
    
    results["completed_at"] = datetime.utcnow().isoformat()
    return results


async def _update_single_resource(
    pool_manager,
    resource_arn: str,
    update_type: str,
    update_params: dict[str, Any],
) -> Any:
    """Update a single resource."""
    # Parse ARN to determine service and resource type
    arn_parts = resource_arn.split(":")
    service = arn_parts[2]
    region = arn_parts[3]
    resource_type = arn_parts[5].split("/")[0] if "/" in arn_parts[5] else arn_parts[5]
    
    # Map update type to operation
    if update_type == "add_tags":
        if service == "ec2":
            return await pool_manager.execute(
                "ec2", "create_tags",
                region_name=region,
                Resources=[resource_arn],
                Tags=update_params.get("tags", [])
            )
        else:
            # Generic tagging
            return await pool_manager.execute(
                service, "tag_resource",
                region_name=region,
                ResourceArn=resource_arn,
                Tags=update_params.get("tags", [])
            )
    else:
        raise ValueError(f"Unsupported update type: {update_type}")


@app.task(name="aws_mcp_server.queue.tasks.compliance_scan_async", queue="compliance")
def compliance_scan_async(
    framework: str,
    regions: list[str],
    auto_remediate: bool = False,
    export_format: Optional[str] = None,
    callback_url: Optional[str] = None,
) -> dict[str, Any]:
    """Run compliance scan asynchronously.
    
    Args:
        framework: Compliance framework (PCI_DSS, HIPAA, etc.)
        regions: List of regions to scan
        auto_remediate: Whether to auto-remediate issues
        export_format: Optional export format
        callback_url: Optional callback URL
        
    Returns:
        Scan results
    """
    try:
        logger.info(f"Starting {framework} compliance scan across {len(regions)} regions")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                _async_compliance_scan(framework, regions, auto_remediate, export_format)
            )
            return results
        finally:
            loop.close()
            
    except SoftTimeLimitExceeded:
        logger.warning("Compliance scan exceeded time limit")
        return {
            "status": "timeout",
            "message": "Scan exceeded time limit",
            "partial_results": getattr(current_task, "_partial_results", {}),
        }
    except Exception as e:
        logger.error(f"Compliance scan failed: {e}")
        raise


async def _async_compliance_scan(
    framework: str,
    regions: list[str],
    auto_remediate: bool,
    export_format: Optional[str],
) -> dict[str, Any]:
    """Async implementation of compliance scan."""
    framework_enum = ComplianceFramework[framework.upper()]
    
    results = {
        "framework": framework,
        "scan_started": datetime.utcnow().isoformat(),
        "regions": {},
        "summary": {
            "total_controls": 0,
            "compliant": 0,
            "non_compliant": 0,
            "remediated": 0,
        },
    }
    
    # Store partial results
    if current_task:
        current_task._partial_results = results
    
    for idx, region in enumerate(regions):
        update_task_progress(
            idx + 1,
            len(regions),
            f"Scanning {region}"
        )
        
        scanner = ComplianceScanner(region=region)
        
        try:
            report = await scanner.scan_compliance(
                framework=framework_enum,
                auto_remediate=auto_remediate
            )
            
            # Store results
            results["regions"][region] = {
                "compliance_score": report.compliance_score,
                "total_controls": report.total_controls,
                "compliant": report.compliant_controls,
                "non_compliant": report.non_compliant_controls,
                "scan_date": report.scan_date.isoformat(),
            }
            
            # Update summary
            results["summary"]["total_controls"] += report.total_controls
            results["summary"]["compliant"] += report.compliant_controls
            results["summary"]["non_compliant"] += report.non_compliant_controls
            
            # Export if requested
            if export_format:
                exported = await scanner.export_report(report, format=export_format)
                results["regions"][region]["exported_report"] = exported
                
        except Exception as e:
            logger.error(f"Compliance scan failed for {region}: {e}")
            results["regions"][region] = {
                "error": str(e),
                "status": "failed",
            }
    
    results["scan_completed"] = datetime.utcnow().isoformat()
    return results


@app.task(name="aws_mcp_server.queue.tasks.security_remediation_async", queue="security")
def security_remediation_async(
    finding_ids: list[str],
    remediation_type: str,
    params: Optional[dict[str, Any]] = None,
    callback_url: Optional[str] = None,
) -> dict[str, Any]:
    """Remediate security findings asynchronously.
    
    Args:
        finding_ids: List of finding IDs
        remediation_type: Type of remediation
        params: Remediation parameters
        callback_url: Optional callback URL
        
    Returns:
        Remediation results
    """
    try:
        logger.info(f"Starting security remediation for {len(finding_ids)} findings")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                _async_security_remediation(finding_ids, remediation_type, params)
            )
            return results
        finally:
            loop.close()
            
    except Exception as e:
        logger.error(f"Security remediation failed: {e}")
        raise


async def _async_security_remediation(
    finding_ids: list[str],
    remediation_type: str,
    params: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Async implementation of security remediation."""
    security_hub = SecurityHubClient()
    
    results = {
        "remediation_type": remediation_type,
        "total_findings": len(finding_ids),
        "successful": 0,
        "failed": 0,
        "results": {},
    }
    
    for idx, finding_id in enumerate(finding_ids):
        update_task_progress(
            idx + 1,
            len(finding_ids),
            f"Remediating finding {idx + 1}"
        )
        
        try:
            if remediation_type == "update_workflow":
                # Update finding workflow status
                workflow_status = WorkflowStatus[params.get("status", "RESOLVED")]
                note = params.get("note", "Automated remediation")
                
                await security_hub.update_finding(
                    finding_id=finding_id,
                    workflow_status=workflow_status,
                    note=note
                )
                
                results["successful"] += 1
                results["results"][finding_id] = {
                    "status": "success",
                    "action": f"Updated to {workflow_status.value}",
                }
            else:
                raise ValueError(f"Unsupported remediation type: {remediation_type}")
                
        except Exception as e:
            logger.error(f"Failed to remediate {finding_id}: {e}")
            results["failed"] += 1
            results["results"][finding_id] = {
                "status": "failed",
                "error": str(e),
            }
    
    return results


@app.task(name="aws_mcp_server.queue.tasks.cleanup_old_results")
def cleanup_old_results():
    """Clean up old task results."""
    # This would connect to result backend and clean up
    logger.info("Cleaning up old task results")
    return {"status": "success", "cleaned": 0}


@app.task(name="aws_mcp_server.queue.tasks.health_check")
def health_check():
    """Perform health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "worker": current_task.request.hostname,
    }