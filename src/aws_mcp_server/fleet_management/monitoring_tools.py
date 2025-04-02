"""
Monitoring Tools for AWS Fleet Management.

This module provides tools for interacting with the monitoring system.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict

from ..tools import Tool, ToolSchema
from .monitoring import (
    MetricManager, MetricPriority, MetricRegistry,
    MetricStatus, MetricType
)

logger = logging.getLogger(__name__)


class MonitoringTool(Tool):
    """Base class for monitoring tools."""
    pass


class ListMetricsToool(MonitoringTool):
    """Tool for listing available metrics."""
    
    name = "list_metrics"
    description = "List available metrics for AWS resources"
    
    schema = ToolSchema(
        properties={
            "metric_type": {
                "type": "string",
                "description": "Type of metrics to list (e.g., cloudwatch, custom, composite)"
            },
            "priority": {
                "type": "string",
                "description": "Filter by priority (e.g., critical, high, medium, low)"
            },
            "include_archived": {
                "type": "boolean",
                "description": "Whether to include archived metrics"
            }
        }
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the list metrics tool."""
        try:
            # Parse the metric type
            metric_type_str = params.get("metric_type", "").upper()
            metric_type = None
            if metric_type_str:
                try:
                    metric_type = MetricType[metric_type_str]
                except KeyError:
                    return json.dumps({
                        "error": f"Invalid metric type: {metric_type_str}"
                    })
            
            # Parse the priority
            priority_str = params.get("priority", "").upper()
            priority = None
            if priority_str:
                try:
                    priority = MetricPriority[priority_str]
                except KeyError:
                    return json.dumps({
                        "error": f"Invalid priority: {priority_str}"
                    })
            
            include_archived = params.get("include_archived", False)
            
            # Get metrics based on filters
            metrics = []
            if metric_type:
                metrics = MetricRegistry.get_metrics_by_type(metric_type)
            elif priority:
                metrics = MetricRegistry.get_metrics_by_priority(priority)
            else:
                metrics = list(MetricRegistry._metrics.values())
            
            # Filter archived if needed
            if not include_archived:
                metrics = [
                    metric for metric in metrics
                    if metric.status != MetricStatus.ARCHIVED
                ]
            
            # Format for output
            result = {
                "metrics": [
                    {
                        "id": metric.id,
                        "name": metric.name,
                        "description": metric.description,
                        "namespace": metric.namespace,
                        "metric_name": metric.metric_name,
                        "dimensions": metric.dimensions,
                        "type": metric.metric_type.value,
                        "priority": metric.priority.value,
                        "status": metric.status.value
                    }
                    for metric in metrics
                ],
                "count": len(metrics)
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing metrics: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetMetricTool(MonitoringTool):
    """Tool for getting details of a metric."""
    
    name = "get_metric"
    description = "Get details of a specific metric"
    
    schema = ToolSchema(
        properties={
            "metric_id": {
                "type": "string",
                "description": "ID of the metric"
            }
        },
        required=["metric_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get metric tool."""
        try:
            metric_id = params.get("metric_id")
            
            metric = MetricRegistry.get_metric(metric_id)
            if not metric:
                return json.dumps({
                    "error": f"Metric not found: {metric_id}"
                })
            
            result = metric.to_dict()
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting metric: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class CreateMetricTool(MonitoringTool):
    """Tool for creating a new metric."""
    
    name = "create_metric"
    description = "Create a new metric to monitor"
    
    schema = ToolSchema(
        properties={
            "name": {
                "type": "string",
                "description": "Name for the metric"
            },
            "description": {
                "type": "string",
                "description": "Description of the metric"
            },
            "namespace": {
                "type": "string",
                "description": "Namespace for the metric (e.g., AWS/EC2)"
            },
            "metric_name": {
                "type": "string",
                "description": "Name of the metric in the namespace (e.g., CPUUtilization)"
            },
            "dimensions": {
                "type": "object",
                "description": "Dimensions as key-value pairs (e.g., {\"InstanceId\": \"{resource_id}\"})"
            },
            "statistic": {
                "type": "string",
                "description": "Statistic to collect (e.g., Average, Sum, Maximum, Minimum)"
            },
            "period": {
                "type": "integer",
                "description": "Collection period in seconds"
            },
            "unit": {
                "type": "string",
                "description": "Unit of the metric (e.g., Percent, Bytes)"
            },
            "metric_type": {
                "type": "string",
                "description": "Type of metric (cloudwatch, custom, composite)"
            },
            "priority": {
                "type": "string",
                "description": "Priority of the metric (critical, high, medium, low)"
            },
            "retention_days": {
                "type": "integer",
                "description": "Number of days to retain data"
            }
        },
        required=["name", "description", "namespace", "metric_name"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the create metric tool."""
        try:
            name = params.get("name")
            description = params.get("description")
            namespace = params.get("namespace")
            metric_name = params.get("metric_name")
            dimensions = params.get("dimensions", {})
            statistic = params.get("statistic", "Average")
            period = params.get("period", 300)
            unit = params.get("unit")
            
            # Parse the metric type
            metric_type_str = params.get("metric_type", "").upper()
            metric_type = MetricType.CLOUDWATCH
            if metric_type_str:
                try:
                    metric_type = MetricType[metric_type_str]
                except KeyError:
                    return json.dumps({
                        "error": f"Invalid metric type: {metric_type_str}"
                    })
            
            # Parse the priority
            priority_str = params.get("priority", "").upper()
            priority = MetricPriority.MEDIUM
            if priority_str:
                try:
                    priority = MetricPriority[priority_str]
                except KeyError:
                    return json.dumps({
                        "error": f"Invalid priority: {priority_str}"
                    })
            
            retention_days = params.get("retention_days", 14)
            
            # Create the metric
            metric = MetricManager.create_metric(
                name=name,
                description=description,
                namespace=namespace,
                metric_name=metric_name,
                dimensions=dimensions,
                statistic=statistic,
                period=period,
                unit=unit,
                metric_type=metric_type,
                priority=priority,
                retention_days=retention_days
            )
            
            return json.dumps({
                "metric_id": metric.id,
                "name": metric.name,
                "type": metric.metric_type.value,
                "namespace": metric.namespace,
                "metric_name": metric.metric_name
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error creating metric: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class DeleteMetricTool(MonitoringTool):
    """Tool for deleting a metric."""
    
    name = "delete_metric"
    description = "Delete a metric (mark as archived)"
    
    schema = ToolSchema(
        properties={
            "metric_id": {
                "type": "string",
                "description": "ID of the metric to delete"
            }
        },
        required=["metric_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the delete metric tool."""
        try:
            metric_id = params.get("metric_id")
            
            result = MetricRegistry.delete_metric(metric_id)
            if not result:
                return json.dumps({
                    "error": f"Metric not found: {metric_id}"
                })
            
            return json.dumps({
                "success": True,
                "message": f"Metric archived: {metric_id}"
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error deleting metric: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class CollectMetricsTool(MonitoringTool):
    """Tool for collecting metrics."""
    
    name = "collect_metrics"
    description = "Collect metrics for AWS resources"
    
    schema = ToolSchema(
        properties={
            "metric_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of specific metrics to collect"
            },
            "resource_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of specific resources to collect for"
            },
            "account_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of specific accounts to collect from"
            },
            "regions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of specific regions to collect from"
            },
            "start_time": {
                "type": "string",
                "description": "Start time for collection (ISO format)"
            },
            "end_time": {
                "type": "string",
                "description": "End time for collection (ISO format)"
            }
        }
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the collect metrics tool."""
        try:
            metric_ids = params.get("metric_ids")
            resource_ids = params.get("resource_ids")
            account_ids = params.get("account_ids")
            regions = params.get("regions")
            
            # Parse time parameters
            start_time = None
            end_time = None
            
            if "start_time" in params:
                try:
                    start_time = datetime.fromisoformat(params["start_time"])
                except ValueError:
                    return json.dumps({
                        "error": f"Invalid start_time format: {params['start_time']}. Use ISO format."
                    })
            
            if "end_time" in params:
                try:
                    end_time = datetime.fromisoformat(params["end_time"])
                except ValueError:
                    return json.dumps({
                        "error": f"Invalid end_time format: {params['end_time']}. Use ISO format."
                    })
            
            # Collect metrics
            metric_data_list = await MetricManager.collect_metrics(
                metric_ids=metric_ids,
                resource_ids=resource_ids,
                account_ids=account_ids,
                regions=regions,
                start_time=start_time,
                end_time=end_time
            )
            
            # Format for output
            result = {
                "metrics_collected": len(metric_data_list),
                "resources": list(set(data.resource_id for data in metric_data_list)),
                "metric_ids": list(set(data.metric_id for data in metric_data_list)),
                "accounts": list(set(data.account_id for data in metric_data_list)),
                "regions": list(set(data.region for data in metric_data_list)),
                "data_points": sum(len(data.values) for data in metric_data_list)
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetMetricDataTool(MonitoringTool):
    """Tool for getting metric data."""
    
    name = "get_metric_data"
    description = "Get collected data for a specific metric"
    
    schema = ToolSchema(
        properties={
            "metric_id": {
                "type": "string",
                "description": "ID of the metric"
            },
            "resource_id": {
                "type": "string",
                "description": "Optional resource ID to filter by"
            },
            "account_id": {
                "type": "string",
                "description": "Optional account ID to filter by"
            },
            "region": {
                "type": "string",
                "description": "Optional region to filter by"
            },
            "start_time": {
                "type": "string",
                "description": "Start time for data (ISO format)"
            },
            "end_time": {
                "type": "string",
                "description": "End time for data (ISO format)"
            }
        },
        required=["metric_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get metric data tool."""
        try:
            metric_id = params.get("metric_id")
            resource_id = params.get("resource_id")
            account_id = params.get("account_id")
            region = params.get("region")
            
            # Validate metric exists
            metric = MetricRegistry.get_metric(metric_id)
            if not metric:
                return json.dumps({
                    "error": f"Metric not found: {metric_id}"
                })
            
            # Parse time parameters
            start_time = None
            end_time = None
            
            if "start_time" in params:
                try:
                    start_time = datetime.fromisoformat(params["start_time"])
                except ValueError:
                    return json.dumps({
                        "error": f"Invalid start_time format: {params['start_time']}. Use ISO format."
                    })
            
            if "end_time" in params:
                try:
                    end_time = datetime.fromisoformat(params["end_time"])
                except ValueError:
                    return json.dumps({
                        "error": f"Invalid end_time format: {params['end_time']}. Use ISO format."
                    })
            
            # Get metric data
            metric_data_list = MetricManager.get_metric_data(
                metric_id=metric_id,
                resource_id=resource_id,
                account_id=account_id,
                region=region,
                start_time=start_time,
                end_time=end_time
            )
            
            # Format for output
            result = {
                "metric": {
                    "id": metric.id,
                    "name": metric.name,
                    "namespace": metric.namespace,
                    "metric_name": metric.metric_name,
                    "unit": metric.unit
                },
                "data": [data.to_dict() for data in metric_data_list],
                "count": len(metric_data_list),
                "data_points": sum(len(data.values) for data in metric_data_list)
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting metric data: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class AnalyzeMetricTrendTool(MonitoringTool):
    """Tool for analyzing metric trends."""
    
    name = "analyze_metric_trend"
    description = "Analyze trend for a specific metric and resource"
    
    schema = ToolSchema(
        properties={
            "metric_id": {
                "type": "string",
                "description": "ID of the metric"
            },
            "resource_id": {
                "type": "string",
                "description": "Resource ID to analyze"
            },
            "account_id": {
                "type": "string",
                "description": "Optional account ID to filter by"
            },
            "region": {
                "type": "string",
                "description": "Optional region to filter by"
            },
            "hours": {
                "type": "integer",
                "description": "Number of hours to analyze"
            }
        },
        required=["metric_id", "resource_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the analyze metric trend tool."""
        try:
            metric_id = params.get("metric_id")
            resource_id = params.get("resource_id")
            account_id = params.get("account_id")
            region = params.get("region")
            hours = params.get("hours", 24)
            
            # Validate metric exists
            metric = MetricRegistry.get_metric(metric_id)
            if not metric:
                return json.dumps({
                    "error": f"Metric not found: {metric_id}"
                })
            
            # Analyze trend
            analysis = MetricManager.analyze_metric_trend(
                metric_id=metric_id,
                resource_id=resource_id,
                account_id=account_id,
                region=region,
                hours=hours
            )
            
            return json.dumps(analysis, indent=2)
            
        except Exception as e:
            logger.error(f"Error analyzing metric trend: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


# List of monitoring tools
monitoring_tools = [
    ListMetricsToool(),
    GetMetricTool(),
    CreateMetricTool(),
    DeleteMetricTool(),
    CollectMetricsTool(),
    GetMetricDataTool(),
    AnalyzeMetricTrendTool()
] 