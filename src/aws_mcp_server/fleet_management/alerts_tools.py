"""
Alert Tools for AWS MCP Server.

This module provides tools for integrating alerting capabilities
with the AWS MCP Server's Model Context Protocol.
"""

import logging
from datetime import datetime
from typing import Any, Dict

from ..tools import Tool, ToolSchema
from .alerts import (
    AlertManager, AlertRegistry,
    AlertSeverity, AlertStatus, ComparisonOperator
)

logger = logging.getLogger(__name__)


class AlertTool(Tool):
    """Base class for alert tools."""
    pass


class ListAlertsTool(AlertTool):
    """Tool for listing alert definitions."""
    
    name = "list_alerts"
    description = "List alert definitions for AWS resources"
    
    schema = ToolSchema(
        properties={
            "severity": {
                "type": "string",
                "description": "Filter by severity (e.g., critical, high, medium, low)"
            },
            "metric_id": {
                "type": "string",
                "description": "Filter by metric ID"
            },
            "include_archived": {
                "type": "boolean",
                "description": "Whether to include archived alerts"
            }
        }
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the list alerts tool."""
        try:
            # Parse the severity
            severity_str = params.get("severity", "").upper()
            severity = None
            if severity_str:
                try:
                    severity = AlertSeverity[severity_str]
                except KeyError:
                    return json.dumps({
                        "error": f"Invalid severity: {severity_str}"
                    })
            
            metric_id = params.get("metric_id")
            include_archived = params.get("include_archived", False)
            
            # Get alerts based on filters
            alerts = []
            if severity:
                alerts = AlertRegistry.get_alerts_by_severity(severity)
            elif metric_id:
                alerts = AlertRegistry.get_alerts_by_metric(metric_id)
            else:
                alerts = list(AlertRegistry._alerts.values())
            
            # Filter archived if needed
            if not include_archived:
                alerts = [
                    alert for alert in alerts
                    if alert.status != AlertStatus.ARCHIVED
                ]
            
            # Format for output
            result = {
                "alerts": [
                    {
                        "id": alert.id,
                        "name": alert.name,
                        "description": alert.description,
                        "severity": alert.severity.value,
                        "status": alert.status.value,
                        "conditions_count": len(alert.conditions),
                        "targets_count": len(alert.targets)
                    }
                    for alert in alerts
                ],
                "count": len(alerts)
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing alerts: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetAlertTool(AlertTool):
    """Tool for getting details of an alert definition."""
    
    name = "get_alert"
    description = "Get details of a specific alert definition"
    
    schema = ToolSchema(
        properties={
            "alert_id": {
                "type": "string",
                "description": "ID of the alert definition"
            }
        },
        required=["alert_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get alert tool."""
        try:
            alert_id = params.get("alert_id")
            
            alert = AlertRegistry.get_alert(alert_id)
            if not alert:
                return json.dumps({
                    "error": f"Alert definition not found: {alert_id}"
                })
            
            result = alert.to_dict()
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting alert: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class CreateAlertTool(AlertTool):
    """Tool for creating a new alert definition."""
    
    name = "create_alert"
    description = "Create a new alert definition"
    
    schema = ToolSchema(
        properties={
            "name": {
                "type": "string",
                "description": "Name for the alert"
            },
            "description": {
                "type": "string",
                "description": "Description of the alert"
            },
            "conditions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "metric_id": {
                            "type": "string",
                            "description": "ID of the metric to monitor"
                        },
                        "operator": {
                            "type": "string",
                            "description": "Comparison operator (>, >=, <, <=, ==, !=)"
                        },
                        "threshold": {
                            "type": "number",
                            "description": "Threshold value"
                        },
                        "evaluation_periods": {
                            "type": "integer",
                            "description": "Number of periods to evaluate"
                        },
                        "datapoints_to_alarm": {
                            "type": "integer",
                            "description": "Number of datapoints that must be breaching"
                        }
                    },
                    "required": ["metric_id", "operator", "threshold"]
                },
                "description": "Conditions that trigger the alert"
            },
            "targets": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "description": "Target type (email, sns, webhook)"
                        },
                        "destination": {
                            "type": "string",
                            "description": "Destination (email address, SNS ARN, URL)"
                        },
                        "format": {
                            "type": "string",
                            "description": "Format for notifications (json, text, html)"
                        }
                    },
                    "required": ["type", "destination"]
                },
                "description": "Notification targets"
            },
            "severity": {
                "type": "string",
                "description": "Severity of the alert (critical, high, medium, low, info)"
            },
            "resource_filters": {
                "type": "object",
                "description": "Resource filters as type to list of IDs"
            },
            "account_filters": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of account IDs to filter by"
            },
            "region_filters": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of regions to filter by"
            },
            "auto_resolve": {
                "type": "boolean",
                "description": "Whether to auto-resolve the alert when condition is no longer true"
            }
        },
        required=["name", "description", "conditions", "targets", "severity"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the create alert tool."""
        try:
            name = params.get("name")
            description = params.get("description")
            conditions_data = params.get("conditions", [])
            targets_data = params.get("targets", [])
            
            # Parse the severity
            severity_str = params.get("severity", "").upper()
            severity = AlertSeverity.MEDIUM
            try:
                severity = AlertSeverity[severity_str]
            except KeyError:
                return json.dumps({
                    "error": f"Invalid severity: {severity_str}"
                })
            
            resource_filters = params.get("resource_filters", {})
            account_filters = params.get("account_filters", [])
            region_filters = params.get("region_filters", [])
            auto_resolve = params.get("auto_resolve", True)
            
            # Create alert conditions
            conditions = []
            for condition_data in conditions_data:
                metric_id = condition_data.get("metric_id")
                operator_str = condition_data.get("operator")
                threshold = condition_data.get("threshold")
                evaluation_periods = condition_data.get("evaluation_periods", 1)
                datapoints_to_alarm = condition_data.get("datapoints_to_alarm", 1)
                
                # Map operator string to enum
                operator_map = {
                    ">": ComparisonOperator.GREATER_THAN,
                    ">=": ComparisonOperator.GREATER_THAN_OR_EQUAL,
                    "<": ComparisonOperator.LESS_THAN,
                    "<=": ComparisonOperator.LESS_THAN_OR_EQUAL,
                    "==": ComparisonOperator.EQUAL,
                    "!=": ComparisonOperator.NOT_EQUAL
                }
                
                if operator_str not in operator_map:
                    return json.dumps({
                        "error": f"Invalid operator: {operator_str}. Must be one of: >, >=, <, <=, ==, !="
                    })
                
                condition = AlertManager.create_alert_condition(
                    metric_id=metric_id,
                    operator=operator_map[operator_str],
                    threshold=threshold,
                    evaluation_periods=evaluation_periods,
                    datapoints_to_alarm=datapoints_to_alarm
                )
                
                conditions.append(condition)
            
            # Create alert targets
            targets = []
            for target_data in targets_data:
                target_type = target_data.get("type")
                destination = target_data.get("destination")
                format = target_data.get("format", "json")
                
                target = AlertManager.create_alert_target(
                    type=target_type,
                    destination=destination,
                    format=format
                )
                
                targets.append(target)
            
            # Create the alert
            alert = AlertManager.create_alert(
                name=name,
                description=description,
                conditions=conditions,
                targets=targets,
                severity=severity,
                resource_filters=resource_filters,
                account_filters=account_filters,
                region_filters=region_filters,
                auto_resolve=auto_resolve
            )
            
            return json.dumps({
                "alert_id": alert.id,
                "name": alert.name,
                "severity": alert.severity.value,
                "conditions_count": len(alert.conditions),
                "targets_count": len(alert.targets)
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class DeleteAlertTool(AlertTool):
    """Tool for deleting an alert definition."""
    
    name = "delete_alert"
    description = "Delete an alert definition (mark as archived)"
    
    schema = ToolSchema(
        properties={
            "alert_id": {
                "type": "string",
                "description": "ID of the alert definition to delete"
            }
        },
        required=["alert_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the delete alert tool."""
        try:
            alert_id = params.get("alert_id")
            
            result = AlertRegistry.delete_alert(alert_id)
            if not result:
                return json.dumps({
                    "error": f"Alert definition not found: {alert_id}"
                })
            
            return json.dumps({
                "success": True,
                "message": f"Alert definition archived: {alert_id}"
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error deleting alert: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetActiveAlertsTool(AlertTool):
    """Tool for getting active alert instances."""
    
    name = "get_active_alerts"
    description = "Get currently active alert instances"
    
    schema = ToolSchema(
        properties={}
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get active alerts tool."""
        try:
            active_alerts = AlertManager.get_active_alerts()
            
            # Format for output
            result = {
                "active_alerts": active_alerts,
                "count": len(active_alerts)
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting active alerts: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class AcknowledgeAlertTool(AlertTool):
    """Tool for acknowledging an alert instance."""
    
    name = "acknowledge_alert"
    description = "Acknowledge an active alert instance"
    
    schema = ToolSchema(
        properties={
            "alert_instance_id": {
                "type": "string",
                "description": "ID of the alert instance to acknowledge"
            },
            "user": {
                "type": "string",
                "description": "User acknowledging the alert"
            }
        },
        required=["alert_instance_id", "user"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the acknowledge alert tool."""
        try:
            alert_instance_id = params.get("alert_instance_id")
            user = params.get("user")
            
            result = AlertManager.acknowledge_alert(alert_instance_id, user)
            if not result:
                return json.dumps({
                    "error": f"Failed to acknowledge alert instance. Alert instance not found or not in ALERTING state: {alert_instance_id}"
                })
            
            return json.dumps({
                "success": True,
                "message": f"Alert instance acknowledged: {alert_instance_id} by {user}"
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error acknowledging alert: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class ResolveAlertTool(AlertTool):
    """Tool for manually resolving an alert instance."""
    
    name = "resolve_alert"
    description = "Manually resolve an alert instance"
    
    schema = ToolSchema(
        properties={
            "alert_instance_id": {
                "type": "string",
                "description": "ID of the alert instance to resolve"
            }
        },
        required=["alert_instance_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the resolve alert tool."""
        try:
            alert_instance_id = params.get("alert_instance_id")
            
            result = AlertManager.resolve_alert(alert_instance_id)
            if not result:
                return json.dumps({
                    "error": f"Failed to resolve alert instance. Alert instance not found or already resolved: {alert_instance_id}"
                })
            
            return json.dumps({
                "success": True,
                "message": f"Alert instance resolved: {alert_instance_id}"
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error resolving alert: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class ProcessMetricDataTool(AlertTool):
    """Tool for processing metric data and triggering alerts if needed."""
    
    name = "process_metric_data"
    description = "Process metric data and trigger alerts if thresholds are breached"
    
    schema = ToolSchema(
        properties={
            "metric_id": {
                "type": "string",
                "description": "ID of the metric being processed"
            },
            "resource_id": {
                "type": "string",
                "description": "ID of the resource this metric is for"
            },
            "account_id": {
                "type": "string",
                "description": "AWS account ID"
            },
            "region": {
                "type": "string",
                "description": "AWS region"
            },
            "timestamp": {
                "type": "string",
                "description": "ISO8601 timestamp for the metric data"
            },
            "value": {
                "type": "number",
                "description": "Metric value"
            },
            "dimensions": {
                "type": "object",
                "description": "Optional dimensions for the metric"
            }
        },
        required=["metric_id", "resource_id", "account_id", "region", "value"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the process metric data tool."""
        try:
            from .monitoring import MetricData
            
            metric_id = params.get("metric_id")
            resource_id = params.get("resource_id")
            account_id = params.get("account_id")
            region = params.get("region")
            timestamp_str = params.get("timestamp")
            value = params.get("value")
            dimensions = params.get("dimensions", {})
            
            # Parse timestamp if provided, otherwise use current time
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = datetime.now()
            
            # Create metric data object
            metric_data = MetricData(
                metric_id=metric_id,
                resource_id=resource_id,
                account_id=account_id,
                region=region,
                timestamp=timestamp,
                values=[{"timestamp": timestamp, "value": value}],
                dimensions=dimensions
            )
            
            # Process the metric data
            alert_instances = await AlertManager.process_metric_data(metric_data)
            
            return json.dumps({
                "processed": True,
                "metric_id": metric_id,
                "timestamp": timestamp.isoformat(),
                "value": value,
                "alerts_triggered": len(alert_instances),
                "alert_instances": [
                    {
                        "id": instance.id,
                        "state": instance.state.value,
                        "severity": instance.severity.value
                    }
                    for instance in alert_instances
                ]
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error processing metric data: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


# List of alert tools
alerts_tools = [
    ListAlertsTool(),
    GetAlertTool(),
    CreateAlertTool(),
    DeleteAlertTool(),
    GetActiveAlertsTool(),
    AcknowledgeAlertTool(),
    ResolveAlertTool(),
    ProcessMetricDataTool()
] 