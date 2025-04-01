"""
Log Management Tools for AWS MCP Server.

This module provides tools for integrating log management capabilities
with the AWS MCP Server's Model Context Protocol.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from ..tools import Tool, ToolSchema
from .logs import (
    LogManager, LogPatternRegistry, LogGroupRegistry,
    LogSource, LogStatus, LogSeverity
)

logger = logging.getLogger(__name__)


class LogTool(Tool):
    """Base class for log management tools."""
    pass


class ListLogPatternsTool(LogTool):
    """Tool for listing log patterns."""
    
    name = "list_log_patterns"
    description = "List available log patterns for parsing logs"
    
    schema = ToolSchema(
        properties={}
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the list log patterns tool."""
        try:
            patterns = LogPatternRegistry.list_patterns()
            
            # Format for output
            result = {
                "patterns": [
                    {
                        "id": pattern.id,
                        "name": pattern.name,
                        "description": pattern.description,
                        "group_names": pattern.group_names
                    }
                    for pattern in patterns
                ],
                "count": len(patterns)
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing log patterns: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetLogPatternTool(LogTool):
    """Tool for getting details of a log pattern."""
    
    name = "get_log_pattern"
    description = "Get details of a specific log pattern"
    
    schema = ToolSchema(
        properties={
            "pattern_id": {
                "type": "string",
                "description": "ID of the log pattern"
            }
        },
        required=["pattern_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get log pattern tool."""
        try:
            pattern_id = params.get("pattern_id")
            
            pattern = LogPatternRegistry.get_pattern(pattern_id)
            if not pattern:
                return json.dumps({
                    "error": f"Log pattern not found: {pattern_id}"
                })
            
            result = pattern.to_dict()
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting log pattern: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class CreateLogPatternTool(LogTool):
    """Tool for creating a new log pattern."""
    
    name = "create_log_pattern"
    description = "Create a new log pattern for parsing logs"
    
    schema = ToolSchema(
        properties={
            "name": {
                "type": "string",
                "description": "Name for the log pattern"
            },
            "description": {
                "type": "string",
                "description": "Description of the log pattern"
            },
            "pattern": {
                "type": "string",
                "description": "Regular expression pattern with named groups"
            },
            "severity_mapping": {
                "type": "object",
                "description": "Mapping of extracted values to severities"
            }
        },
        required=["name", "description", "pattern"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the create log pattern tool."""
        try:
            name = params.get("name")
            description = params.get("description")
            pattern = params.get("pattern")
            severity_mapping_raw = params.get("severity_mapping", {})
            
            # Convert severity mapping to proper enum values
            severity_mapping = {}
            for key, value in severity_mapping_raw.items():
                try:
                    severity = LogSeverity[value.upper()]
                    severity_mapping[key] = severity
                except (KeyError, AttributeError):
                    return json.dumps({
                        "error": f"Invalid severity value: {value}"
                    })
            
            # Create the log pattern
            log_pattern = LogManager.create_log_pattern(
                name=name,
                description=description,
                pattern=pattern,
                severity_mapping=severity_mapping
            )
            
            return json.dumps({
                "pattern_id": log_pattern.id,
                "name": log_pattern.name,
                "group_names": log_pattern.group_names
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error creating log pattern: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class DeleteLogPatternTool(LogTool):
    """Tool for deleting a log pattern."""
    
    name = "delete_log_pattern"
    description = "Delete a log pattern"
    
    schema = ToolSchema(
        properties={
            "pattern_id": {
                "type": "string",
                "description": "ID of the log pattern to delete"
            }
        },
        required=["pattern_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the delete log pattern tool."""
        try:
            pattern_id = params.get("pattern_id")
            
            result = LogPatternRegistry.delete_pattern(pattern_id)
            if not result:
                return json.dumps({
                    "error": f"Log pattern not found: {pattern_id}"
                })
            
            return json.dumps({
                "success": True,
                "message": f"Log pattern deleted: {pattern_id}"
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error deleting log pattern: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class ListLogGroupsTool(LogTool):
    """Tool for listing log groups."""
    
    name = "list_log_groups"
    description = "List available log groups"
    
    schema = ToolSchema(
        properties={
            "source": {
                "type": "string",
                "description": "Filter by source (e.g., cloudwatch, agent, custom)"
            },
            "resource_type": {
                "type": "string",
                "description": "Filter by resource type"
            },
            "include_archived": {
                "type": "boolean",
                "description": "Whether to include archived log groups"
            }
        }
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the list log groups tool."""
        try:
            # Parse the source
            source_str = params.get("source", "").upper()
            source = None
            if source_str:
                try:
                    source = LogSource[source_str]
                except KeyError:
                    return json.dumps({
                        "error": f"Invalid source: {source_str}"
                    })
            
            resource_type = params.get("resource_type")
            include_archived = params.get("include_archived", False)
            
            # Get log groups based on filters
            log_groups = []
            if source:
                log_groups = LogGroupRegistry.get_log_groups_by_source(source)
            elif resource_type:
                log_groups = LogGroupRegistry.get_log_groups_by_resource_type(resource_type)
            else:
                log_groups = LogGroupRegistry.list_log_groups()
            
            # Filter archived if needed
            if not include_archived:
                log_groups = [
                    log_group for log_group in log_groups
                    if log_group.status != LogStatus.ARCHIVED
                ]
            
            # Format for output
            result = {
                "log_groups": [
                    {
                        "id": log_group.id,
                        "name": log_group.name,
                        "description": log_group.description,
                        "source": log_group.source.value,
                        "log_group_name": log_group.log_group_name,
                        "resource_type": log_group.resource_type,
                        "retention_days": log_group.retention_days,
                        "status": log_group.status.value
                    }
                    for log_group in log_groups
                ],
                "count": len(log_groups)
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing log groups: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetLogGroupTool(LogTool):
    """Tool for getting details of a log group."""
    
    name = "get_log_group"
    description = "Get details of a specific log group"
    
    schema = ToolSchema(
        properties={
            "log_group_id": {
                "type": "string",
                "description": "ID of the log group"
            }
        },
        required=["log_group_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get log group tool."""
        try:
            log_group_id = params.get("log_group_id")
            
            log_group = LogGroupRegistry.get_log_group(log_group_id)
            if not log_group:
                return json.dumps({
                    "error": f"Log group not found: {log_group_id}"
                })
            
            result = log_group.to_dict()
            
            # Add pattern details
            patterns = []
            for pattern_id in log_group.patterns:
                pattern = LogPatternRegistry.get_pattern(pattern_id)
                if pattern:
                    patterns.append({
                        "id": pattern.id,
                        "name": pattern.name
                    })
            
            result["pattern_details"] = patterns
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting log group: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class CreateLogGroupTool(LogTool):
    """Tool for creating a new log group."""
    
    name = "create_log_group"
    description = "Create a new log group for collecting logs"
    
    schema = ToolSchema(
        properties={
            "name": {
                "type": "string",
                "description": "Name for the log group"
            },
            "description": {
                "type": "string",
                "description": "Description of the log group"
            },
            "source": {
                "type": "string",
                "description": "Source of the logs (cloudwatch, agent, custom)"
            },
            "log_group_name": {
                "type": "string",
                "description": "Name of the log group in CloudWatch or other source"
            },
            "resource_type": {
                "type": "string",
                "description": "Type of resources this group applies to"
            },
            "retention_days": {
                "type": "integer",
                "description": "Number of days to retain logs"
            },
            "patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of pattern IDs to apply to this log group"
            }
        },
        required=["name", "source", "log_group_name"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the create log group tool."""
        try:
            name = params.get("name")
            description = params.get("description", "")
            source_str = params.get("source", "").upper()
            log_group_name = params.get("log_group_name")
            resource_type = params.get("resource_type", "*")
            retention_days = params.get("retention_days", 30)
            patterns = params.get("patterns", [])
            
            # Parse the source
            try:
                source = LogSource[source_str]
            except KeyError:
                return json.dumps({
                    "error": f"Invalid source: {source_str}. Must be one of: cloudwatch, agent, custom."
                })
            
            # Validate patterns
            for pattern_id in patterns:
                if not LogPatternRegistry.get_pattern(pattern_id):
                    return json.dumps({
                        "error": f"Log pattern not found: {pattern_id}"
                    })
            
            # Create the log group
            log_group = LogManager.create_log_group(
                name=name,
                description=description,
                source=source,
                log_group_name=log_group_name,
                resource_type=resource_type,
                retention_days=retention_days,
                patterns=patterns
            )
            
            return json.dumps({
                "log_group_id": log_group.id,
                "name": log_group.name,
                "source": log_group.source.value,
                "log_group_name": log_group.log_group_name
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error creating log group: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class DeleteLogGroupTool(LogTool):
    """Tool for deleting a log group."""
    
    name = "delete_log_group"
    description = "Delete a log group (mark as archived)"
    
    schema = ToolSchema(
        properties={
            "log_group_id": {
                "type": "string",
                "description": "ID of the log group to delete"
            }
        },
        required=["log_group_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the delete log group tool."""
        try:
            log_group_id = params.get("log_group_id")
            
            result = LogGroupRegistry.delete_log_group(log_group_id)
            if not result:
                return json.dumps({
                    "error": f"Log group not found: {log_group_id}"
                })
            
            return json.dumps({
                "success": True,
                "message": f"Log group archived: {log_group_id}"
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error deleting log group: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class CollectLogsTool(LogTool):
    """Tool for collecting logs."""
    
    name = "collect_logs"
    description = "Collect logs from AWS resources"
    
    schema = ToolSchema(
        properties={
            "log_group_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of specific log groups to collect from"
            },
            "resource_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of specific resources to collect logs for"
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
        """Run the collect logs tool."""
        try:
            log_group_ids = params.get("log_group_ids")
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
            
            # Collect logs
            logs_by_group = await LogManager.collect_logs(
                log_group_ids=log_group_ids,
                resource_ids=resource_ids,
                account_ids=account_ids,
                regions=regions,
                start_time=start_time,
                end_time=end_time
            )
            
            # Format for output
            result = {
                "log_groups_collected": len(logs_by_group),
                "entries_collected": sum(len(entries) for entries in logs_by_group.values()),
                "details": {
                    log_group_id: {
                        "group_name": LogGroupRegistry.get_log_group(log_group_id).name if LogGroupRegistry.get_log_group(log_group_id) else "Unknown",
                        "entries_count": len(entries),
                        "resources": list(set(entry.resource_id for entry in entries))
                    }
                    for log_group_id, entries in logs_by_group.items()
                }
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error collecting logs: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class SearchLogsTool(LogTool):
    """Tool for searching logs."""
    
    name = "search_logs"
    description = "Search logs with filtering"
    
    schema = ToolSchema(
        properties={
            "query_string": {
                "type": "string",
                "description": "Search query string"
            },
            "log_groups": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of log group IDs to search in"
            },
            "start_time": {
                "type": "string",
                "description": "Start time for search (ISO format)"
            },
            "end_time": {
                "type": "string",
                "description": "End time for search (ISO format)"
            },
            "resource_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of resource IDs to filter by"
            },
            "account_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of account IDs to filter by"
            },
            "regions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of regions to filter by"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of results to return"
            }
        },
        required=["query_string", "log_groups"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the search logs tool."""
        try:
            query_string = params.get("query_string")
            log_groups = params.get("log_groups")
            resource_ids = params.get("resource_ids", [])
            account_ids = params.get("account_ids", [])
            regions = params.get("regions", [])
            limit = params.get("limit", 100)
            
            # Parse time parameters
            start_time = datetime.now() - timedelta(hours=1)  # Default to last hour
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
            
            # Create and execute the query
            query = LogManager.create_log_query(
                name=f"Search: {query_string}",
                query_string=query_string,
                log_groups=log_groups,
                start_time=start_time,
                end_time=end_time,
                limit=limit,
                account_ids=account_ids,
                regions=regions,
                resource_ids=resource_ids
            )
            
            result = LogManager.search_logs(query)
            
            # Format for output
            formatted_result = {
                "query_id": result.query_id,
                "count": len(result.entries),
                "execution_time_ms": result.execution_time_ms,
                "scanned_bytes": result.scanned_bytes,
                "entries": [
                    {
                        "id": entry.id,
                        "timestamp": entry.timestamp.isoformat(),
                        "resource_id": entry.resource_id,
                        "severity": entry.severity.value,
                        "message": entry.message[:200] + ("..." if len(entry.message) > 200 else ""),
                        "log_group": entry.log_group,
                        "account_id": entry.account_id,
                        "region": entry.region
                    }
                    for entry in result.entries
                ]
            }
            
            return json.dumps(formatted_result, indent=2)
            
        except Exception as e:
            logger.error(f"Error searching logs: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


# List of log management tools
logs_tools = [
    ListLogPatternsTool(),
    GetLogPatternTool(),
    CreateLogPatternTool(),
    DeleteLogPatternTool(),
    ListLogGroupsTool(),
    GetLogGroupTool(),
    CreateLogGroupTool(),
    DeleteLogGroupTool(),
    CollectLogsTool(),
    SearchLogsTool()
] 