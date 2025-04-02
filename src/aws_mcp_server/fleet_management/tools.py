"""
Fleet Management Tools for AWS.

This module provides tools for discovering and managing AWS resources.
"""

import json
import logging
from typing import Any, Dict

from ..tools import Tool, ToolSchema
from .discovery import discover_all_resources
from .models import ResourceRegistry

logger = logging.getLogger(__name__)

class FleetManagementTool(Tool):
    """Base class for fleet management tools."""
    
    async def _get_discovery_session(self, params):
        """Get or create AWS session for resource discovery."""
        # This will be implemented to use the MCP server's credential management
        return None


class DiscoverResourcesTool(FleetManagementTool):
    """Tool for discovering AWS resources."""
    
    name = "discover_resources"
    description = "Discover AWS resources across accounts and regions"
    
    schema = ToolSchema(
        properties={
            "resource_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Types of resources to discover (e.g. ec2, s3, rds)"
            },
            "regions": {
                "type": "array", 
                "items": {"type": "string"},
                "description": "AWS regions to scan"
            },
            "max_items": {
                "type": "integer",
                "description": "Maximum number of resources to return per type"
            }
        }
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the resource discovery tool."""
        session = await self._get_discovery_session(params)
        regions = params.get("regions")
        resource_types = params.get("resource_types")
        max_items = params.get("max_items", 100)
        
        try:
            # Run the discovery process
            resources = await discover_all_resources(
                session=session,
                regions=regions,
                resource_types=resource_types
            )
            
            # Format results
            result = {"discovered_resources": {}}
            
            # Count resources by type
            for resource_type, items in resources.items():
                count = len(items)
                sample = list(items.values())[:max_items] if isinstance(items, dict) else items[:max_items]
                
                result["discovered_resources"][resource_type] = {
                    "count": count,
                    "sample": sample
                }
            
            return json.dumps(result, indent=2)
        
        except Exception as e:
            logger.error(f"Error discovering resources: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetResourceDetailsTool(FleetManagementTool):
    """Tool for getting details about specific resources."""
    
    name = "get_resource_details"
    description = "Get detailed information about specific AWS resources"
    
    schema = ToolSchema(
        properties={
            "resource_id": {
                "type": "string",
                "description": "ID of the resource to get details for"
            },
            "resource_type": {
                "type": "string",
                "description": "Type of the resource (e.g. ec2:instance)"
            },
            "include_related": {
                "type": "boolean",
                "description": "Whether to include related resources"
            }
        },
        required=["resource_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get resource details tool."""
        resource_id = params.get("resource_id")
        include_related = params.get("include_related", False)
        
        try:
            # Get resource from registry
            resource = ResourceRegistry.get_resource(resource_id)
            
            if not resource:
                return json.dumps({"error": f"Resource not found: {resource_id}"})
            
            # Convert to dictionary
            result = {"resource": resource.to_dict()}
            
            # Include related resources if requested
            if include_related and resource.related_resources:
                related = {}
                for relation_type, related_ids in resource.related_resources.items():
                    related[relation_type] = []
                    for related_id in related_ids:
                        related_resource = ResourceRegistry.get_resource(related_id)
                        if related_resource:
                            related[relation_type].append(related_resource.to_dict())
                
                result["related_resources"] = related
            
            return json.dumps(result, indent=2)
        
        except Exception as e:
            logger.error(f"Error getting resource details: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class SearchResourcesTool(FleetManagementTool):
    """Tool for searching resources by various criteria."""
    
    name = "search_resources"
    description = "Search for AWS resources by various criteria"
    
    schema = ToolSchema(
        properties={
            "resource_type": {
                "type": "string",
                "description": "Type of resources to search for"
            },
            "tags": {
                "type": "object",
                "description": "Tags to filter by (key-value pairs)"
            },
            "state": {
                "type": "string",
                "description": "Resource state to filter by"
            },
            "region": {
                "type": "string",
                "description": "AWS region to filter by"
            },
            "name_pattern": {
                "type": "string",
                "description": "Pattern to match resource names against"
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of results to return"
            }
        }
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the search resources tool."""
        resource_type = params.get("resource_type")
        tags = params.get("tags", {})
        state = params.get("state")
        region = params.get("region")
        name_pattern = params.get("name_pattern")
        max_results = params.get("max_results", 50)
        
        try:
            # Get all resources of the specified type
            if resource_type:
                resources = ResourceRegistry.get_resources_by_type(resource_type)
            else:
                resources = list(ResourceRegistry._instances.values())
            
            # Apply filters
            filtered = []
            for resource in resources:
                # Filter by state
                if state and resource.state != state:
                    continue
                
                # Filter by region
                if region and resource.region != region:
                    continue
                
                # Filter by name pattern
                if name_pattern and resource.name:
                    if name_pattern not in resource.name:
                        continue
                
                # Filter by tags
                if tags:
                    match = True
                    resource_tags = {tag.key: tag.value for tag in resource.tags}
                    for key, value in tags.items():
                        if key not in resource_tags or resource_tags[key] != value:
                            match = False
                            break
                    if not match:
                        continue
                
                filtered.append(resource)
            
            # Limit results
            results = filtered[:max_results]
            
            # Format output
            output = {
                "total_matches": len(filtered),
                "returned": len(results),
                "resources": [r.to_dict() for r in results]
            }
            
            return json.dumps(output, indent=2)
        
        except Exception as e:
            logger.error(f"Error searching resources: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


# List of tools to register with the server
fleet_management_tools = [
    DiscoverResourcesTool(),
    GetResourceDetailsTool(),
    SearchResourcesTool(),
] 