"""
Integration Tools for AWS MCP Server.

This module provides tools for managing integrations with external systems.
"""

import json
import logging
import asyncio
from typing import Dict, List, Any, Optional

from ..tools import Tool, ToolSchema
from .integration import IntegrationRegistry, Integration, IntegrationConfig
from .integration import IntegrationType, Direction, AuthType, AuthConfig

logger = logging.getLogger(__name__)


class CreateIntegrationTool(Tool):
    """Tool for creating a new external system integration."""
    
    def __init__(self, integration_registry: IntegrationRegistry):
        """
        Initialize the tool.
        
        Args:
            integration_registry: Registry for managing integrations
        """
        super().__init__(
            name="create_integration",
            schema=ToolSchema(
                description="Create a new integration with an external system",
                parameters={
                    "name": {
                        "description": "Name of the integration",
                        "type": "string"
                    },
                    "description": {
                        "description": "Description of the integration",
                        "type": "string"
                    },
                    "type": {
                        "description": "Type of integration",
                        "type": "string",
                        "enum": [t.value for t in IntegrationType]
                    },
                    "direction": {
                        "description": "Data flow direction",
                        "type": "string",
                        "enum": [d.value for d in Direction],
                        "default": "bidirectional"
                    },
                    "version": {
                        "description": "Integration version",
                        "type": "string",
                        "default": "1.0.0"
                    },
                    "auth_type": {
                        "description": "Authentication type",
                        "type": "string",
                        "enum": [a.value for a in AuthType],
                        "default": "none"
                    },
                    "auth_config": {
                        "description": "Authentication configuration",
                        "type": "object",
                        "default": {}
                    },
                    "credentials_key": {
                        "description": "Key to use for retrieving credentials",
                        "type": "string"
                    },
                    "health_check_enabled": {
                        "description": "Whether health checks are enabled",
                        "type": "boolean",
                        "default": True
                    },
                    "health_check_interval": {
                        "description": "Health check interval in seconds",
                        "type": "integer",
                        "default": 300
                    },
                    "health_check_endpoint": {
                        "description": "Health check endpoint",
                        "type": "string"
                    },
                    "timeout_seconds": {
                        "description": "Request timeout in seconds",
                        "type": "integer",
                        "default": 30
                    },
                    "rate_limit": {
                        "description": "Rate limit in requests per minute",
                        "type": "integer",
                        "default": 60
                    },
                    "retry_enabled": {
                        "description": "Whether retries are enabled",
                        "type": "boolean",
                        "default": True
                    },
                    "retry_max_attempts": {
                        "description": "Maximum retry attempts",
                        "type": "integer",
                        "default": 3
                    },
                    "tags": {
                        "description": "Tags for the integration",
                        "type": "object",
                        "default": {}
                    },
                    "metadata": {
                        "description": "Additional metadata",
                        "type": "object",
                        "default": {}
                    }
                },
                returns={
                    "description": "Result of integration creation",
                    "type": "object",
                    "properties": {
                        "integration_id": {"type": "string"},
                        "name": {"type": "string"},
                        "type": {"type": "string"},
                        "status": {"type": "string"}
                    }
                }
            )
        )
        self.integration_registry = integration_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            name = parameters.get("name")
            description = parameters.get("description")
            
            if not name:
                return {"error": "Integration name is required"}
                
            if not description:
                return {"error": "Integration description is required"}
            
            # Create auth config
            auth_config = AuthConfig(
                type=AuthType(parameters.get("auth_type", "none")),
                credentials_key=parameters.get("credentials_key"),
                config=parameters.get("auth_config", {})
            )
            
            # Create health check config
            health_check_config = {
                "enabled": parameters.get("health_check_enabled", True),
                "interval_seconds": parameters.get("health_check_interval", 300)
            }
            
            if "health_check_endpoint" in parameters:
                health_check_config["endpoint"] = parameters["health_check_endpoint"]
            
            # Create retry config
            retry_config = {
                "enabled": parameters.get("retry_enabled", True),
                "max_attempts": parameters.get("retry_max_attempts", 3)
            }
            
            # Create integration config
            config = IntegrationConfig(
                name=name,
                description=description,
                type=IntegrationType(parameters.get("type")),
                direction=Direction(parameters.get("direction", "bidirectional")),
                version=parameters.get("version", "1.0.0"),
                auth=auth_config,
                health_check=health_check_config,
                retry=retry_config,
                timeout_seconds=parameters.get("timeout_seconds", 30),
                rate_limit_per_minute=parameters.get("rate_limit", 60),
                tags=parameters.get("tags", {}),
                metadata=parameters.get("metadata", {})
            )
            
            # Register integration
            integration_id = await self.integration_registry.register_integration(config)
            
            # Get integration to return its status
            integration = await self.integration_registry.get_integration(integration_id)
            
            return {
                "integration_id": integration_id,
                "name": name,
                "type": parameters.get("type"),
                "status": integration.status.value if integration else "unknown"
            }
        except Exception as e:
            logger.error(f"Error creating integration: {str(e)}")
            return {"error": str(e)}


class UpdateIntegrationTool(Tool):
    """Tool for updating an existing integration."""
    
    def __init__(self, integration_registry: IntegrationRegistry):
        """
        Initialize the tool.
        
        Args:
            integration_registry: Registry for managing integrations
        """
        super().__init__(
            name="update_integration",
            schema=ToolSchema(
                description="Update an existing integration",
                parameters={
                    "integration_id": {
                        "description": "ID of the integration to update",
                        "type": "string"
                    },
                    "name": {
                        "description": "Name of the integration",
                        "type": "string"
                    },
                    "description": {
                        "description": "Description of the integration",
                        "type": "string"
                    },
                    "version": {
                        "description": "Integration version",
                        "type": "string"
                    },
                    "auth_type": {
                        "description": "Authentication type",
                        "type": "string",
                        "enum": [a.value for a in AuthType]
                    },
                    "auth_config": {
                        "description": "Authentication configuration",
                        "type": "object"
                    },
                    "credentials_key": {
                        "description": "Key to use for retrieving credentials",
                        "type": "string"
                    },
                    "health_check_enabled": {
                        "description": "Whether health checks are enabled",
                        "type": "boolean"
                    },
                    "health_check_interval": {
                        "description": "Health check interval in seconds",
                        "type": "integer"
                    },
                    "health_check_endpoint": {
                        "description": "Health check endpoint",
                        "type": "string"
                    },
                    "timeout_seconds": {
                        "description": "Request timeout in seconds",
                        "type": "integer"
                    },
                    "rate_limit": {
                        "description": "Rate limit in requests per minute",
                        "type": "integer"
                    },
                    "retry_enabled": {
                        "description": "Whether retries are enabled",
                        "type": "boolean"
                    },
                    "retry_max_attempts": {
                        "description": "Maximum retry attempts",
                        "type": "integer"
                    },
                    "tags": {
                        "description": "Tags for the integration",
                        "type": "object"
                    },
                    "metadata": {
                        "description": "Additional metadata",
                        "type": "object"
                    }
                },
                returns={
                    "description": "Result of integration update",
                    "type": "object",
                    "properties": {
                        "integration_id": {"type": "string"},
                        "name": {"type": "string"},
                        "status": {"type": "string"}
                    }
                }
            )
        )
        self.integration_registry = integration_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            integration_id = parameters.get("integration_id")
            
            if not integration_id:
                return {"error": "Integration ID is required"}
            
            # Get existing integration
            integration = await self.integration_registry.get_integration(integration_id)
            
            if not integration:
                return {"error": f"Integration with ID {integration_id} not found"}
            
            # Create new config based on existing config
            config = integration.config
            
            # Update fields if provided
            if "name" in parameters:
                config.name = parameters["name"]
                
            if "description" in parameters:
                config.description = parameters["description"]
                
            if "version" in parameters:
                config.version = parameters["version"]
                
            # Update auth config if required fields provided
            if "auth_type" in parameters:
                config.auth.type = AuthType(parameters["auth_type"])
                
            if "credentials_key" in parameters:
                config.auth.credentials_key = parameters["credentials_key"]
                
            if "auth_config" in parameters:
                config.auth.config = parameters["auth_config"]
            
            # Update health check config
            if "health_check_enabled" in parameters:
                config.health_check["enabled"] = parameters["health_check_enabled"]
                
            if "health_check_interval" in parameters:
                config.health_check["interval_seconds"] = parameters["health_check_interval"]
                
            if "health_check_endpoint" in parameters:
                config.health_check["endpoint"] = parameters["health_check_endpoint"]
            
            # Update retry config
            if "retry_enabled" in parameters:
                config.retry["enabled"] = parameters["retry_enabled"]
                
            if "retry_max_attempts" in parameters:
                config.retry["max_attempts"] = parameters["retry_max_attempts"]
            
            # Update other fields
            if "timeout_seconds" in parameters:
                config.timeout_seconds = parameters["timeout_seconds"]
                
            if "rate_limit" in parameters:
                config.rate_limit_per_minute = parameters["rate_limit"]
                
            if "tags" in parameters:
                config.tags = parameters["tags"]
                
            if "metadata" in parameters:
                config.metadata = parameters["metadata"]
            
            # Update integration
            success = await self.integration_registry.update_integration(integration_id, config)
            
            if not success:
                return {"error": f"Failed to update integration {integration_id}"}
            
            # Get updated integration
            integration = await self.integration_registry.get_integration(integration_id)
            
            return {
                "integration_id": integration_id,
                "name": config.name,
                "status": integration.status.value if integration else "unknown"
            }
        except Exception as e:
            logger.error(f"Error updating integration: {str(e)}")
            return {"error": str(e)}


class DeleteIntegrationTool(Tool):
    """Tool for deleting an integration."""
    
    def __init__(self, integration_registry: IntegrationRegistry):
        """
        Initialize the tool.
        
        Args:
            integration_registry: Registry for managing integrations
        """
        super().__init__(
            name="delete_integration",
            schema=ToolSchema(
                description="Delete an integration",
                parameters={
                    "integration_id": {
                        "description": "ID of the integration to delete",
                        "type": "string"
                    }
                },
                returns={
                    "description": "Result of integration deletion",
                    "type": "object",
                    "properties": {
                        "integration_id": {"type": "string"},
                        "success": {"type": "boolean"},
                        "message": {"type": "string"}
                    }
                }
            )
        )
        self.integration_registry = integration_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            integration_id = parameters.get("integration_id")
            
            if not integration_id:
                return {"error": "Integration ID is required"}
            
            # Get existing integration (for logging)
            integration = await self.integration_registry.get_integration(integration_id)
            
            if not integration:
                return {
                    "integration_id": integration_id,
                    "success": False,
                    "message": f"Integration with ID {integration_id} not found"
                }
            
            # Delete integration
            success = await self.integration_registry.delete_integration(integration_id)
            
            if success:
                return {
                    "integration_id": integration_id,
                    "success": True,
                    "message": f"Integration {integration.config.name} deleted successfully"
                }
            else:
                return {
                    "integration_id": integration_id,
                    "success": False,
                    "message": f"Failed to delete integration {integration_id}"
                }
        except Exception as e:
            logger.error(f"Error deleting integration: {str(e)}")
            return {"error": str(e)}


class GetIntegrationTool(Tool):
    """Tool for getting integration details."""
    
    def __init__(self, integration_registry: IntegrationRegistry):
        """
        Initialize the tool.
        
        Args:
            integration_registry: Registry for managing integrations
        """
        super().__init__(
            name="get_integration",
            schema=ToolSchema(
                description="Get details of a specific integration",
                parameters={
                    "integration_id": {
                        "description": "ID of the integration to get",
                        "type": "string"
                    }
                },
                returns={
                    "description": "Integration details",
                    "type": "object"
                }
            )
        )
        self.integration_registry = integration_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            integration_id = parameters.get("integration_id")
            
            if not integration_id:
                return {"error": "Integration ID is required"}
            
            # Get integration
            integration = await self.integration_registry.get_integration(integration_id)
            
            if not integration:
                return {"error": f"Integration with ID {integration_id} not found"}
            
            # Convert to dictionary
            integration_dict = await integration.to_dict()
            
            return integration_dict
        except Exception as e:
            logger.error(f"Error getting integration: {str(e)}")
            return {"error": str(e)}


class ListIntegrationsTool(Tool):
    """Tool for listing integrations."""
    
    def __init__(self, integration_registry: IntegrationRegistry):
        """
        Initialize the tool.
        
        Args:
            integration_registry: Registry for managing integrations
        """
        super().__init__(
            name="list_integrations",
            schema=ToolSchema(
                description="List all integrations or filter by type and status",
                parameters={
                    "type": {
                        "description": "Filter by integration type",
                        "type": "string",
                        "enum": [t.value for t in IntegrationType]
                    },
                    "status": {
                        "description": "Filter by integration status",
                        "type": "string",
                        "enum": ["active", "inactive", "error", "configuring", "testing", "deprecated"]
                    },
                    "enabled_only": {
                        "description": "Only return enabled integrations",
                        "type": "boolean",
                        "default": False
                    }
                },
                returns={
                    "description": "List of integrations",
                    "type": "array"
                }
            )
        )
        self.integration_registry = integration_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            # Get filter parameters
            type_filter = None
            if "type" in parameters:
                type_filter = IntegrationType(parameters["type"])
                
            status_filter = None
            if "status" in parameters:
                from .integration import IntegrationStatus
                status_filter = IntegrationStatus(parameters["status"])
                
            enabled_only = parameters.get("enabled_only", False)
            
            # Get integrations
            integrations = await self.integration_registry.get_integrations(
                type_filter=type_filter,
                status_filter=status_filter,
                enabled_only=enabled_only
            )
            
            # Convert to dictionaries
            result = []
            for integration in integrations:
                integration_dict = await integration.to_dict()
                result.append(integration_dict)
            
            return result
        except Exception as e:
            logger.error(f"Error listing integrations: {str(e)}")
            return [{"error": str(e)}]


class CheckIntegrationHealthTool(Tool):
    """Tool for checking integration health."""
    
    def __init__(self, integration_registry: IntegrationRegistry):
        """
        Initialize the tool.
        
        Args:
            integration_registry: Registry for managing integrations
        """
        super().__init__(
            name="check_integration_health",
            schema=ToolSchema(
                description="Check the health of an integration",
                parameters={
                    "integration_id": {
                        "description": "ID of the integration to check",
                        "type": "string"
                    }
                },
                returns={
                    "description": "Health check result",
                    "type": "object",
                    "properties": {
                        "integration_id": {"type": "string"},
                        "name": {"type": "string"},
                        "healthy": {"type": "boolean"},
                        "status": {"type": "string"},
                        "last_check": {"type": "string"},
                        "message": {"type": "string"}
                    }
                }
            )
        )
        self.integration_registry = integration_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            integration_id = parameters.get("integration_id")
            
            if not integration_id:
                return {"error": "Integration ID is required"}
            
            # Get integration
            integration = await self.integration_registry.get_integration(integration_id)
            
            if not integration:
                return {"error": f"Integration with ID {integration_id} not found"}
            
            # Perform health check
            is_healthy = await integration.health_check()
            
            # Get status after health check
            status = integration.status.value
            
            # Determine last check time
            last_check = integration.last_success or integration.last_failure
            
            # Create message
            if is_healthy:
                message = f"Integration is healthy with status {status}"
            else:
                message = f"Integration is unhealthy with status {status}"
                if integration.failure_count > 0:
                    message += f" after {integration.failure_count} consecutive failures"
            
            return {
                "integration_id": integration_id,
                "name": integration.config.name,
                "healthy": is_healthy,
                "status": status,
                "last_check": last_check.isoformat() if last_check else None,
                "message": message
            }
        except Exception as e:
            logger.error(f"Error checking integration health: {str(e)}")
            return {"error": str(e)}


# Create an empty registry that will be initialized later
integration_registry = IntegrationRegistry()

# Define list of integration tools
integration_tools = [] 