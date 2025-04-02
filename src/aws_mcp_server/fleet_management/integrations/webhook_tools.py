"""
Webhook Tools for AWS MCP Server.

This module provides tools for integrating webhook capabilities
with the AWS MCP Server's Model Context Protocol.
"""

import json
import logging
from typing import Dict, List, Any, Optional

from ..tools import Tool, ToolSchema
from .integration import IntegrationConfig, IntegrationType, Direction, AuthType, AuthConfig
from .webhooks import (
    WebhookRegistry, Webhook, WebhookConfig, WebhookMethod, WebhookContentType,
    SignatureMethod, WebhookSignatureConfig, WebhookHandler
)
from .integration_tools import integration_registry

logger = logging.getLogger(__name__)


class CreateWebhookTool(Tool):
    """Tool for creating a new webhook."""
    
    def __init__(self, webhook_registry: WebhookRegistry):
        """
        Initialize the tool.
        
        Args:
            webhook_registry: Registry for managing webhooks
        """
        super().__init__(
            name="create_webhook",
            schema=ToolSchema(
                description="Create a new webhook for receiving data from external systems",
                parameters={
                    "name": {
                        "description": "Name of the webhook",
                        "type": "string"
                    },
                    "description": {
                        "description": "Description of the webhook",
                        "type": "string"
                    },
                    "path": {
                        "description": "URL path to expose the webhook on",
                        "type": "string"
                    },
                    "methods": {
                        "description": "HTTP methods to accept",
                        "type": "array",
                        "items": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
                        "default": ["POST"]
                    },
                    "content_types": {
                        "description": "Content types to accept",
                        "type": "array",
                        "items": {
                            "type": "string", 
                            "enum": [
                                "application/json", 
                                "application/xml", 
                                "application/x-www-form-urlencoded",
                                "multipart/form-data",
                                "text/plain",
                                "text/html",
                                "application/octet-stream"
                            ]
                        },
                        "default": ["application/json"]
                    },
                    "signature_enabled": {
                        "description": "Whether to enable signature verification",
                        "type": "boolean",
                        "default": False
                    },
                    "signature_method": {
                        "description": "Signature verification method",
                        "type": "string",
                        "enum": [
                            "hmac-sha256", 
                            "hmac-sha1", 
                            "hmac-md5", 
                            "basic-auth", 
                            "api-key", 
                            "custom"
                        ],
                        "default": "hmac-sha256"
                    },
                    "signature_secret_key": {
                        "description": "Secret key for signature verification",
                        "type": "string"
                    },
                    "signature_header": {
                        "description": "Header name for signature",
                        "type": "string",
                        "default": "X-Signature"
                    },
                    "include_timestamp": {
                        "description": "Whether to include timestamp in signature verification",
                        "type": "boolean",
                        "default": False
                    },
                    "timestamp_header": {
                        "description": "Header name for timestamp",
                        "type": "string",
                        "default": "X-Timestamp"
                    },
                    "rate_limit": {
                        "description": "Rate limit in requests per minute",
                        "type": "integer",
                        "default": 60
                    },
                    "timeout_seconds": {
                        "description": "Request timeout in seconds",
                        "type": "integer",
                        "default": 30
                    },
                    "tags": {
                        "description": "Tags for the webhook",
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
                    "description": "Result of webhook creation",
                    "type": "object",
                    "properties": {
                        "webhook_id": {"type": "string"},
                        "name": {"type": "string"},
                        "path": {"type": "string"},
                        "status": {"type": "string"}
                    }
                }
            )
        )
        self.webhook_registry = webhook_registry
    
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
            path = parameters.get("path")
            
            if not name:
                return {"error": "Webhook name is required"}
                
            if not description:
                return {"error": "Webhook description is required"}
                
            if not path:
                return {"error": "Webhook path is required"}
            
            # Normalize path (ensure it starts with /)
            if not path.startswith("/"):
                path = f"/{path}"
            
            # Parse methods
            methods = []
            for method in parameters.get("methods", ["POST"]):
                methods.append(WebhookMethod(method))
            
            # Parse content types
            content_types = []
            for content_type in parameters.get("content_types", ["application/json"]):
                content_types.append(WebhookContentType(content_type))
            
            # Create signature config
            signature_config = WebhookSignatureConfig(
                enabled=parameters.get("signature_enabled", False),
                method=SignatureMethod(parameters.get("signature_method", "hmac-sha256")),
                secret_key=parameters.get("signature_secret_key"),
                header_name=parameters.get("signature_header", "X-Signature"),
                include_timestamp=parameters.get("include_timestamp", False),
                timestamp_header=parameters.get("timestamp_header", "X-Timestamp")
            )
            
            # Create webhook config
            webhook_config = WebhookConfig(
                path=path,
                methods=methods,
                content_types=content_types,
                signature=signature_config,
                description=description,
                tags=parameters.get("tags", {}),
                metadata=parameters.get("metadata", {}),
                rate_limit_per_minute=parameters.get("rate_limit", 60),
                timeout_seconds=parameters.get("timeout_seconds", 30)
            )
            
            # Create integration config (webhooks are a type of integration)
            integration_config = IntegrationConfig(
                name=name,
                description=description,
                type=IntegrationType.WEBHOOK,
                direction=Direction.INBOUND,
                version="1.0.0",
                tags=parameters.get("tags", {}),
                metadata=parameters.get("metadata", {})
            )
            
            # Register webhook
            webhook_id = await self.webhook_registry.register_webhook(
                integration_config,
                webhook_config
            )
            
            # Get webhook to return status
            webhooks = await self.webhook_registry.get_webhooks_for_path(path)
            webhook = next((w for w in webhooks if w.id == webhook_id), None)
            
            return {
                "webhook_id": webhook_id,
                "name": name,
                "path": path,
                "status": webhook.status.value if webhook else "unknown"
            }
        except Exception as e:
            logger.error(f"Error creating webhook: {str(e)}")
            return {"error": str(e)}


class DeleteWebhookTool(Tool):
    """Tool for deleting a webhook."""
    
    def __init__(self, webhook_registry: WebhookRegistry):
        """
        Initialize the tool.
        
        Args:
            webhook_registry: Registry for managing webhooks
        """
        super().__init__(
            name="delete_webhook",
            schema=ToolSchema(
                description="Delete a webhook",
                parameters={
                    "webhook_id": {
                        "description": "ID of the webhook to delete",
                        "type": "string"
                    }
                },
                returns={
                    "description": "Result of webhook deletion",
                    "type": "object",
                    "properties": {
                        "webhook_id": {"type": "string"},
                        "success": {"type": "boolean"},
                        "message": {"type": "string"}
                    }
                }
            )
        )
        self.webhook_registry = webhook_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            webhook_id = parameters.get("webhook_id")
            
            if not webhook_id:
                return {"error": "Webhook ID is required"}
            
            # Delete webhook
            success = await self.webhook_registry.unregister_webhook(webhook_id)
            
            if success:
                return {
                    "webhook_id": webhook_id,
                    "success": True,
                    "message": "Webhook deleted successfully"
                }
            else:
                return {
                    "error": f"Failed to delete webhook: {webhook_id}"
                }
        except Exception as e:
            logger.error(f"Error deleting webhook: {str(e)}")
            return {"error": str(e)}


class ListWebhooksTool(Tool):
    """Tool for listing webhooks."""
    
    def __init__(self, webhook_registry: WebhookRegistry):
        """
        Initialize the tool.
        
        Args:
            webhook_registry: Registry for managing webhooks
        """
        super().__init__(
            name="list_webhooks",
            schema=ToolSchema(
                description="List all webhooks",
                parameters={
                    "path": {
                        "description": "Filter by path",
                        "type": "string"
                    }
                },
                returns={
                    "description": "List of webhooks",
                    "type": "array"
                }
            )
        )
        self.webhook_registry = webhook_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            path = parameters.get("path")
            
            if path:
                # Get webhooks for specific path
                webhooks = await self.webhook_registry.get_webhooks_for_path(path)
            else:
                # Get all webhooks
                webhooks = await self.integration_registry.get_integrations(
                    type_filter=IntegrationType.WEBHOOK
                )
            
            # Convert to dictionaries
            result = []
            for webhook in webhooks:
                if isinstance(webhook, Webhook):
                    webhook_dict = await webhook.to_dict()
                    result.append(webhook_dict)
            
            return result
        except Exception as e:
            logger.error(f"Error listing webhooks: {str(e)}")
            return [{"error": str(e)}]


class GetWebhookEventsTool(Tool):
    """Tool for getting webhook events."""
    
    def __init__(self, webhook_registry: WebhookRegistry):
        """
        Initialize the tool.
        
        Args:
            webhook_registry: Registry for managing webhooks
        """
        super().__init__(
            name="get_webhook_events",
            schema=ToolSchema(
                description="Get recent events for a webhook",
                parameters={
                    "webhook_id": {
                        "description": "ID of the webhook",
                        "type": "string"
                    },
                    "limit": {
                        "description": "Maximum number of events to return",
                        "type": "integer",
                        "default": 10
                    }
                },
                returns={
                    "description": "Webhook events",
                    "type": "object",
                    "properties": {
                        "webhook_id": {"type": "string"},
                        "name": {"type": "string"},
                        "events": {"type": "array"}
                    }
                }
            )
        )
        self.webhook_registry = webhook_registry
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            webhook_id = parameters.get("webhook_id")
            limit = parameters.get("limit", 10)
            
            if not webhook_id:
                return {"error": "Webhook ID is required"}
            
            # Get webhook
            webhook = await self.integration_registry.get_integration(webhook_id)
            
            if not webhook or not isinstance(webhook, Webhook):
                return {"error": f"Webhook with ID {webhook_id} not found"}
            
            # Get events (most recent first)
            events = list(reversed(webhook.events[-limit:]))
            
            # Convert to dictionaries
            event_dicts = []
            for event in events:
                event_dict = {
                    "request_id": event.request_id,
                    "timestamp": event.timestamp.isoformat(),
                    "success": event.success,
                    "status_code": event.status_code,
                    "execution_time_ms": event.execution_time_ms
                }
                
                if event.error_message:
                    event_dict["error_message"] = event.error_message
                    
                event_dicts.append(event_dict)
            
            return {
                "webhook_id": webhook_id,
                "name": webhook.config.name,
                "events": event_dicts
            }
        except Exception as e:
            logger.error(f"Error getting webhook events: {str(e)}")
            return {"error": str(e)}


# Create webhook registry that will be initialized with integration registry
webhook_registry = WebhookRegistry(integration_registry)

# Define list of webhook tools
webhook_tools = [
    CreateWebhookTool(webhook_registry),
    DeleteWebhookTool(webhook_registry),
    ListWebhooksTool(webhook_registry),
    GetWebhookEventsTool(webhook_registry)
] 