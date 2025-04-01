"""
Configuration Management Tools for AWS MCP Server.

This module provides tools for integrating configuration management capabilities
with the AWS MCP Server's Model Context Protocol.
"""

import json
import logging
from typing import Dict, List, Any, Optional

from ..tools import Tool, ToolSchema
from .configuration import ConfigManager, ConfigRegistry, ConfigType, ConfigStatus

logger = logging.getLogger(__name__)


class ConfigurationTool(Tool):
    """Base class for configuration management tools."""
    pass


class ListConfigSetsToool(ConfigurationTool):
    """Tool for listing available configuration sets."""
    
    name = "list_config_sets"
    description = "List available configuration sets for AWS resources"
    
    schema = ToolSchema(
        properties={
            "config_type": {
                "type": "string",
                "description": "Type of configuration sets to list (e.g., global, account, region)"
            },
            "scope": {
                "type": "string",
                "description": "Optional scope to filter by (e.g., account ID, region name)"
            },
            "include_archived": {
                "type": "boolean",
                "description": "Whether to include archived configuration sets"
            }
        }
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the list configuration sets tool."""
        try:
            # Parse the config type
            config_type_str = params.get("config_type", "").upper()
            config_type = None
            if config_type_str:
                try:
                    config_type = ConfigType[config_type_str]
                except KeyError:
                    return json.dumps({
                        "error": f"Invalid configuration type: {config_type_str}"
                    })
            
            scope = params.get("scope")
            include_archived = params.get("include_archived", False)
            
            # Get configuration sets
            if config_type and scope:
                configs = ConfigRegistry.get_config_sets_by_scope(config_type, scope)
            elif config_type:
                configs = ConfigRegistry.get_config_sets_by_type(config_type)
            else:
                configs = list(ConfigRegistry._config_sets.values())
            
            # Filter archived if needed
            if not include_archived:
                configs = [
                    config for config in configs
                    if config.status != ConfigStatus.ARCHIVED
                ]
            
            # Format for output
            result = {
                "config_sets": [
                    {
                        "id": config.id,
                        "name": config.name,
                        "type": config.config_type.value,
                        "scope": config.scope,
                        "status": config.status.value,
                        "items_count": len(config.items)
                    }
                    for config in configs
                ],
                "count": len(configs)
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing configuration sets: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetConfigSetTool(ConfigurationTool):
    """Tool for getting details of a configuration set."""
    
    name = "get_config_set"
    description = "Get details of a specific configuration set"
    
    schema = ToolSchema(
        properties={
            "config_id": {
                "type": "string",
                "description": "ID of the configuration set"
            },
            "include_history": {
                "type": "boolean",
                "description": "Whether to include configuration history"
            }
        },
        required=["config_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get configuration set tool."""
        try:
            config_id = params.get("config_id")
            include_history = params.get("include_history", False)
            
            config_set = ConfigRegistry.get_config_set(config_id)
            if not config_set:
                return json.dumps({
                    "error": f"Configuration set not found: {config_id}"
                })
            
            # Get children if any
            children = ConfigRegistry.get_config_children(config_id)
            
            result = {
                "config_set": config_set.to_dict(include_history),
                "children_count": len(children),
                "children": [
                    {
                        "id": child.id,
                        "name": child.name,
                        "type": child.config_type.value,
                        "scope": child.scope
                    }
                    for child in children
                ]
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting configuration set: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class CreateConfigSetTool(ConfigurationTool):
    """Tool for creating a new configuration set."""
    
    name = "create_config_set"
    description = "Create a new configuration set"
    
    schema = ToolSchema(
        properties={
            "name": {
                "type": "string",
                "description": "Name for the configuration set"
            },
            "config_type": {
                "type": "string",
                "description": "Type of configuration (e.g., global, account, region)"
            },
            "scope": {
                "type": "string",
                "description": "Scope identifier (e.g., account ID, region name)"
            },
            "parent_id": {
                "type": "string",
                "description": "ID of the parent configuration set (optional)"
            },
            "initial_values": {
                "type": "object",
                "description": "Initial configuration values as key-value pairs"
            }
        },
        required=["name", "config_type", "scope"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the create configuration set tool."""
        try:
            name = params.get("name")
            config_type_str = params.get("config_type", "").upper()
            scope = params.get("scope")
            parent_id = params.get("parent_id")
            initial_values = params.get("initial_values", {})
            
            # Parse the config type
            try:
                config_type = ConfigType[config_type_str]
            except KeyError:
                return json.dumps({
                    "error": f"Invalid configuration type: {config_type_str}"
                })
            
            # Validate parent if provided
            if parent_id:
                parent = ConfigRegistry.get_config_set(parent_id)
                if not parent:
                    return json.dumps({
                        "error": f"Parent configuration set not found: {parent_id}"
                    })
            
            # Create the configuration set
            config_set = ConfigManager.create_config_set(
                name=name,
                config_type=config_type,
                scope=scope,
                parent_id=parent_id
            )
            
            # Set initial values
            for key, value in initial_values.items():
                encrypted = key.startswith("secret.") or key.endswith(".secret")
                ConfigManager.set_config_value(
                    config_id=config_set.id,
                    key=key,
                    value=value,
                    user="api",
                    encrypted=encrypted
                )
            
            return json.dumps({
                "config_id": config_set.id,
                "name": config_set.name,
                "type": config_set.config_type.value,
                "scope": config_set.scope,
                "parent_id": config_set.parent_id,
                "items_count": len(config_set.items)
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error creating configuration set: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class SetConfigValueTool(ConfigurationTool):
    """Tool for setting a configuration value."""
    
    name = "set_config_value"
    description = "Set a value in a configuration set"
    
    schema = ToolSchema(
        properties={
            "config_id": {
                "type": "string",
                "description": "ID of the configuration set"
            },
            "key": {
                "type": "string",
                "description": "Configuration key"
            },
            "value": {
                "type": "string",
                "description": "Configuration value"
            },
            "encrypted": {
                "type": "boolean",
                "description": "Whether the value should be encrypted"
            },
            "description": {
                "type": "string",
                "description": "Optional description of the change"
            }
        },
        required=["config_id", "key", "value"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the set configuration value tool."""
        try:
            config_id = params.get("config_id")
            key = params.get("key")
            value = params.get("value")
            encrypted = params.get("encrypted", False)
            description = params.get("description", "")
            
            # Auto-detect sensitive values if not explicitly specified
            if not encrypted:
                encrypted = key.startswith("secret.") or key.endswith(".secret")
            
            # Set the configuration value
            result = ConfigManager.set_config_value(
                config_id=config_id,
                key=key,
                value=value,
                user="api",
                encrypted=encrypted,
                description=description
            )
            
            if not result:
                return json.dumps({
                    "error": f"Failed to set configuration value. Configuration set not found: {config_id}"
                })
            
            return json.dumps({
                "success": True,
                "message": f"Configuration value set: {key}"
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error setting configuration value: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetConfigValueTool(ConfigurationTool):
    """Tool for getting a configuration value."""
    
    name = "get_config_value"
    description = "Get a value from a configuration set"
    
    schema = ToolSchema(
        properties={
            "config_id": {
                "type": "string",
                "description": "ID of the configuration set"
            },
            "key": {
                "type": "string",
                "description": "Configuration key"
            }
        },
        required=["config_id", "key"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get configuration value tool."""
        try:
            config_id = params.get("config_id")
            key = params.get("key")
            
            # Get the configuration value
            value = ConfigManager.get_config_value(config_id, key)
            
            if value is None:
                return json.dumps({
                    "error": f"Configuration value not found: {key}"
                })
            
            return json.dumps({
                "key": key,
                "value": value
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting configuration value: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetEffectiveConfigTool(ConfigurationTool):
    """Tool for getting effective configuration by resolving inheritance."""
    
    name = "get_effective_config"
    description = "Get effective configuration for a scope with inheritance resolved"
    
    schema = ToolSchema(
        properties={
            "config_type": {
                "type": "string",
                "description": "Type of configuration (e.g., global, account, region)"
            },
            "scope": {
                "type": "string",
                "description": "Scope identifier (e.g., account ID, region name)"
            },
            "keys": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of specific keys to retrieve"
            }
        },
        required=["config_type", "scope"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get effective configuration tool."""
        try:
            config_type_str = params.get("config_type", "").upper()
            scope = params.get("scope")
            keys = params.get("keys")
            
            # Parse the config type
            try:
                config_type = ConfigType[config_type_str]
            except KeyError:
                return json.dumps({
                    "error": f"Invalid configuration type: {config_type_str}"
                })
            
            # Get the effective configuration
            config = ConfigManager.get_effective_config(config_type, scope, keys)
            
            return json.dumps({
                "config_type": config_type.value,
                "scope": scope,
                "effective_config": config,
                "keys_count": len(config)
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting effective configuration: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class DeleteConfigValueTool(ConfigurationTool):
    """Tool for deleting a configuration value."""
    
    name = "delete_config_value"
    description = "Delete a value from a configuration set"
    
    schema = ToolSchema(
        properties={
            "config_id": {
                "type": "string",
                "description": "ID of the configuration set"
            },
            "key": {
                "type": "string",
                "description": "Configuration key to delete"
            },
            "description": {
                "type": "string",
                "description": "Optional description of why the value is being deleted"
            }
        },
        required=["config_id", "key"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the delete configuration value tool."""
        try:
            config_id = params.get("config_id")
            key = params.get("key")
            description = params.get("description", "")
            
            # Delete the configuration value
            result = ConfigManager.delete_config_value(
                config_id=config_id,
                key=key,
                user="api",
                description=description
            )
            
            if not result:
                return json.dumps({
                    "error": f"Failed to delete configuration value. Configuration set not found or key not present: {config_id}/{key}"
                })
            
            return json.dumps({
                "success": True,
                "message": f"Configuration value deleted: {key}"
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error deleting configuration value: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


# List of configuration tools to register with the server
configuration_tools = [
    ListConfigSetsToool(),
    GetConfigSetTool(),
    CreateConfigSetTool(),
    SetConfigValueTool(),
    GetConfigValueTool(),
    GetEffectiveConfigTool(),
    DeleteConfigValueTool(),
] 