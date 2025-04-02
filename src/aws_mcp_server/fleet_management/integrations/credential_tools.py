"""
Credential Tools for AWS MCP Server.

This module provides tools for managing secure credentials for external system integrations.
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from ..tools import Tool, ToolSchema
from .credentials import (
    CredentialManager, Credential, CredentialConfig, CredentialType,
    CredentialStorageType, CredentialFormat
)

logger = logging.getLogger(__name__)


class CreateCredentialTool(Tool):
    """Tool for creating a new credential."""
    
    def __init__(self, credential_manager: CredentialManager):
        """
        Initialize the tool.
        
        Args:
            credential_manager: Manager for secure credentials
        """
        super().__init__(
            name="create_credential",
            schema=ToolSchema(
                description="Create a new secure credential for external system access",
                parameters={
                    "name": {
                        "description": "Name of the credential",
                        "type": "string"
                    },
                    "description": {
                        "description": "Description of the credential",
                        "type": "string"
                    },
                    "type": {
                        "description": "Type of credential",
                        "type": "string",
                        "enum": [t.value for t in CredentialType]
                    },
                    "data": {
                        "description": "Credential data (will be stored securely)",
                        "type": "object"
                    },
                    "data_format": {
                        "description": "Format of credential data",
                        "type": "string",
                        "enum": [f.value for f in CredentialFormat],
                        "default": "json"
                    },
                    "expires_at": {
                        "description": "Expiration date (ISO 8601 format)",
                        "type": "string"
                    },
                    "tags": {
                        "description": "Tags for the credential",
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
                    "description": "Result of credential creation",
                    "type": "object",
                    "properties": {
                        "credential_id": {"type": "string"},
                        "name": {"type": "string"},
                        "type": {"type": "string"}
                    }
                }
            )
        )
        self.credential_manager = credential_manager
    
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
            cred_type = parameters.get("type")
            data = parameters.get("data")
            
            if not name:
                return {"error": "Credential name is required"}
                
            if not description:
                return {"error": "Credential description is required"}
                
            if not cred_type:
                return {"error": "Credential type is required"}
                
            if not data:
                return {"error": "Credential data is required"}
            
            # Parse expiration date if provided
            expires_at = None
            if "expires_at" in parameters and parameters["expires_at"]:
                expires_at = datetime.fromisoformat(parameters["expires_at"])
            
            # Create credential
            credential_id = await self.credential_manager.create_credential(
                name=name,
                description=description,
                type=CredentialType(cred_type),
                data=data,
                data_format=CredentialFormat(parameters.get("data_format", "json")),
                tags=parameters.get("tags", {}),
                metadata=parameters.get("metadata", {}),
                expires_at=expires_at
            )
            
            return {
                "credential_id": credential_id,
                "name": name,
                "type": cred_type
            }
        except Exception as e:
            logger.error(f"Error creating credential: {str(e)}")
            return {"error": str(e)}


class GetCredentialTool(Tool):
    """Tool for retrieving a credential."""
    
    def __init__(self, credential_manager: CredentialManager):
        """
        Initialize the tool.
        
        Args:
            credential_manager: Manager for secure credentials
        """
        super().__init__(
            name="get_credential",
            schema=ToolSchema(
                description="Get a secure credential",
                parameters={
                    "credential_id": {
                        "description": "ID of the credential to retrieve",
                        "type": "string"
                    }
                },
                returns={
                    "description": "Credential data",
                    "type": "object"
                }
            )
        )
        self.credential_manager = credential_manager
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            credential_id = parameters.get("credential_id")
            
            if not credential_id:
                return {"error": "Credential ID is required"}
            
            # Get credential data
            credential_data = await self.credential_manager.get_credential(credential_id)
            
            if not credential_data:
                return {"error": f"Credential with ID {credential_id} not found"}
            
            return credential_data
        except Exception as e:
            logger.error(f"Error getting credential: {str(e)}")
            return {"error": str(e)}


class UpdateCredentialTool(Tool):
    """Tool for updating a credential."""
    
    def __init__(self, credential_manager: CredentialManager):
        """
        Initialize the tool.
        
        Args:
            credential_manager: Manager for secure credentials
        """
        super().__init__(
            name="update_credential",
            schema=ToolSchema(
                description="Update an existing credential",
                parameters={
                    "credential_id": {
                        "description": "ID of the credential to update",
                        "type": "string"
                    },
                    "data": {
                        "description": "New credential data (will be stored securely)",
                        "type": "object"
                    },
                    "description": {
                        "description": "New description",
                        "type": "string"
                    },
                    "tags": {
                        "description": "New tags",
                        "type": "object"
                    },
                    "metadata": {
                        "description": "New metadata",
                        "type": "object"
                    },
                    "expires_at": {
                        "description": "New expiration date (ISO 8601 format)",
                        "type": "string"
                    }
                },
                returns={
                    "description": "Result of credential update",
                    "type": "object",
                    "properties": {
                        "credential_id": {"type": "string"},
                        "success": {"type": "boolean"},
                        "message": {"type": "string"}
                    }
                }
            )
        )
        self.credential_manager = credential_manager
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            credential_id = parameters.get("credential_id")
            
            if not credential_id:
                return {"error": "Credential ID is required"}
            
            # Parse expiration date if provided
            expires_at = None
            if "expires_at" in parameters and parameters["expires_at"]:
                expires_at = datetime.fromisoformat(parameters["expires_at"])
            
            # Update credential
            success = await self.credential_manager.update_credential(
                credential_id=credential_id,
                data=parameters.get("data"),
                description=parameters.get("description"),
                tags=parameters.get("tags"),
                metadata=parameters.get("metadata"),
                expires_at=expires_at
            )
            
            if success:
                return {
                    "credential_id": credential_id,
                    "success": True,
                    "message": "Credential updated successfully"
                }
            else:
                return {
                    "credential_id": credential_id,
                    "success": False,
                    "message": f"Credential with ID {credential_id} not found"
                }
        except Exception as e:
            logger.error(f"Error updating credential: {str(e)}")
            return {"error": str(e)}


class DeleteCredentialTool(Tool):
    """Tool for deleting a credential."""
    
    def __init__(self, credential_manager: CredentialManager):
        """
        Initialize the tool.
        
        Args:
            credential_manager: Manager for secure credentials
        """
        super().__init__(
            name="delete_credential",
            schema=ToolSchema(
                description="Delete a credential",
                parameters={
                    "credential_id": {
                        "description": "ID of the credential to delete",
                        "type": "string"
                    }
                },
                returns={
                    "description": "Result of credential deletion",
                    "type": "object",
                    "properties": {
                        "credential_id": {"type": "string"},
                        "success": {"type": "boolean"},
                        "message": {"type": "string"}
                    }
                }
            )
        )
        self.credential_manager = credential_manager
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            credential_id = parameters.get("credential_id")
            
            if not credential_id:
                return {"error": "Credential ID is required"}
            
            # Delete credential
            success = await self.credential_manager.delete_credential(credential_id)
            
            if success:
                return {
                    "credential_id": credential_id,
                    "success": True,
                    "message": "Credential deleted successfully"
                }
            else:
                return {
                    "credential_id": credential_id,
                    "success": False,
                    "message": f"Credential with ID {credential_id} not found"
                }
        except Exception as e:
            logger.error(f"Error deleting credential: {str(e)}")
            return {"error": str(e)}


class ListCredentialsTool(Tool):
    """Tool for listing credentials."""
    
    def __init__(self, credential_manager: CredentialManager):
        """
        Initialize the tool.
        
        Args:
            credential_manager: Manager for secure credentials
        """
        super().__init__(
            name="list_credentials",
            schema=ToolSchema(
                description="List available credentials",
                parameters={
                    "type": {
                        "description": "Filter by credential type",
                        "type": "string",
                        "enum": [t.value for t in CredentialType]
                    },
                    "tag_filter": {
                        "description": "Filter by tags",
                        "type": "object"
                    }
                },
                returns={
                    "description": "List of credentials",
                    "type": "array"
                }
            )
        )
        self.credential_manager = credential_manager
    
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
                type_filter = CredentialType(parameters["type"])
                
            tag_filter = parameters.get("tag_filter")
            
            # Get credentials
            credentials = await self.credential_manager.get_credentials(
                type_filter=type_filter,
                tag_filter=tag_filter
            )
            
            return credentials
        except Exception as e:
            logger.error(f"Error listing credentials: {str(e)}")
            return [{"error": str(e)}]


class BackupCredentialsTool(Tool):
    """Tool for backing up credentials."""
    
    def __init__(self, credential_manager: CredentialManager):
        """
        Initialize the tool.
        
        Args:
            credential_manager: Manager for secure credentials
        """
        super().__init__(
            name="backup_credentials",
            schema=ToolSchema(
                description="Backup all credentials to a secure file",
                parameters={
                    "backup_dir": {
                        "description": "Directory to store the backup",
                        "type": "string"
                    }
                },
                returns={
                    "description": "Result of credential backup",
                    "type": "object",
                    "properties": {
                        "success": {"type": "boolean"},
                        "credential_count": {"type": "integer"},
                        "message": {"type": "string"}
                    }
                }
            )
        )
        self.credential_manager = credential_manager
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            backup_dir = parameters.get("backup_dir")
            
            if not backup_dir:
                return {"error": "Backup directory is required"}
            
            # Backup credentials
            credential_count = await self.credential_manager.backup_credentials(backup_dir)
            
            return {
                "success": True,
                "credential_count": credential_count,
                "message": f"Successfully backed up {credential_count} credentials"
            }
        except Exception as e:
            logger.error(f"Error backing up credentials: {str(e)}")
            return {"error": str(e)}


class RestoreCredentialsTool(Tool):
    """Tool for restoring credentials from backup."""
    
    def __init__(self, credential_manager: CredentialManager):
        """
        Initialize the tool.
        
        Args:
            credential_manager: Manager for secure credentials
        """
        super().__init__(
            name="restore_credentials",
            schema=ToolSchema(
                description="Restore credentials from a backup file",
                parameters={
                    "backup_file": {
                        "description": "Path to the backup file",
                        "type": "string"
                    },
                    "overwrite": {
                        "description": "Whether to overwrite existing credentials",
                        "type": "boolean",
                        "default": False
                    }
                },
                returns={
                    "description": "Result of credential restoration",
                    "type": "object",
                    "properties": {
                        "success": {"type": "boolean"},
                        "credential_count": {"type": "integer"},
                        "message": {"type": "string"}
                    }
                }
            )
        )
        self.credential_manager = credential_manager
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            backup_file = parameters.get("backup_file")
            overwrite = parameters.get("overwrite", False)
            
            if not backup_file:
                return {"error": "Backup file is required"}
            
            # Restore credentials
            credential_count = await self.credential_manager.restore_credentials(
                backup_file,
                overwrite
            )
            
            return {
                "success": True,
                "credential_count": credential_count,
                "message": f"Successfully restored {credential_count} credentials"
            }
        except Exception as e:
            logger.error(f"Error restoring credentials: {str(e)}")
            return {"error": str(e)}


class CheckCredentialRotationTool(Tool):
    """Tool for checking which credentials need rotation."""
    
    def __init__(self, credential_manager: CredentialManager):
        """
        Initialize the tool.
        
        Args:
            credential_manager: Manager for secure credentials
        """
        super().__init__(
            name="check_credential_rotation",
            schema=ToolSchema(
                description="Check which credentials are due for rotation",
                parameters={},
                returns={
                    "description": "Credentials due for rotation",
                    "type": "object",
                    "properties": {
                        "count": {"type": "integer"},
                        "credentials": {
                            "type": "object",
                            "additionalProperties": {"type": "string"}
                        }
                    }
                }
            )
        )
        self.credential_manager = credential_manager
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        try:
            # Check for credentials due for rotation
            due_for_rotation = await self.credential_manager.rotate_credentials()
            
            return {
                "count": len(due_for_rotation),
                "credentials": due_for_rotation
            }
        except Exception as e:
            logger.error(f"Error checking credential rotation: {str(e)}")
            return {"error": str(e)}


# Create credential manager with default config
credential_config = CredentialConfig(
    storage_type=CredentialStorageType.ENCRYPTED_FILE,
    data_dir="data/credentials",
    rotation_enabled=True,
    rotation_frequency_days=90,
    audit_enabled=True
)
credential_manager = CredentialManager(credential_config)

# Define list of credential tools
credential_tools = [
    CreateCredentialTool(credential_manager),
    GetCredentialTool(credential_manager),
    UpdateCredentialTool(credential_manager),
    DeleteCredentialTool(credential_manager),
    ListCredentialsTool(credential_manager),
    BackupCredentialsTool(credential_manager),
    RestoreCredentialsTool(credential_manager),
    CheckCredentialRotationTool(credential_manager)
] 