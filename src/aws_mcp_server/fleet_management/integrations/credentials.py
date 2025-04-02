"""
External Credential Management for AWS Fleet Management.

This module provides secure storage and management of credentials
for external system integrations.
"""

import os
import json
import base64
import logging
import hashlib
import secrets
import boto3
from enum import Enum
from typing import Dict, List, Any, Optional, Union, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class CredentialType(Enum):
    """Types of credentials supported by the system."""
    API_KEY = "api_key"
    USERNAME_PASSWORD = "username_password"
    OAUTH2 = "oauth2"
    OAUTH1 = "oauth1"
    AWS_CREDENTIALS = "aws_credentials"
    X509_CERTIFICATE = "x509_certificate"
    SECRET_KEY = "secret_key"
    WEBHOOK_SECRET = "webhook_secret"
    CUSTOM = "custom"


class CredentialStorageType(Enum):
    """Storage types for credentials."""
    ENCRYPTED_FILE = "encrypted_file"
    AWS_SECRETS_MANAGER = "aws_secrets_manager"
    AWS_SSM_PARAMETER_STORE = "aws_ssm_parameter_store"
    MEMORY = "memory"


class CredentialFormat(Enum):
    """Format of credential data."""
    JSON = "json"
    TEXT = "text"
    BINARY = "binary"


@dataclass
class CredentialConfig:
    """Configuration for credential management."""
    storage_type: CredentialStorageType = CredentialStorageType.ENCRYPTED_FILE
    master_key: Optional[str] = None
    salt: Optional[str] = None
    aws_region: str = "us-east-1"
    aws_profile: Optional[str] = None
    aws_assume_role_arn: Optional[str] = None
    data_dir: Optional[str] = None
    rotation_enabled: bool = False
    rotation_frequency_days: int = 90
    audit_enabled: bool = True
    auto_backup: bool = True


@dataclass
class Credential:
    """
    Representation of a credential.
    
    This class represents a credential for an external system,
    including metadata and access tracking.
    """
    id: str
    name: str
    description: str
    type: CredentialType
    data: Dict[str, Any]
    data_format: CredentialFormat
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    rotation_due_at: Optional[datetime] = None
    last_accessed: Optional[datetime] = None
    access_count: int = 0


class CredentialManager:
    """
    Manager for secure credential storage and access.
    
    This class handles the secure storage, retrieval, and management
    of credentials for external systems.
    """
    
    def __init__(self, config: Optional[CredentialConfig] = None):
        """
        Initialize the credential manager.
        
        Args:
            config: Optional configuration for credential management
        """
        self.config = config or CredentialConfig()
        self.credentials: Dict[str, Credential] = {}
        self._cipher = None
        self._initialized = False
        self._aws_clients = {}
    
    async def initialize(self) -> bool:
        """
        Initialize the credential manager.
        
        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            # Create data directory if using file storage
            if self.config.storage_type == CredentialStorageType.ENCRYPTED_FILE and self.config.data_dir:
                data_dir = Path(self.config.data_dir)
                data_dir.mkdir(parents=True, exist_ok=True)
            
            # Initialize encryption
            if not await self._init_encryption():
                return False
            
            # Initialize AWS clients if using AWS storage
            if self.config.storage_type in [
                CredentialStorageType.AWS_SECRETS_MANAGER,
                CredentialStorageType.AWS_SSM_PARAMETER_STORE
            ]:
                if not await self._init_aws_clients():
                    return False
            
            # Load credentials
            await self._load_credentials()
            
            self._initialized = True
            logger.info("Credential manager initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize credential manager: {str(e)}")
            return False
    
    async def shutdown(self) -> None:
        """Shut down the credential manager and clean up resources."""
        # Save credentials
        if self.config.storage_type == CredentialStorageType.ENCRYPTED_FILE:
            await self._save_credentials()
        
        # Clear in-memory data
        self.credentials.clear()
        self._cipher = None
        self._aws_clients.clear()
        self._initialized = False
    
    async def create_credential(
        self,
        name: str,
        description: str,
        type: CredentialType,
        data: Dict[str, Any],
        data_format: CredentialFormat = CredentialFormat.JSON,
        tags: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        expires_at: Optional[datetime] = None
    ) -> str:
        """
        Create a new credential.
        
        Args:
            name: Name of the credential
            description: Description of the credential
            type: Type of credential
            data: Credential data
            data_format: Format of credential data
            tags: Optional tags for the credential
            metadata: Optional metadata for the credential
            expires_at: Optional expiration date
            
        Returns:
            ID of the created credential
            
        Raises:
            ValueError: If a credential with the same name already exists
        """
        if not self._initialized:
            raise RuntimeError("Credential manager not initialized")
        
        # Check if credential with the same name already exists
        for credential in self.credentials.values():
            if credential.name == name:
                raise ValueError(f"Credential with name '{name}' already exists")
        
        # Generate ID
        credential_id = self._generate_id(name)
        
        # Determine rotation due date if rotation is enabled
        rotation_due_at = None
        if self.config.rotation_enabled and self.config.rotation_frequency_days > 0:
            rotation_due_at = datetime.utcnow() + timedelta(days=self.config.rotation_frequency_days)
        
        # Create credential
        credential = Credential(
            id=credential_id,
            name=name,
            description=description,
            type=type,
            data=data.copy(),
            data_format=data_format,
            tags=tags or {},
            metadata=metadata or {},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            expires_at=expires_at,
            rotation_due_at=rotation_due_at
        )
        
        # Store credential
        await self._store_credential(credential)
        
        # Add to in-memory cache
        self.credentials[credential_id] = credential
        
        logger.info(f"Created credential: {name} ({credential_id})")
        return credential_id
    
    async def get_credential(self, credential_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a credential by ID.
        
        Args:
            credential_id: ID of the credential to get
            
        Returns:
            Credential data if found, None otherwise
        """
        if not self._initialized:
            raise RuntimeError("Credential manager not initialized")
        
        # Check if credential exists
        if credential_id not in self.credentials:
            return None
        
        # Get credential
        credential = self.credentials[credential_id]
        
        # Update access metrics
        credential.last_accessed = datetime.utcnow()
        credential.access_count += 1
        
        # Save updated metrics if audit is enabled
        if self.config.audit_enabled:
            if self.config.storage_type == CredentialStorageType.ENCRYPTED_FILE:
                await self._save_credential_metadata(credential)
            # For AWS storage, only update the metadata
            elif self.config.storage_type in [
                CredentialStorageType.AWS_SECRETS_MANAGER,
                CredentialStorageType.AWS_SSM_PARAMETER_STORE
            ]:
                await self._update_aws_metadata(credential)
        
        # Return credential data
        return credential.data.copy()
    
    async def update_credential(
        self,
        credential_id: str,
        data: Optional[Dict[str, Any]] = None,
        description: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        expires_at: Optional[datetime] = None
    ) -> bool:
        """
        Update an existing credential.
        
        Args:
            credential_id: ID of the credential to update
            data: Optional new credential data
            description: Optional new description
            tags: Optional new tags
            metadata: Optional new metadata
            expires_at: Optional new expiration date
            
        Returns:
            True if successful, False if credential not found
        """
        if not self._initialized:
            raise RuntimeError("Credential manager not initialized")
        
        # Check if credential exists
        if credential_id not in self.credentials:
            return False
        
        # Get credential
        credential = self.credentials[credential_id]
        
        # Update fields
        if data is not None:
            credential.data = data.copy()
            
        if description is not None:
            credential.description = description
            
        if tags is not None:
            credential.tags = tags.copy()
            
        if metadata is not None:
            credential.metadata = metadata.copy()
            
        if expires_at is not None:
            credential.expires_at = expires_at
            
        # Update timestamps
        credential.updated_at = datetime.utcnow()
        
        # Reset rotation due date if data was updated
        if data is not None and self.config.rotation_enabled:
            credential.rotation_due_at = datetime.utcnow() + timedelta(days=self.config.rotation_frequency_days)
        
        # Store updated credential
        await self._store_credential(credential)
        
        logger.info(f"Updated credential: {credential.name} ({credential_id})")
        return True
    
    async def delete_credential(self, credential_id: str) -> bool:
        """
        Delete a credential.
        
        Args:
            credential_id: ID of the credential to delete
            
        Returns:
            True if successful, False if credential not found
        """
        if not self._initialized:
            raise RuntimeError("Credential manager not initialized")
        
        # Check if credential exists
        if credential_id not in self.credentials:
            return False
        
        # Get credential for logging
        credential = self.credentials[credential_id]
        
        # Remove from storage
        if self.config.storage_type == CredentialStorageType.ENCRYPTED_FILE:
            data_file = Path(self.config.data_dir) / f"{credential_id}.enc"
            meta_file = Path(self.config.data_dir) / f"{credential_id}.meta"
            
            if data_file.exists():
                data_file.unlink()
                
            if meta_file.exists():
                meta_file.unlink()
        elif self.config.storage_type == CredentialStorageType.AWS_SECRETS_MANAGER:
            client = self._get_aws_client("secretsmanager")
            try:
                client.delete_secret(
                    SecretId=f"fleet-management/credentials/{credential_id}",
                    ForceDeleteWithoutRecovery=True
                )
            except Exception as e:
                logger.error(f"Failed to delete credential from AWS Secrets Manager: {str(e)}")
        elif self.config.storage_type == CredentialStorageType.AWS_SSM_PARAMETER_STORE:
            client = self._get_aws_client("ssm")
            try:
                client.delete_parameter(
                    Name=f"/fleet-management/credentials/{credential_id}"
                )
            except Exception as e:
                logger.error(f"Failed to delete credential from AWS SSM Parameter Store: {str(e)}")
        
        # Remove from memory
        del self.credentials[credential_id]
        
        logger.info(f"Deleted credential: {credential.name} ({credential_id})")
        return True
    
    async def get_credentials(
        self,
        type_filter: Optional[CredentialType] = None,
        tag_filter: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get all credentials matching the given filters.
        
        Args:
            type_filter: Optional filter by credential type
            tag_filter: Optional filter by tags
            
        Returns:
            List of credential metadata (without sensitive data)
        """
        if not self._initialized:
            raise RuntimeError("Credential manager not initialized")
        
        result = []
        
        for credential in self.credentials.values():
            # Apply type filter
            if type_filter and credential.type != type_filter:
                continue
                
            # Apply tag filter
            if tag_filter:
                match = True
                for key, value in tag_filter.items():
                    if key not in credential.tags or credential.tags[key] != value:
                        match = False
                        break
                        
                if not match:
                    continue
            
            # Add metadata to result (without sensitive data)
            result.append({
                "id": credential.id,
                "name": credential.name,
                "description": credential.description,
                "type": credential.type.value,
                "data_format": credential.data_format.value,
                "tags": credential.tags,
                "metadata": credential.metadata,
                "created_at": credential.created_at.isoformat(),
                "updated_at": credential.updated_at.isoformat(),
                "expires_at": credential.expires_at.isoformat() if credential.expires_at else None,
                "rotation_due_at": credential.rotation_due_at.isoformat() if credential.rotation_due_at else None,
                "last_accessed": credential.last_accessed.isoformat() if credential.last_accessed else None,
                "access_count": credential.access_count
            })
            
        return result
    
    async def rotate_credentials(self) -> Dict[str, str]:
        """
        Check for credentials due for rotation.
        
        Returns:
            Dictionary of credential IDs that need rotation and their names
        """
        if not self._initialized or not self.config.rotation_enabled:
            return {}
        
        now = datetime.utcnow()
        due_for_rotation = {}
        
        for credential_id, credential in list(self.credentials.items()):
            if credential.rotation_due_at and now >= credential.rotation_due_at:
                due_for_rotation[credential_id] = credential.name
        
        return due_for_rotation
    
    async def backup_credentials(self, backup_dir: str) -> int:
        """
        Backup all credentials to a file.
        
        Args:
            backup_dir: Directory to store the backup
            
        Returns:
            Number of credentials backed up
            
        Raises:
            ValueError: If backup directory is invalid
        """
        if not self._initialized:
            raise RuntimeError("Credential manager not initialized")
        
        # Create backup directory
        backup_path = Path(backup_dir)
        if not backup_path.exists():
            backup_path.mkdir(parents=True)
        elif not backup_path.is_dir():
            raise ValueError(f"Backup path is not a directory: {backup_dir}")
        
        # Generate backup timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        backup_file = backup_path / f"credentials_backup_{timestamp}.enc"
        
        # Create backup data
        backup_data = {
            "credentials": {},
            "metadata": {
                "backup_time": datetime.utcnow().isoformat(),
                "credential_count": len(self.credentials),
                "version": "1.0"
            }
        }
        
        # Add credentials to backup
        for credential_id, credential in self.credentials.items():
            # Convert to dictionary
            credential_dict = {
                "id": credential.id,
                "name": credential.name,
                "description": credential.description,
                "type": credential.type.value,
                "data": credential.data,
                "data_format": credential.data_format.value,
                "tags": credential.tags,
                "metadata": credential.metadata,
                "created_at": credential.created_at.isoformat(),
                "updated_at": credential.updated_at.isoformat(),
                "access_count": credential.access_count
            }
            
            if credential.expires_at:
                credential_dict["expires_at"] = credential.expires_at.isoformat()
                
            if credential.rotation_due_at:
                credential_dict["rotation_due_at"] = credential.rotation_due_at.isoformat()
                
            if credential.last_accessed:
                credential_dict["last_accessed"] = credential.last_accessed.isoformat()
            
            backup_data["credentials"][credential_id] = credential_dict
        
        # Encrypt and save backup
        json_data = json.dumps(backup_data)
        encrypted_data = self._cipher.encrypt(json_data.encode("utf-8"))
        
        with open(backup_file, "wb") as f:
            f.write(encrypted_data)
        
        logger.info(f"Backed up {len(self.credentials)} credentials to {backup_file}")
        return len(self.credentials)
    
    async def restore_credentials(self, backup_file: str, overwrite: bool = False) -> int:
        """
        Restore credentials from a backup file.
        
        Args:
            backup_file: Path to backup file
            overwrite: Whether to overwrite existing credentials
            
        Returns:
            Number of credentials restored
            
        Raises:
            ValueError: If backup file is invalid
        """
        if not self._initialized:
            raise RuntimeError("Credential manager not initialized")
        
        # Check if backup file exists
        backup_path = Path(backup_file)
        if not backup_path.exists() or not backup_path.is_file():
            raise ValueError(f"Backup file does not exist: {backup_file}")
        
        # Read and decrypt backup
        with open(backup_path, "rb") as f:
            encrypted_data = f.read()
            
        try:
            decrypted_data = self._cipher.decrypt(encrypted_data)
            backup_data = json.loads(decrypted_data.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to decrypt backup: {str(e)}") from e
        
        # Validate backup format
        if "credentials" not in backup_data or "metadata" not in backup_data:
            raise ValueError("Invalid backup format")
        
        # Restore credentials
        restored_count = 0
        
        for credential_id, credential_dict in backup_data["credentials"].items():
            # Skip if credential exists and overwrite is False
            if credential_id in self.credentials and not overwrite:
                continue
                
            try:
                # Create credential object
                credential = Credential(
                    id=credential_dict["id"],
                    name=credential_dict["name"],
                    description=credential_dict["description"],
                    type=CredentialType(credential_dict["type"]),
                    data=credential_dict["data"],
                    data_format=CredentialFormat(credential_dict["data_format"]),
                    tags=credential_dict.get("tags", {}),
                    metadata=credential_dict.get("metadata", {}),
                    access_count=credential_dict.get("access_count", 0)
                )
                
                # Set timestamps
                credential.created_at = datetime.fromisoformat(credential_dict["created_at"])
                credential.updated_at = datetime.fromisoformat(credential_dict["updated_at"])
                
                if "expires_at" in credential_dict and credential_dict["expires_at"]:
                    credential.expires_at = datetime.fromisoformat(credential_dict["expires_at"])
                    
                if "rotation_due_at" in credential_dict and credential_dict["rotation_due_at"]:
                    credential.rotation_due_at = datetime.fromisoformat(credential_dict["rotation_due_at"])
                    
                if "last_accessed" in credential_dict and credential_dict["last_accessed"]:
                    credential.last_accessed = datetime.fromisoformat(credential_dict["last_accessed"])
                
                # Store credential
                await self._store_credential(credential)
                
                # Add to in-memory cache
                self.credentials[credential_id] = credential
                
                restored_count += 1
            except Exception as e:
                logger.error(f"Failed to restore credential {credential_id}: {str(e)}")
        
        logger.info(f"Restored {restored_count} credentials from {backup_file}")
        return restored_count
    
    def _generate_id(self, name: str) -> str:
        """
        Generate a unique ID for a credential.
        
        Args:
            name: Name of the credential
            
        Returns:
            Unique ID
        """
        base = name.lower().replace(" ", "_")
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        random_suffix = secrets.token_hex(4)
        
        return f"{base}_{timestamp}_{random_suffix}"
    
    async def _init_encryption(self) -> bool:
        """
        Initialize encryption for credential data.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get or generate encryption key
            key = await self._get_encryption_key()
            
            # Create cipher
            self._cipher = Fernet(key)
            
            return True
        except Exception as e:
            logger.error(f"Failed to initialize encryption: {str(e)}")
            return False
    
    async def _get_encryption_key(self) -> bytes:
        """
        Get or generate encryption key.
        
        Returns:
            Encryption key as bytes
        """
        # Use master key if provided
        if self.config.master_key:
            # Derive key using PBKDF2
            salt = self.config.salt
            if not salt:
                salt = os.urandom(16)
                self.config.salt = salt.hex()
            elif isinstance(salt, str):
                salt = bytes.fromhex(salt)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            
            key = base64.urlsafe_b64encode(kdf.derive(self.config.master_key.encode()))
            return key
        
        # Generate random key
        return Fernet.generate_key()
    
    async def _init_aws_clients(self) -> bool:
        """
        Initialize AWS clients for credential storage.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create session
            session_kwargs = {"region_name": self.config.aws_region}
            
            if self.config.aws_profile:
                session_kwargs["profile_name"] = self.config.aws_profile
                
            session = boto3.Session(**session_kwargs)
            
            # Create clients
            if self.config.storage_type == CredentialStorageType.AWS_SECRETS_MANAGER:
                self._aws_clients["secretsmanager"] = session.client("secretsmanager")
            elif self.config.storage_type == CredentialStorageType.AWS_SSM_PARAMETER_STORE:
                self._aws_clients["ssm"] = session.client("ssm")
            
            # Assume role if needed
            if self.config.aws_assume_role_arn:
                sts_client = session.client("sts")
                response = sts_client.assume_role(
                    RoleArn=self.config.aws_assume_role_arn,
                    RoleSessionName="FleetManagementCredentialManager"
                )
                
                credentials = response["Credentials"]
                
                # Create new session with assumed role
                session = boto3.Session(
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                    region_name=self.config.aws_region
                )
                
                # Create clients with assumed role
                if self.config.storage_type == CredentialStorageType.AWS_SECRETS_MANAGER:
                    self._aws_clients["secretsmanager"] = session.client("secretsmanager")
                elif self.config.storage_type == CredentialStorageType.AWS_SSM_PARAMETER_STORE:
                    self._aws_clients["ssm"] = session.client("ssm")
            
            return True
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {str(e)}")
            return False
    
    def _get_aws_client(self, service_name: str):
        """
        Get AWS client for a service.
        
        Args:
            service_name: Name of the AWS service
            
        Returns:
            AWS client for the service
            
        Raises:
            RuntimeError: If AWS clients are not initialized
        """
        if service_name not in self._aws_clients:
            raise RuntimeError(f"AWS client for {service_name} not initialized")
            
        return self._aws_clients[service_name]
    
    async def _load_credentials(self) -> None:
        """Load credentials from storage."""
        if self.config.storage_type == CredentialStorageType.ENCRYPTED_FILE:
            await self._load_credentials_from_files()
        elif self.config.storage_type == CredentialStorageType.AWS_SECRETS_MANAGER:
            await self._load_credentials_from_secrets_manager()
        elif self.config.storage_type == CredentialStorageType.AWS_SSM_PARAMETER_STORE:
            await self._load_credentials_from_ssm()
        # Memory storage doesn't need loading
    
    async def _load_credentials_from_files(self) -> None:
        """Load credentials from encrypted files."""
        if not self.config.data_dir:
            return
            
        data_dir = Path(self.config.data_dir)
        if not data_dir.exists():
            return
            
        for meta_file in data_dir.glob("*.meta"):
            try:
                # Load metadata
                with open(meta_file, "r") as f:
                    metadata = json.load(f)
                    
                # Load encrypted data
                data_file = meta_file.with_suffix(".enc")
                if not data_file.exists():
                    logger.warning(f"Credential data file not found: {data_file}")
                    continue
                    
                with open(data_file, "rb") as f:
                    encrypted_data = f.read()
                    
                # Decrypt data
                decrypted_data = self._cipher.decrypt(encrypted_data)
                credential_data = json.loads(decrypted_data.decode("utf-8"))
                
                # Create credential object
                credential_id = meta_file.stem
                
                credential = Credential(
                    id=credential_id,
                    name=metadata["name"],
                    description=metadata["description"],
                    type=CredentialType(metadata["type"]),
                    data=credential_data,
                    data_format=CredentialFormat(metadata["data_format"]),
                    tags=metadata.get("tags", {}),
                    metadata=metadata.get("metadata", {}),
                    access_count=metadata.get("access_count", 0)
                )
                
                # Set timestamps
                credential.created_at = datetime.fromisoformat(metadata["created_at"])
                credential.updated_at = datetime.fromisoformat(metadata["updated_at"])
                
                if "expires_at" in metadata and metadata["expires_at"]:
                    credential.expires_at = datetime.fromisoformat(metadata["expires_at"])
                    
                if "rotation_due_at" in metadata and metadata["rotation_due_at"]:
                    credential.rotation_due_at = datetime.fromisoformat(metadata["rotation_due_at"])
                    
                if "last_accessed" in metadata and metadata["last_accessed"]:
                    credential.last_accessed = datetime.fromisoformat(metadata["last_accessed"])
                
                # Add to in-memory cache
                self.credentials[credential_id] = credential
                
                logger.debug(f"Loaded credential: {credential.name} ({credential_id})")
            except Exception as e:
                logger.error(f"Failed to load credential from {meta_file}: {str(e)}")
    
    async def _load_credentials_from_secrets_manager(self) -> None:
        """Load credentials from AWS Secrets Manager."""
        try:
            client = self._get_aws_client("secretsmanager")
            
            # List secrets
            paginator = client.get_paginator("list_secrets")
            
            for page in paginator.paginate(
                Filters=[{"Key": "name", "Values": ["fleet-management/credentials/"]}]
            ):
                for secret in page.get("SecretList", []):
                    try:
                        # Get secret metadata
                        secret_id = secret["Name"].split("/")[-1]
                        
                        # Get tags
                        tags = {}
                        for tag in secret.get("Tags", []):
                            tags[tag["Key"]] = tag["Value"]
                            
                        # Get secret value
                        response = client.get_secret_value(SecretId=secret["ARN"])
                        secret_value = json.loads(response["SecretString"])
                        
                        # Create credential object
                        credential = Credential(
                            id=secret_id,
                            name=tags.get("Name", secret_id),
                            description=tags.get("Description", ""),
                            type=CredentialType(tags.get("Type", "custom")),
                            data=secret_value["data"],
                            data_format=CredentialFormat(tags.get("DataFormat", "json")),
                            tags={k: v for k, v in tags.items() if k not in ["Name", "Description", "Type", "DataFormat"]},
                            metadata=secret_value.get("metadata", {})
                        )
                        
                        # Set timestamps
                        if "CreatedDate" in secret:
                            credential.created_at = secret["CreatedDate"].replace(tzinfo=None)
                            
                        if "LastModifiedDate" in secret:
                            credential.updated_at = secret["LastModifiedDate"].replace(tzinfo=None)
                            
                        if "expires_at" in secret_value and secret_value["expires_at"]:
                            credential.expires_at = datetime.fromisoformat(secret_value["expires_at"])
                            
                        if "rotation_due_at" in secret_value and secret_value["rotation_due_at"]:
                            credential.rotation_due_at = datetime.fromisoformat(secret_value["rotation_due_at"])
                            
                        if "last_accessed" in secret_value and secret_value["last_accessed"]:
                            credential.last_accessed = datetime.fromisoformat(secret_value["last_accessed"])
                            
                        if "access_count" in secret_value:
                            credential.access_count = secret_value["access_count"]
                        
                        # Add to in-memory cache
                        self.credentials[secret_id] = credential
                        
                        logger.debug(f"Loaded credential from Secrets Manager: {credential.name} ({secret_id})")
                    except Exception as e:
                        logger.error(f"Failed to load credential from Secrets Manager: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to list secrets from AWS Secrets Manager: {str(e)}")
    
    async def _load_credentials_from_ssm(self) -> None:
        """Load credentials from AWS SSM Parameter Store."""
        try:
            client = self._get_aws_client("ssm")
            
            # List parameters
            paginator = client.get_paginator("describe_parameters")
            
            for page in paginator.paginate(
                ParameterFilters=[{"Key": "Path", "Values": ["/fleet-management/credentials/"]}]
            ):
                for parameter in page.get("Parameters", []):
                    try:
                        # Get parameter metadata
                        param_name = parameter["Name"]
                        param_id = param_name.split("/")[-1]
                        
                        # Get parameter value
                        response = client.get_parameter(
                            Name=param_name,
                            WithDecryption=True
                        )
                        
                        # Parse parameter value
                        param_value = json.loads(response["Parameter"]["Value"])
                        
                        # Create credential object
                        credential = Credential(
                            id=param_id,
                            name=param_value.get("name", param_id),
                            description=param_value.get("description", ""),
                            type=CredentialType(param_value.get("type", "custom")),
                            data=param_value["data"],
                            data_format=CredentialFormat(param_value.get("data_format", "json")),
                            tags=param_value.get("tags", {}),
                            metadata=param_value.get("metadata", {})
                        )
                        
                        # Set timestamps
                        if "created_at" in param_value:
                            credential.created_at = datetime.fromisoformat(param_value["created_at"])
                        elif "LastModifiedDate" in parameter:
                            credential.created_at = parameter["LastModifiedDate"].replace(tzinfo=None)
                            
                        if "updated_at" in param_value:
                            credential.updated_at = datetime.fromisoformat(param_value["updated_at"])
                        elif "LastModifiedDate" in parameter:
                            credential.updated_at = parameter["LastModifiedDate"].replace(tzinfo=None)
                            
                        if "expires_at" in param_value and param_value["expires_at"]:
                            credential.expires_at = datetime.fromisoformat(param_value["expires_at"])
                            
                        if "rotation_due_at" in param_value and param_value["rotation_due_at"]:
                            credential.rotation_due_at = datetime.fromisoformat(param_value["rotation_due_at"])
                            
                        if "last_accessed" in param_value and param_value["last_accessed"]:
                            credential.last_accessed = datetime.fromisoformat(param_value["last_accessed"])
                            
                        if "access_count" in param_value:
                            credential.access_count = param_value["access_count"]
                        
                        # Add to in-memory cache
                        self.credentials[param_id] = credential
                        
                        logger.debug(f"Loaded credential from SSM: {credential.name} ({param_id})")
                    except Exception as e:
                        logger.error(f"Failed to load credential from SSM: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to list parameters from AWS SSM Parameter Store: {str(e)}")
    
    async def _store_credential(self, credential: Credential) -> None:
        """
        Store a credential.
        
        Args:
            credential: Credential to store
        """
        if self.config.storage_type == CredentialStorageType.ENCRYPTED_FILE:
            await self._save_credential_to_file(credential)
        elif self.config.storage_type == CredentialStorageType.AWS_SECRETS_MANAGER:
            await self._save_credential_to_secrets_manager(credential)
        elif self.config.storage_type == CredentialStorageType.AWS_SSM_PARAMETER_STORE:
            await self._save_credential_to_ssm(credential)
        # Memory storage doesn't need saving
    
    async def _save_credential_to_file(self, credential: Credential) -> None:
        """
        Save a credential to an encrypted file.
        
        Args:
            credential: Credential to save
        """
        if not self.config.data_dir:
            return
            
        data_dir = Path(self.config.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        
        # Save credential data (encrypted)
        data_file = data_dir / f"{credential.id}.enc"
        encrypted_data = self._cipher.encrypt(json.dumps(credential.data).encode("utf-8"))
        
        with open(data_file, "wb") as f:
            f.write(encrypted_data)
        
        # Save metadata (unencrypted)
        await self._save_credential_metadata(credential)
    
    async def _save_credential_metadata(self, credential: Credential) -> None:
        """
        Save credential metadata to a file.
        
        Args:
            credential: Credential to save metadata for
        """
        if not self.config.data_dir:
            return
            
        data_dir = Path(self.config.data_dir)
        meta_file = data_dir / f"{credential.id}.meta"
        
        metadata = {
            "name": credential.name,
            "description": credential.description,
            "type": credential.type.value,
            "data_format": credential.data_format.value,
            "tags": credential.tags,
            "metadata": credential.metadata,
            "created_at": credential.created_at.isoformat(),
            "updated_at": credential.updated_at.isoformat(),
            "access_count": credential.access_count
        }
        
        if credential.expires_at:
            metadata["expires_at"] = credential.expires_at.isoformat()
            
        if credential.rotation_due_at:
            metadata["rotation_due_at"] = credential.rotation_due_at.isoformat()
            
        if credential.last_accessed:
            metadata["last_accessed"] = credential.last_accessed.isoformat()
        
        with open(meta_file, "w") as f:
            json.dump(metadata, f, indent=2)
    
    async def _save_credential_to_secrets_manager(self, credential: Credential) -> None:
        """
        Save a credential to AWS Secrets Manager.
        
        Args:
            credential: Credential to save
        """
        try:
            client = self._get_aws_client("secretsmanager")
            
            # Prepare secret value
            secret_value = {
                "data": credential.data,
                "metadata": credential.metadata
            }
            
            if credential.expires_at:
                secret_value["expires_at"] = credential.expires_at.isoformat()
                
            if credential.rotation_due_at:
                secret_value["rotation_due_at"] = credential.rotation_due_at.isoformat()
                
            if credential.last_accessed:
                secret_value["last_accessed"] = credential.last_accessed.isoformat()
                
            secret_value["access_count"] = credential.access_count
            
            # Prepare tags
            tags = [
                {"Key": "Name", "Value": credential.name},
                {"Key": "Description", "Value": credential.description},
                {"Key": "Type", "Value": credential.type.value},
                {"Key": "DataFormat", "Value": credential.data_format.value}
            ]
            
            for key, value in credential.tags.items():
                tags.append({"Key": key, "Value": value})
            
            # Check if secret exists
            try:
                client.describe_secret(SecretId=f"fleet-management/credentials/{credential.id}")
                
                # Update existing secret
                client.update_secret(
                    SecretId=f"fleet-management/credentials/{credential.id}",
                    SecretString=json.dumps(secret_value)
                )
                
                # Update tags
                client.tag_resource(
                    SecretId=f"fleet-management/credentials/{credential.id}",
                    Tags=tags
                )
            except client.exceptions.ResourceNotFoundException:
                # Create new secret
                client.create_secret(
                    Name=f"fleet-management/credentials/{credential.id}",
                    SecretString=json.dumps(secret_value),
                    Tags=tags
                )
        except Exception as e:
            logger.error(f"Failed to save credential to AWS Secrets Manager: {str(e)}")
    
    async def _save_credential_to_ssm(self, credential: Credential) -> None:
        """
        Save a credential to AWS SSM Parameter Store.
        
        Args:
            credential: Credential to save
        """
        try:
            client = self._get_aws_client("ssm")
            
            # Prepare parameter value
            param_value = {
                "name": credential.name,
                "description": credential.description,
                "type": credential.type.value,
                "data_format": credential.data_format.value,
                "data": credential.data,
                "tags": credential.tags,
                "metadata": credential.metadata,
                "created_at": credential.created_at.isoformat(),
                "updated_at": credential.updated_at.isoformat(),
                "access_count": credential.access_count
            }
            
            if credential.expires_at:
                param_value["expires_at"] = credential.expires_at.isoformat()
                
            if credential.rotation_due_at:
                param_value["rotation_due_at"] = credential.rotation_due_at.isoformat()
                
            if credential.last_accessed:
                param_value["last_accessed"] = credential.last_accessed.isoformat()
            
            # Check if parameter exists
            try:
                client.get_parameter(Name=f"/fleet-management/credentials/{credential.id}")
                
                # Update existing parameter
                client.put_parameter(
                    Name=f"/fleet-management/credentials/{credential.id}",
                    Value=json.dumps(param_value),
                    Type="SecureString",
                    Overwrite=True
                )
            except client.exceptions.ParameterNotFound:
                # Create new parameter
                client.put_parameter(
                    Name=f"/fleet-management/credentials/{credential.id}",
                    Value=json.dumps(param_value),
                    Type="SecureString",
                    Tags=[
                        {"Key": "Name", "Value": credential.name},
                        {"Key": "Type", "Value": credential.type.value}
                    ]
                )
        except Exception as e:
            logger.error(f"Failed to save credential to AWS SSM Parameter Store: {str(e)}")
    
    async def _update_aws_metadata(self, credential: Credential) -> None:
        """
        Update credential metadata in AWS.
        
        Args:
            credential: Credential to update metadata for
        """
        if self.config.storage_type == CredentialStorageType.AWS_SECRETS_MANAGER:
            await self._save_credential_to_secrets_manager(credential)
        elif self.config.storage_type == CredentialStorageType.AWS_SSM_PARAMETER_STORE:
            await self._save_credential_to_ssm(credential)
    
    async def _save_credentials(self) -> None:
        """Save all credentials."""
        if self.config.storage_type == CredentialStorageType.ENCRYPTED_FILE:
            for credential in self.credentials.values():
                await self._save_credential_to_file(credential) 