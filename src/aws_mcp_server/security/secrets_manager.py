"""AWS Secrets Manager and KMS integration for secure credential management.

This module provides tools to:
- Securely store and retrieve secrets
- Rotate credentials automatically
- Manage encryption keys
- Implement secure credential patterns
"""

import asyncio
import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Optional, Union

import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class SecretType(Enum):
    """Types of secrets that can be stored."""

    DATABASE = "database"
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    SSH_KEY = "ssh_key"
    TLS_CERTIFICATE = "tls_certificate"
    GENERIC = "generic"


class RotationStatus(Enum):
    """Status of secret rotation."""

    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    SCHEDULED = "SCHEDULED"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"


@dataclass
class Secret:
    """Represents a secret in Secrets Manager."""

    name: str
    arn: str
    description: Optional[str] = None
    secret_type: SecretType = SecretType.GENERIC
    created_date: Optional[datetime] = None
    last_accessed_date: Optional[datetime] = None
    last_changed_date: Optional[datetime] = None
    rotation_enabled: bool = False
    rotation_lambda_arn: Optional[str] = None
    next_rotation_date: Optional[datetime] = None
    tags: dict[str, str] = field(default_factory=dict)
    kms_key_id: Optional[str] = None
    version_id: Optional[str] = None


@dataclass
class EncryptionKey:
    """Represents a KMS encryption key."""

    key_id: str
    arn: str
    alias: Optional[str] = None
    description: Optional[str] = None
    key_state: str = "Enabled"
    key_usage: str = "ENCRYPT_DECRYPT"
    creation_date: Optional[datetime] = None
    enabled: bool = True
    multi_region: bool = False
    key_policy: Optional[dict[str, Any]] = None
    tags: dict[str, str] = field(default_factory=dict)


class SecretsManagerClient:
    """Client for AWS Secrets Manager operations."""

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """Initialize Secrets Manager client.

        Args:
            region: AWS region
            profile: AWS profile to use for authentication
        """
        self.region = region or "us-east-1"
        self.profile = profile

        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.client = session.client("secretsmanager", region_name=self.region)
        self.kms_client = session.client("kms", region_name=self.region)

    async def create_secret(
        self,
        name: str,
        secret_value: Union[str, dict[str, Any]],
        description: Optional[str] = None,
        kms_key_id: Optional[str] = None,
        tags: Optional[dict[str, str]] = None,
        secret_type: SecretType = SecretType.GENERIC,
    ) -> Secret:
        """Create a new secret in Secrets Manager.

        Args:
            name: Name of the secret
            secret_value: Secret value (string or dict)
            description: Description of the secret
            kms_key_id: KMS key ID for encryption
            tags: Tags to apply to the secret
            secret_type: Type of secret

        Returns:
            Created secret
        """
        # Convert dict to JSON if needed
        if isinstance(secret_value, dict):
            secret_string = json.dumps(secret_value)
        else:
            secret_string = secret_value

        params = {
            "Name": name,
            "SecretString": secret_string,
        }

        if description:
            params["Description"] = description
        if kms_key_id:
            params["KmsKeyId"] = kms_key_id

        # Add tags including secret type
        all_tags = {"Type": secret_type.value}
        if tags:
            all_tags.update(tags)

        tags_list = [{"Key": k, "Value": v} for k, v in all_tags.items()]
        if tags_list:
            params["Tags"] = tags_list

        try:
            response = await asyncio.to_thread(self.client.create_secret, **params)

            return Secret(
                name=name,
                arn=response["ARN"],
                description=description,
                secret_type=secret_type,
                created_date=datetime.now(),
                kms_key_id=kms_key_id,
                version_id=response.get("VersionId"),
                tags=all_tags,
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceExistsException":
                logger.warning(f"Secret {name} already exists, updating instead")
                return await self.update_secret(name, secret_value)
            raise

    async def get_secret(self, name_or_arn: str, version_id: Optional[str] = None) -> tuple[Secret, Union[str, dict[str, Any]]]:
        """Retrieve a secret value.

        Args:
            name_or_arn: Secret name or ARN
            version_id: Specific version to retrieve

        Returns:
            Tuple of (Secret metadata, secret value)
        """
        params = {"SecretId": name_or_arn}
        if version_id:
            params["VersionId"] = version_id

        try:
            response = await asyncio.to_thread(self.client.get_secret_value, **params)

            # Parse secret value
            if "SecretString" in response:
                secret_value = response["SecretString"]
                # Try to parse as JSON
                try:
                    secret_value = json.loads(secret_value)
                except json.JSONDecodeError:
                    pass  # Keep as string
            else:
                # Binary secret
                secret_value = base64.b64decode(response["SecretBinary"])

            # Get metadata
            metadata_response = await asyncio.to_thread(self.client.describe_secret, SecretId=name_or_arn)

            secret = Secret(
                name=metadata_response["Name"],
                arn=metadata_response["ARN"],
                description=metadata_response.get("Description"),
                created_date=metadata_response.get("CreatedDate"),
                last_accessed_date=metadata_response.get("LastAccessedDate"),
                last_changed_date=metadata_response.get("LastChangedDate"),
                rotation_enabled=metadata_response.get("RotationEnabled", False),
                rotation_lambda_arn=metadata_response.get("RotationLambdaARN"),
                next_rotation_date=metadata_response.get("NextRotationDate"),
                kms_key_id=metadata_response.get("KmsKeyId"),
                version_id=response.get("VersionId"),
                tags={tag["Key"]: tag["Value"] for tag in metadata_response.get("Tags", [])},
            )

            # Determine secret type from tags
            if "Type" in secret.tags:
                secret.secret_type = SecretType(secret.tags["Type"])

            return secret, secret_value

        except ClientError as e:
            logger.error(f"Error retrieving secret {name_or_arn}: {e}")
            raise

    async def update_secret(self, name_or_arn: str, secret_value: Union[str, dict[str, Any]]) -> Secret:
        """Update an existing secret value.

        Args:
            name_or_arn: Secret name or ARN
            secret_value: New secret value

        Returns:
            Updated secret
        """
        # Convert dict to JSON if needed
        if isinstance(secret_value, dict):
            secret_string = json.dumps(secret_value)
        else:
            secret_string = secret_value

        try:
            response = await asyncio.to_thread(self.client.update_secret, SecretId=name_or_arn, SecretString=secret_string)

            # Get updated metadata
            secret, _ = await self.get_secret(name_or_arn)
            secret.version_id = response.get("VersionId")
            secret.last_changed_date = datetime.now()

            return secret

        except ClientError as e:
            logger.error(f"Error updating secret {name_or_arn}: {e}")
            raise

    async def delete_secret(self, name_or_arn: str, recovery_days: int = 30, force_delete: bool = False) -> dict[str, Any]:
        """Delete a secret with optional recovery window.

        Args:
            name_or_arn: Secret name or ARN
            recovery_days: Days before permanent deletion (7-30)
            force_delete: Force immediate deletion

        Returns:
            Deletion response
        """
        params = {"SecretId": name_or_arn}

        if force_delete:
            params["ForceDeleteWithoutRecovery"] = True
        else:
            params["RecoveryWindowInDays"] = max(7, min(30, recovery_days))

        try:
            response = await asyncio.to_thread(self.client.delete_secret, **params)
            logger.info(f"Secret {name_or_arn} scheduled for deletion")
            return response
        except ClientError as e:
            logger.error(f"Error deleting secret {name_or_arn}: {e}")
            raise

    async def list_secrets(self, filters: Optional[dict[str, Any]] = None) -> list[Secret]:
        """List all secrets in the account/region.

        Args:
            filters: Optional filters for listing

        Returns:
            List of secrets
        """
        secrets = []
        paginator = self.client.get_paginator("list_secrets")

        params = {}
        if filters:
            params["Filters"] = filters

        try:
            async for page in self._async_paginate(paginator, **params):
                for secret_data in page.get("SecretList", []):
                    secret = Secret(
                        name=secret_data["Name"],
                        arn=secret_data["ARN"],
                        description=secret_data.get("Description"),
                        created_date=secret_data.get("CreatedDate"),
                        last_accessed_date=secret_data.get("LastAccessedDate"),
                        last_changed_date=secret_data.get("LastChangedDate"),
                        rotation_enabled=secret_data.get("RotationEnabled", False),
                        rotation_lambda_arn=secret_data.get("RotationLambdaARN"),
                        next_rotation_date=secret_data.get("NextRotationDate"),
                        kms_key_id=secret_data.get("KmsKeyId"),
                        tags={tag["Key"]: tag["Value"] for tag in secret_data.get("Tags", [])},
                    )

                    if "Type" in secret.tags:
                        secret.secret_type = SecretType(secret.tags["Type"])

                    secrets.append(secret)

        except ClientError as e:
            logger.error(f"Error listing secrets: {e}")
            raise

        return secrets

    async def enable_rotation(
        self,
        name_or_arn: str,
        rotation_lambda_arn: str,
        rotation_rules: dict[str, Any],
        rotate_immediately: bool = True,
    ) -> Secret:
        """Enable automatic rotation for a secret.

        Args:
            name_or_arn: Secret name or ARN
            rotation_lambda_arn: ARN of Lambda function to handle rotation
            rotation_rules: Rotation schedule rules
            rotate_immediately: Whether to rotate immediately

        Returns:
            Updated secret with rotation enabled
        """
        try:
            await asyncio.to_thread(
                self.client.rotate_secret,
                SecretId=name_or_arn,
                RotationLambdaARN=rotation_lambda_arn,
                RotationRules=rotation_rules,
                RotateImmediately=rotate_immediately,
            )

            secret, _ = await self.get_secret(name_or_arn)
            secret.rotation_enabled = True
            secret.rotation_lambda_arn = rotation_lambda_arn

            logger.info(f"Enabled rotation for secret {name_or_arn}")
            return secret

        except ClientError as e:
            logger.error(f"Error enabling rotation: {e}")
            raise

    async def generate_random_password(
        self,
        length: int = 32,
        exclude_characters: Optional[str] = None,
        exclude_numbers: bool = False,
        exclude_punctuation: bool = False,
        exclude_uppercase: bool = False,
        exclude_lowercase: bool = False,
        include_space: bool = False,
        require_each_included_type: bool = True,
    ) -> str:
        """Generate a random password using Secrets Manager.

        Args:
            length: Password length
            exclude_characters: Characters to exclude
            exclude_numbers: Exclude numbers
            exclude_punctuation: Exclude punctuation
            exclude_uppercase: Exclude uppercase letters
            exclude_lowercase: Exclude lowercase letters
            include_space: Include spaces
            require_each_included_type: Require at least one of each type

        Returns:
            Generated password
        """
        params = {
            "PasswordLength": length,
            "ExcludeNumbers": exclude_numbers,
            "ExcludePunctuation": exclude_punctuation,
            "ExcludeUppercase": exclude_uppercase,
            "ExcludeLowercase": exclude_lowercase,
            "IncludeSpace": include_space,
            "RequireEachIncludedType": require_each_included_type,
        }

        if exclude_characters:
            params["ExcludeCharacters"] = exclude_characters

        try:
            response = await asyncio.to_thread(self.client.get_random_password, **params)
            return response["RandomPassword"]
        except ClientError as e:
            logger.error(f"Error generating password: {e}")
            raise

    async def restore_secret(self, name_or_arn: str) -> Secret:
        """Restore a previously deleted secret.

        Args:
            name_or_arn: Secret name or ARN

        Returns:
            Restored secret
        """
        try:
            await asyncio.to_thread(self.client.restore_secret, SecretId=name_or_arn)
            secret, _ = await self.get_secret(name_or_arn)
            logger.info(f"Restored secret {name_or_arn}")
            return secret
        except ClientError as e:
            logger.error(f"Error restoring secret: {e}")
            raise

    # Helper methods

    async def _async_paginate(self, paginator, **kwargs):
        """Async wrapper for boto3 paginator."""
        page_iterator = paginator.paginate(**kwargs)
        for page in page_iterator:
            yield page


class KMSClient:
    """Client for AWS KMS operations."""

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """Initialize KMS client.

        Args:
            region: AWS region
            profile: AWS profile to use for authentication
        """
        self.region = region or "us-east-1"
        self.profile = profile

        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.client = session.client("kms", region_name=self.region)

    async def create_key(
        self,
        description: Optional[str] = None,
        key_usage: str = "ENCRYPT_DECRYPT",
        key_spec: str = "SYMMETRIC_DEFAULT",
        multi_region: bool = False,
        tags: Optional[dict[str, str]] = None,
    ) -> EncryptionKey:
        """Create a new KMS key.

        Args:
            description: Key description
            key_usage: Key usage type
            key_spec: Key specification
            multi_region: Whether to create multi-region key
            tags: Tags to apply

        Returns:
            Created encryption key
        """
        params = {
            "KeyUsage": key_usage,
            "KeySpec": key_spec,
            "MultiRegion": multi_region,
        }

        if description:
            params["Description"] = description

        if tags:
            params["Tags"] = [{"TagKey": k, "TagValue": v} for k, v in tags.items()]

        try:
            response = await asyncio.to_thread(self.client.create_key, **params)
            key_metadata = response["KeyMetadata"]

            return EncryptionKey(
                key_id=key_metadata["KeyId"],
                arn=key_metadata["Arn"],
                description=description,
                key_state=key_metadata["KeyState"],
                key_usage=key_metadata["KeyUsage"],
                creation_date=key_metadata["CreationDate"],
                enabled=key_metadata["Enabled"],
                multi_region=key_metadata.get("MultiRegion", False),
                tags=tags or {},
            )

        except ClientError as e:
            logger.error(f"Error creating KMS key: {e}")
            raise

    async def create_alias(self, alias_name: str, key_id: str) -> dict[str, Any]:
        """Create an alias for a KMS key.

        Args:
            alias_name: Alias name (must start with 'alias/')
            key_id: Key ID or ARN

        Returns:
            Response from KMS
        """
        if not alias_name.startswith("alias/"):
            alias_name = f"alias/{alias_name}"

        try:
            response = await asyncio.to_thread(self.client.create_alias, AliasName=alias_name, TargetKeyId=key_id)
            logger.info(f"Created alias {alias_name} for key {key_id}")
            return response
        except ClientError as e:
            logger.error(f"Error creating alias: {e}")
            raise

    async def encrypt(self, key_id: str, plaintext: Union[str, bytes], encryption_context: Optional[dict[str, str]] = None) -> bytes:
        """Encrypt data using KMS.

        Args:
            key_id: Key ID, ARN, or alias
            plaintext: Data to encrypt
            encryption_context: Additional authenticated data

        Returns:
            Encrypted ciphertext
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        params = {
            "KeyId": key_id,
            "Plaintext": plaintext,
        }

        if encryption_context:
            params["EncryptionContext"] = encryption_context

        try:
            response = await asyncio.to_thread(self.client.encrypt, **params)
            return response["CiphertextBlob"]
        except ClientError as e:
            logger.error(f"Error encrypting data: {e}")
            raise

    async def decrypt(self, ciphertext: bytes, encryption_context: Optional[dict[str, str]] = None) -> bytes:
        """Decrypt data using KMS.

        Args:
            ciphertext: Encrypted data
            encryption_context: Additional authenticated data

        Returns:
            Decrypted plaintext
        """
        params = {
            "CiphertextBlob": ciphertext,
        }

        if encryption_context:
            params["EncryptionContext"] = encryption_context

        try:
            response = await asyncio.to_thread(self.client.decrypt, **params)
            return response["Plaintext"]
        except ClientError as e:
            logger.error(f"Error decrypting data: {e}")
            raise

    async def generate_data_key(
        self, key_id: str, key_spec: str = "AES_256", encryption_context: Optional[dict[str, str]] = None
    ) -> tuple[bytes, bytes]:
        """Generate a data encryption key.

        Args:
            key_id: Key ID, ARN, or alias
            key_spec: Key specification
            encryption_context: Additional authenticated data

        Returns:
            Tuple of (plaintext key, encrypted key)
        """
        params = {
            "KeyId": key_id,
            "KeySpec": key_spec,
        }

        if encryption_context:
            params["EncryptionContext"] = encryption_context

        try:
            response = await asyncio.to_thread(self.client.generate_data_key, **params)
            return response["Plaintext"], response["CiphertextBlob"]
        except ClientError as e:
            logger.error(f"Error generating data key: {e}")
            raise

    async def enable_key_rotation(self, key_id: str) -> dict[str, Any]:
        """Enable automatic key rotation.

        Args:
            key_id: Key ID or ARN

        Returns:
            Response from KMS
        """
        try:
            response = await asyncio.to_thread(self.client.enable_key_rotation, KeyId=key_id)
            logger.info(f"Enabled rotation for key {key_id}")
            return response
        except ClientError as e:
            logger.error(f"Error enabling key rotation: {e}")
            raise

    async def list_keys(self) -> list[EncryptionKey]:
        """List all KMS keys in the account/region.

        Returns:
            List of encryption keys
        """
        keys = []
        paginator = self.client.get_paginator("list_keys")

        try:
            async for page in self._async_paginate(paginator):
                for key_entry in page.get("Keys", []):
                    # Get detailed key metadata
                    try:
                        metadata = await asyncio.to_thread(self.client.describe_key, KeyId=key_entry["KeyId"])
                        key_metadata = metadata["KeyMetadata"]

                        # Get aliases for this key
                        aliases_response = await asyncio.to_thread(self.client.list_aliases, KeyId=key_entry["KeyId"])
                        aliases = [alias["AliasName"] for alias in aliases_response.get("Aliases", [])]

                        key = EncryptionKey(
                            key_id=key_metadata["KeyId"],
                            arn=key_metadata["Arn"],
                            alias=aliases[0] if aliases else None,
                            description=key_metadata.get("Description"),
                            key_state=key_metadata["KeyState"],
                            key_usage=key_metadata["KeyUsage"],
                            creation_date=key_metadata["CreationDate"],
                            enabled=key_metadata["Enabled"],
                            multi_region=key_metadata.get("MultiRegion", False),
                        )
                        keys.append(key)
                    except ClientError:
                        # Skip keys we can't access
                        continue

        except ClientError as e:
            logger.error(f"Error listing keys: {e}")
            raise

        return keys

    async def get_key_policy(self, key_id: str, policy_name: str = "default") -> dict[str, Any]:
        """Get the key policy for a KMS key.

        Args:
            key_id: Key ID or ARN
            policy_name: Policy name (usually 'default')

        Returns:
            Key policy document
        """
        try:
            response = await asyncio.to_thread(self.client.get_key_policy, KeyId=key_id, PolicyName=policy_name)
            return json.loads(response["Policy"])
        except ClientError as e:
            logger.error(f"Error getting key policy: {e}")
            raise

    async def put_key_policy(self, key_id: str, policy: dict[str, Any], policy_name: str = "default") -> dict[str, Any]:
        """Update the key policy for a KMS key.

        Args:
            key_id: Key ID or ARN
            policy: Policy document
            policy_name: Policy name (usually 'default')

        Returns:
            Response from KMS
        """
        try:
            response = await asyncio.to_thread(
                self.client.put_key_policy, KeyId=key_id, PolicyName=policy_name, Policy=json.dumps(policy)
            )
            logger.info(f"Updated policy for key {key_id}")
            return response
        except ClientError as e:
            logger.error(f"Error updating key policy: {e}")
            raise

    # Helper methods

    async def _async_paginate(self, paginator, **kwargs):
        """Async wrapper for boto3 paginator."""
        page_iterator = paginator.paginate(**kwargs)
        for page in page_iterator:
            yield page


class SecureCredentialManager:
    """High-level credential management with best practices."""

    def __init__(self, secrets_client: SecretsManagerClient, kms_client: KMSClient):
        """Initialize credential manager.

        Args:
            secrets_client: Secrets Manager client
            kms_client: KMS client
        """
        self.secrets = secrets_client
        self.kms = kms_client

    async def create_database_credentials(
        self,
        name: str,
        username: str,
        host: str,
        port: int,
        database: str,
        engine: str = "mysql",
        generate_password: bool = True,
        password: Optional[str] = None,
        kms_key_id: Optional[str] = None,
    ) -> Secret:
        """Create database credentials following best practices.

        Args:
            name: Secret name
            username: Database username
            host: Database host
            port: Database port
            database: Database name
            engine: Database engine
            generate_password: Whether to generate a password
            password: Existing password (if not generating)
            kms_key_id: KMS key for encryption

        Returns:
            Created secret
        """
        if generate_password:
            password = await self.secrets.generate_random_password(
                length=32, exclude_characters=' /"\\\'', exclude_punctuation=False
            )

        secret_value = {
            "username": username,
            "password": password,
            "engine": engine,
            "host": host,
            "port": port,
            "dbname": database,
        }

        return await self.secrets.create_secret(
            name=name,
            secret_value=secret_value,
            description=f"Database credentials for {engine} at {host}",
            kms_key_id=kms_key_id,
            secret_type=SecretType.DATABASE,
            tags={"Engine": engine, "Host": host, "Database": database},
        )

    async def create_api_key(
        self, name: str, api_key: str, api_url: Optional[str] = None, headers: Optional[dict[str, str]] = None, kms_key_id: Optional[str] = None
    ) -> Secret:
        """Store API key with metadata.

        Args:
            name: Secret name
            api_key: API key value
            api_url: API endpoint URL
            headers: Additional headers
            kms_key_id: KMS key for encryption

        Returns:
            Created secret
        """
        secret_value = {"api_key": api_key}

        if api_url:
            secret_value["api_url"] = api_url
        if headers:
            secret_value["headers"] = headers

        return await self.secrets.create_secret(
            name=name,
            secret_value=secret_value,
            description=f"API key for {api_url or 'external service'}",
            kms_key_id=kms_key_id,
            secret_type=SecretType.API_KEY,
        )

    async def rotate_database_password(self, secret_name: str, update_function) -> Secret:
        """Rotate database password with zero downtime.

        Args:
            secret_name: Name of the secret
            update_function: Async function to update password in database

        Returns:
            Updated secret
        """
        # Get current credentials
        secret, current_creds = await self.secrets.get_secret(secret_name)

        # Generate new password
        new_password = await self.secrets.generate_random_password(length=32, exclude_characters=' /"\\\'')

        # Create new version with both passwords
        pending_creds = current_creds.copy()
        pending_creds["password"] = new_password
        pending_creds["previous_password"] = current_creds["password"]

        # Store pending version
        await self.secrets.update_secret(secret_name, pending_creds)

        try:
            # Update password in database
            await update_function(pending_creds["username"], new_password)

            # Finalize rotation by removing previous password
            final_creds = pending_creds.copy()
            del final_creds["previous_password"]
            return await self.secrets.update_secret(secret_name, final_creds)

        except Exception as e:
            # Rollback on failure
            logger.error(f"Failed to rotate password: {e}")
            await self.secrets.update_secret(secret_name, current_creds)
            raise

    async def create_encryption_envelope(self, data: bytes, kms_key_id: str) -> dict[str, Any]:
        """Create envelope encryption for large data.

        Args:
            data: Data to encrypt
            kms_key_id: KMS key ID

        Returns:
            Encrypted envelope with data key and ciphertext
        """
        # Generate data encryption key
        plaintext_key, encrypted_key = await self.kms.generate_data_key(kms_key_id)

        # Use data key to encrypt data
        fernet = Fernet(base64.urlsafe_b64encode(plaintext_key[:32]))
        encrypted_data = fernet.encrypt(data)

        return {
            "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
            "encrypted_data": encrypted_data.decode("utf-8"),
            "kms_key_id": kms_key_id,
            "algorithm": "AES-256-GCM",
        }

    async def decrypt_envelope(self, envelope: dict[str, Any]) -> bytes:
        """Decrypt envelope encrypted data.

        Args:
            envelope: Encrypted envelope

        Returns:
            Decrypted data
        """
        # Decrypt the data key
        encrypted_key = base64.b64decode(envelope["encrypted_key"])
        plaintext_key = await self.kms.decrypt(encrypted_key)

        # Use data key to decrypt data
        fernet = Fernet(base64.urlsafe_b64encode(plaintext_key[:32]))
        return fernet.decrypt(envelope["encrypted_data"].encode("utf-8"))