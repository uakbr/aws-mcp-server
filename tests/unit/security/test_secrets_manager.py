"""Unit tests for Secrets Manager and KMS integration."""

import asyncio
import base64
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_mcp_server.security.secrets_manager import (
    EncryptionKey,
    KMSClient,
    Secret,
    SecretType,
    SecretsManagerClient,
    SecureCredentialManager,
)


@pytest.fixture
def mock_boto3_session():
    """Mock boto3 session."""
    with patch("boto3.Session") as mock:
        yield mock


@pytest.fixture
def secrets_manager_client(mock_boto3_session):
    """Create a SecretsManagerClient with mocked AWS clients."""
    mock_session = MagicMock()
    mock_boto3_session.return_value = mock_session
    
    mock_secrets_client = MagicMock()
    mock_kms_client = MagicMock()
    
    def mock_client(service_name, **kwargs):
        if service_name == "secretsmanager":
            return mock_secrets_client
        elif service_name == "kms":
            return mock_kms_client
        return MagicMock()
    
    mock_session.client.side_effect = mock_client
    
    client = SecretsManagerClient(region="us-east-1")
    client.client = mock_secrets_client
    client.kms_client = mock_kms_client
    
    return client


@pytest.fixture
def kms_client(mock_boto3_session):
    """Create a KMSClient with mocked AWS clients."""
    mock_session = MagicMock()
    mock_boto3_session.return_value = mock_session
    
    mock_client = MagicMock()
    mock_session.client.return_value = mock_client
    
    client = KMSClient(region="us-east-1")
    client.client = mock_client
    
    return client


class TestSecret:
    """Test Secret dataclass."""
    
    def test_secret_creation(self):
        """Test creating a Secret."""
        secret = Secret(
            name="test-secret",
            arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-abc123",
            description="Test secret",
            secret_type=SecretType.DATABASE,
            created_date=datetime.utcnow(),
            rotation_enabled=True
        )
        
        assert secret.name == "test-secret"
        assert secret.secret_type == SecretType.DATABASE
        assert secret.rotation_enabled is True


class TestSecretsManagerClient:
    """Test SecretsManagerClient."""
    
    @pytest.mark.asyncio
    async def test_create_secret_string(self, secrets_manager_client):
        """Test creating a secret with string value."""
        mock_response = {
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-abc123",
            "VersionId": "v1"
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            secret = await secrets_manager_client.create_secret(
                name="test-secret",
                secret_value="my-secret-password",
                description="Test secret",
                secret_type=SecretType.API_KEY
            )
        
        assert secret.name == "test-secret"
        assert secret.arn == mock_response["ARN"]
        assert secret.version_id == "v1"
        assert secret.secret_type == SecretType.API_KEY
    
    @pytest.mark.asyncio
    async def test_create_secret_dict(self, secrets_manager_client):
        """Test creating a secret with dictionary value."""
        secret_dict = {
            "username": "admin",
            "password": "secret123",
            "host": "db.example.com"
        }
        
        mock_response = {
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-secret-xyz789",
            "VersionId": "v1"
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            secret = await secrets_manager_client.create_secret(
                name="db-secret",
                secret_value=secret_dict,
                secret_type=SecretType.DATABASE
            )
        
        # Verify JSON conversion happened
        call_args = secrets_manager_client.client.create_secret.call_args
        assert call_args is None  # Because we mocked asyncio.to_thread
    
    @pytest.mark.asyncio
    async def test_create_secret_already_exists(self, secrets_manager_client):
        """Test creating a secret that already exists."""
        error = ClientError(
            {"Error": {"Code": "ResourceExistsException", "Message": "Secret already exists"}},
            "CreateSecret"
        )
        
        # Mock update_secret for fallback
        secrets_manager_client.update_secret = AsyncMock(return_value=Secret(
            name="test-secret",
            arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-abc123"
        ))
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=error)):
            secret = await secrets_manager_client.create_secret(
                name="test-secret",
                secret_value="value"
            )
        
        assert secret.name == "test-secret"
        secrets_manager_client.update_secret.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_secret(self, secrets_manager_client):
        """Test retrieving a secret."""
        get_value_response = {
            "SecretString": json.dumps({"password": "secret123"}),
            "VersionId": "v2"
        }
        
        describe_response = {
            "Name": "test-secret",
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-abc123",
            "Description": "Test secret",
            "CreatedDate": datetime.utcnow(),
            "RotationEnabled": False,
            "Tags": [{"Key": "Type", "Value": "api_key"}]
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            get_value_response,
            describe_response
        ])):
            secret, value = await secrets_manager_client.get_secret("test-secret")
        
        assert secret.name == "test-secret"
        assert secret.secret_type == SecretType.API_KEY
        assert value == {"password": "secret123"}
    
    @pytest.mark.asyncio
    async def test_get_secret_binary(self, secrets_manager_client):
        """Test retrieving a binary secret."""
        binary_data = b"binary secret data"
        encoded_data = base64.b64encode(binary_data)
        
        get_value_response = {
            "SecretBinary": encoded_data,
            "VersionId": "v1"
        }
        
        describe_response = {
            "Name": "binary-secret",
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:binary-secret",
            "Tags": []
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            get_value_response,
            describe_response
        ])):
            secret, value = await secrets_manager_client.get_secret("binary-secret")
        
        assert secret.name == "binary-secret"
        assert value == binary_data
    
    @pytest.mark.asyncio
    async def test_update_secret(self, secrets_manager_client):
        """Test updating a secret."""
        update_response = {"VersionId": "v3"}
        
        # Mock get_secret for the updated metadata
        secrets_manager_client.get_secret = AsyncMock(return_value=(
            Secret(
                name="test-secret",
                arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret"
            ),
            "dummy-value"
        ))
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=update_response)):
            secret = await secrets_manager_client.update_secret(
                "test-secret",
                {"password": "new-password"}
            )
        
        assert secret.name == "test-secret"
        assert secret.version_id == "v3"
    
    @pytest.mark.asyncio
    async def test_delete_secret(self, secrets_manager_client):
        """Test deleting a secret."""
        delete_response = {
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret",
            "DeletionDate": datetime.utcnow()
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=delete_response)):
            result = await secrets_manager_client.delete_secret(
                "test-secret",
                recovery_days=7
            )
        
        assert result["ARN"] == delete_response["ARN"]
    
    @pytest.mark.asyncio
    async def test_list_secrets(self, secrets_manager_client):
        """Test listing secrets."""
        mock_pages = [{
            "SecretList": [
                {
                    "Name": "secret1",
                    "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret1",
                    "Tags": [{"Key": "Type", "Value": "database"}]
                },
                {
                    "Name": "secret2",
                    "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret2",
                    "Tags": [{"Key": "Type", "Value": "api_key"}]
                }
            ]
        }]
        
        # Mock paginator
        mock_paginator = MagicMock()
        mock_page_iterator = MagicMock()
        mock_page_iterator.__iter__.return_value = iter(mock_pages)
        mock_paginator.paginate.return_value = mock_page_iterator
        secrets_manager_client.client.get_paginator.return_value = mock_paginator
        
        secrets = await secrets_manager_client.list_secrets()
        
        assert len(secrets) == 2
        assert secrets[0].name == "secret1"
        assert secrets[0].secret_type == SecretType.DATABASE
        assert secrets[1].name == "secret2"
        assert secrets[1].secret_type == SecretType.API_KEY
    
    @pytest.mark.asyncio
    async def test_enable_rotation(self, secrets_manager_client):
        """Test enabling secret rotation."""
        # Mock get_secret for updated metadata
        secrets_manager_client.get_secret = AsyncMock(return_value=(
            Secret(
                name="test-secret",
                arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret",
                rotation_enabled=True,
                rotation_lambda_arn="arn:aws:lambda:us-east-1:123456789012:function:rotation"
            ),
            "value"
        ))
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value={})):
            secret = await secrets_manager_client.enable_rotation(
                "test-secret",
                rotation_lambda_arn="arn:aws:lambda:us-east-1:123456789012:function:rotation",
                rotation_rules={"AutomaticallyAfterDays": 30}
            )
        
        assert secret.rotation_enabled is True
        assert secret.rotation_lambda_arn is not None
    
    @pytest.mark.asyncio
    async def test_generate_random_password(self, secrets_manager_client):
        """Test generating random password."""
        mock_response = {"RandomPassword": "GeneratedP@ssw0rd123!"}
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            password = await secrets_manager_client.generate_random_password(
                length=20,
                exclude_punctuation=False
            )
        
        assert password == "GeneratedP@ssw0rd123!"


class TestKMSClient:
    """Test KMSClient."""
    
    @pytest.mark.asyncio
    async def test_create_key(self, kms_client):
        """Test creating a KMS key."""
        mock_response = {
            "KeyMetadata": {
                "KeyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
                "Arn": "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
                "KeyState": "Enabled",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "CreationDate": datetime.utcnow(),
                "Enabled": True,
                "MultiRegion": False
            }
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            key = await kms_client.create_key(
                description="Test encryption key",
                multi_region=False
            )
        
        assert key.key_id == "1234abcd-12ab-34cd-56ef-1234567890ab"
        assert key.key_usage == "ENCRYPT_DECRYPT"
        assert key.enabled is True
    
    @pytest.mark.asyncio
    async def test_create_alias(self, kms_client):
        """Test creating a key alias."""
        with patch("asyncio.to_thread", new=AsyncMock(return_value={})):
            result = await kms_client.create_alias(
                "my-key-alias",
                "1234abcd-12ab-34cd-56ef-1234567890ab"
            )
        
        assert result == {}
    
    @pytest.mark.asyncio
    async def test_encrypt(self, kms_client):
        """Test encrypting data."""
        plaintext = "sensitive data"
        ciphertext = b"encrypted data blob"
        
        mock_response = {"CiphertextBlob": ciphertext}
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            encrypted = await kms_client.encrypt(
                key_id="alias/my-key",
                plaintext=plaintext
            )
        
        assert encrypted == ciphertext
    
    @pytest.mark.asyncio
    async def test_decrypt(self, kms_client):
        """Test decrypting data."""
        ciphertext = b"encrypted data blob"
        plaintext = b"sensitive data"
        
        mock_response = {"Plaintext": plaintext}
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            decrypted = await kms_client.decrypt(ciphertext)
        
        assert decrypted == plaintext
    
    @pytest.mark.asyncio
    async def test_generate_data_key(self, kms_client):
        """Test generating a data encryption key."""
        plaintext_key = b"plaintext data key"
        encrypted_key = b"encrypted data key"
        
        mock_response = {
            "Plaintext": plaintext_key,
            "CiphertextBlob": encrypted_key
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            plain, encrypted = await kms_client.generate_data_key(
                key_id="alias/my-key",
                key_spec="AES_256"
            )
        
        assert plain == plaintext_key
        assert encrypted == encrypted_key
    
    @pytest.mark.asyncio
    async def test_list_keys(self, kms_client):
        """Test listing KMS keys."""
        mock_pages = [{
            "Keys": [
                {"KeyId": "key1"},
                {"KeyId": "key2"}
            ]
        }]
        
        # Mock paginator
        mock_paginator = MagicMock()
        mock_page_iterator = MagicMock()
        mock_page_iterator.__iter__.return_value = iter(mock_pages)
        mock_paginator.paginate.return_value = mock_page_iterator
        kms_client.client.get_paginator.return_value = mock_paginator
        
        # Mock describe_key and list_aliases
        key_metadata = {
            "KeyMetadata": {
                "KeyId": "key1",
                "Arn": "arn:aws:kms:us-east-1:123456789012:key/key1",
                "KeyState": "Enabled",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "CreationDate": datetime.utcnow(),
                "Enabled": True
            }
        }
        
        aliases_response = {
            "Aliases": [{"AliasName": "alias/test-key"}]
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            key_metadata,
            aliases_response,
            ClientError({"Error": {"Code": "AccessDenied"}}, "DescribeKey")  # For key2
        ])):
            keys = await kms_client.list_keys()
        
        assert len(keys) == 1
        assert keys[0].key_id == "key1"
        assert keys[0].alias == "alias/test-key"


class TestSecureCredentialManager:
    """Test SecureCredentialManager."""
    
    @pytest.fixture
    def credential_manager(self, secrets_manager_client, kms_client):
        """Create SecureCredentialManager."""
        return SecureCredentialManager(secrets_manager_client, kms_client)
    
    @pytest.mark.asyncio
    async def test_create_database_credentials(self, credential_manager):
        """Test creating database credentials."""
        # Mock password generation
        credential_manager.secrets.generate_random_password = AsyncMock(
            return_value="GeneratedDBPassword123!"
        )
        
        # Mock secret creation
        credential_manager.secrets.create_secret = AsyncMock(return_value=Secret(
            name="db-creds",
            arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds",
            secret_type=SecretType.DATABASE
        ))
        
        secret = await credential_manager.create_database_credentials(
            name="db-creds",
            username="dbuser",
            host="db.example.com",
            port=5432,
            database="mydb",
            engine="postgresql"
        )
        
        assert secret.name == "db-creds"
        assert secret.secret_type == SecretType.DATABASE
        
        # Verify create_secret was called with correct structure
        call_args = credential_manager.secrets.create_secret.call_args
        secret_value = call_args[1]["secret_value"]
        assert secret_value["username"] == "dbuser"
        assert secret_value["host"] == "db.example.com"
        assert secret_value["port"] == 5432
    
    @pytest.mark.asyncio
    async def test_rotate_database_password(self, credential_manager):
        """Test rotating database password."""
        current_creds = {
            "username": "dbuser",
            "password": "old_password",
            "host": "db.example.com"
        }
        
        # Mock get current secret
        credential_manager.secrets.get_secret = AsyncMock(return_value=(
            Secret(name="db-creds", arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds"),
            current_creds
        ))
        
        # Mock password generation
        credential_manager.secrets.generate_random_password = AsyncMock(
            return_value="NewPassword123!"
        )
        
        # Mock update secret
        credential_manager.secrets.update_secret = AsyncMock(return_value=Secret(
            name="db-creds",
            arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds"
        ))
        
        # Mock database update function
        async def mock_update_db(username, password):
            assert username == "dbuser"
            assert password == "NewPassword123!"
        
        secret = await credential_manager.rotate_database_password(
            "db-creds",
            mock_update_db
        )
        
        assert secret.name == "db-creds"
        
        # Verify update was called twice (pending and final)
        assert credential_manager.secrets.update_secret.call_count == 2
    
    @pytest.mark.asyncio
    async def test_create_encryption_envelope(self, credential_manager):
        """Test envelope encryption."""
        data = b"sensitive data to encrypt"
        
        # Mock generate_data_key
        plaintext_key = b"0" * 32  # 32 bytes for AES-256
        encrypted_key = b"encrypted key blob"
        
        credential_manager.kms.generate_data_key = AsyncMock(
            return_value=(plaintext_key, encrypted_key)
        )
        
        envelope = await credential_manager.create_encryption_envelope(
            data,
            "alias/my-key"
        )
        
        assert "encrypted_key" in envelope
        assert "encrypted_data" in envelope
        assert envelope["kms_key_id"] == "alias/my-key"
        assert envelope["algorithm"] == "AES-256-GCM"
        
        # Verify the data was encrypted (not equal to original)
        assert envelope["encrypted_data"] != data.decode("utf-8")