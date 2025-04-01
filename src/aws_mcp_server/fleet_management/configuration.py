"""
Configuration Management System for AWS Fleet Management.

This module provides capabilities to manage configurations across
the fleet of AWS resources in a hierarchical, inheritable, and secure manner.
"""

import json
import logging
import asyncio
import copy
import uuid
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Union, Set
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class ConfigType(Enum):
    """Type of configuration."""
    GLOBAL = "global"
    ACCOUNT = "account"
    REGION = "region"
    RESOURCE_TYPE = "resource_type"
    RESOURCE_GROUP = "resource_group"
    RESOURCE = "resource"


class ConfigStatus(Enum):
    """Status of a configuration."""
    ACTIVE = "active"
    ARCHIVED = "archived"
    PENDING = "pending"


@dataclass
class ConfigChange:
    """Represents a change to a configuration."""
    timestamp: datetime
    user: str
    previous_value: Optional[Any] = None
    new_value: Optional[Any] = None
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "user": self.user,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
            "description": self.description
        }


@dataclass
class ConfigItem:
    """Represents a configuration item with history."""
    key: str
    value: Any
    encrypted: bool = False
    history: List[ConfigChange] = field(default_factory=list)
    
    def update(self, new_value: Any, user: str, description: str = "") -> None:
        """Update the value and record the change in history."""
        change = ConfigChange(
            timestamp=datetime.now(),
            user=user,
            previous_value=self.value,
            new_value=new_value,
            description=description
        )
        self.value = new_value
        self.history.append(change)
    
    def to_dict(self, include_history: bool = False) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "key": self.key,
            "value": self.value,
            "encrypted": self.encrypted
        }
        
        if include_history:
            result["history"] = [change.to_dict() for change in self.history]
        
        return result


@dataclass
class ConfigSet:
    """A set of related configuration items."""
    id: str
    name: str
    config_type: ConfigType
    scope: str  # e.g., account ID, region, resource type, resource ID
    items: Dict[str, ConfigItem] = field(default_factory=dict)
    parent_id: Optional[str] = None
    status: ConfigStatus = ConfigStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    
    def get_item(self, key: str) -> Optional[ConfigItem]:
        """Get a configuration item by key."""
        return self.items.get(key)
    
    def set_item(self, key: str, value: Any, user: str, 
                encrypted: bool = False, description: str = "") -> None:
        """Set a configuration item."""
        if key in self.items:
            self.items[key].update(value, user, description)
        else:
            config_item = ConfigItem(key=key, value=value, encrypted=encrypted)
            config_item.update(value, user, description)
            self.items[key] = config_item
        
        self.updated_at = datetime.now()
    
    def delete_item(self, key: str, user: str, description: str = "") -> bool:
        """Delete a configuration item."""
        if key in self.items:
            # We don't actually delete, just set to None to maintain history
            self.items[key].update(None, user, f"Deleted: {description}")
            self.updated_at = datetime.now()
            return True
        return False
    
    def to_dict(self, include_history: bool = False) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "config_type": self.config_type.value,
            "scope": self.scope,
            "parent_id": self.parent_id,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "items": {
                key: item.to_dict(include_history) 
                for key, item in self.items.items()
            }
        }


class ConfigEncryption:
    """Handles encryption and decryption of sensitive configuration values."""
    
    _instance = None
    _key = None
    
    @classmethod
    def initialize(cls, master_key: str) -> None:
        """Initialize the encryption system with a master key."""
        # Generate a key from the master key using PBKDF2
        salt = b'aws-mcp-server-fleet-management'  # Fixed salt for consistency
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        cls._key = key
    
    @classmethod
    def get_instance(cls) -> 'ConfigEncryption':
        """Get the singleton instance."""
        if cls._instance is None:
            cls._instance = ConfigEncryption()
        return cls._instance
    
    def encrypt(self, value: str) -> str:
        """Encrypt a value."""
        if self._key is None:
            raise ValueError("Encryption not initialized. Call initialize() first.")
        
        f = Fernet(self._key)
        encrypted = f.encrypt(value.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt a value."""
        if self._key is None:
            raise ValueError("Encryption not initialized. Call initialize() first.")
        
        f = Fernet(self._key)
        encrypted = base64.urlsafe_b64decode(encrypted_value.encode())
        return f.decrypt(encrypted).decode()


class ConfigRegistry:
    """Registry for managing configurations."""
    
    _config_sets: Dict[str, ConfigSet] = {}
    _config_hierarchy: Dict[str, List[str]] = {}  # parent_id -> list of child ids
    
    @classmethod
    def register_config_set(cls, config_set: ConfigSet) -> None:
        """Register a configuration set."""
        cls._config_sets[config_set.id] = config_set
        
        # Update hierarchy
        if config_set.parent_id:
            if config_set.parent_id not in cls._config_hierarchy:
                cls._config_hierarchy[config_set.parent_id] = []
            cls._config_hierarchy[config_set.parent_id].append(config_set.id)
    
    @classmethod
    def get_config_set(cls, config_id: str) -> Optional[ConfigSet]:
        """Get a configuration set by ID."""
        return cls._config_sets.get(config_id)
    
    @classmethod
    def get_config_sets_by_type(cls, config_type: ConfigType) -> List[ConfigSet]:
        """Get all configuration sets of a specific type."""
        return [
            config for config in cls._config_sets.values()
            if config.config_type == config_type
        ]
    
    @classmethod
    def get_config_sets_by_scope(cls, config_type: ConfigType, scope: str) -> List[ConfigSet]:
        """Get all configuration sets for a specific scope."""
        return [
            config for config in cls._config_sets.values()
            if config.config_type == config_type and config.scope == scope
        ]
    
    @classmethod
    def get_config_children(cls, config_id: str) -> List[ConfigSet]:
        """Get all child configurations of a configuration set."""
        child_ids = cls._config_hierarchy.get(config_id, [])
        return [cls._config_sets[child_id] for child_id in child_ids]
    
    @classmethod
    def delete_config_set(cls, config_id: str) -> bool:
        """Delete a configuration set (mark as archived)."""
        config_set = cls.get_config_set(config_id)
        if not config_set:
            return False
        
        config_set.status = ConfigStatus.ARCHIVED
        return True


class ConfigManager:
    """Manager for handling configurations across the fleet."""
    
    @classmethod
    def create_config_set(
        cls, name: str, config_type: ConfigType, scope: str,
        parent_id: Optional[str] = None
    ) -> ConfigSet:
        """Create a new configuration set."""
        config_id = f"config-{uuid.uuid4()}"
        config_set = ConfigSet(
            id=config_id,
            name=name,
            config_type=config_type,
            scope=scope,
            parent_id=parent_id
        )
        
        ConfigRegistry.register_config_set(config_set)
        return config_set
    
    @classmethod
    def get_effective_config(
        cls, config_type: ConfigType, scope: str,
        keys: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Get the effective configuration for a scope by resolving inheritance.
        
        Args:
            config_type: Type of configuration to resolve
            scope: Scope identifier (e.g., account ID, region)
            keys: Optional list of specific keys to retrieve
            
        Returns:
            Dictionary of effective configuration values
        """
        # Find direct configurations for this scope
        configs = ConfigRegistry.get_config_sets_by_scope(config_type, scope)
        
        if not configs:
            return {}
        
        # Use the first one for simplicity
        # In a real implementation, we might need more complex merging logic
        config = configs[0]
        
        # Build inheritance chain
        inheritance_chain = []
        current = config
        
        while current:
            inheritance_chain.append(current)
            if current.parent_id:
                current = ConfigRegistry.get_config_set(current.parent_id)
            else:
                current = None
        
        # Process inheritance chain in reverse (from most general to most specific)
        inheritance_chain.reverse()
        
        # Resolve values
        result = {}
        
        for config_set in inheritance_chain:
            # Add items from this config set, overriding previous values
            for key, item in config_set.items.items():
                if not keys or key in keys:
                    # Skip deleted items (value is None)
                    if item.value is not None:
                        # Handle encrypted values
                        if item.encrypted:
                            try:
                                encryption = ConfigEncryption.get_instance()
                                decrypted = encryption.decrypt(item.value)
                                result[key] = decrypted
                            except Exception as e:
                                logger.error(f"Error decrypting value for key {key}: {e}")
                                # Skip this item if decryption fails
                                continue
                        else:
                            result[key] = item.value
        
        return result
    
    @classmethod
    def set_config_value(
        cls, config_id: str, key: str, value: Any,
        user: str, encrypted: bool = False, description: str = ""
    ) -> bool:
        """Set a configuration value."""
        config_set = ConfigRegistry.get_config_set(config_id)
        if not config_set:
            return False
        
        # Encrypt if needed
        if encrypted and isinstance(value, str):
            try:
                encryption = ConfigEncryption.get_instance()
                value = encryption.encrypt(value)
            except Exception as e:
                logger.error(f"Error encrypting value for key {key}: {e}")
                return False
        
        config_set.set_item(key, value, user, encrypted, description)
        return True
    
    @classmethod
    def get_config_value(cls, config_id: str, key: str) -> Optional[Any]:
        """Get a configuration value directly (without inheritance resolution)."""
        config_set = ConfigRegistry.get_config_set(config_id)
        if not config_set:
            return None
        
        item = config_set.get_item(key)
        if not item or item.value is None:
            return None
        
        # Decrypt if needed
        if item.encrypted:
            try:
                encryption = ConfigEncryption.get_instance()
                return encryption.decrypt(item.value)
            except Exception as e:
                logger.error(f"Error decrypting value for key {key}: {e}")
                return None
        
        return item.value
    
    @classmethod
    def delete_config_value(cls, config_id: str, key: str, user: str, description: str = "") -> bool:
        """Delete a configuration value."""
        config_set = ConfigRegistry.get_config_set(config_id)
        if not config_set:
            return False
        
        return config_set.delete_item(key, user, description)


# Initialize a global configuration set
def initialize_configuration():
    """Initialize the configuration system with default settings."""
    global_config = ConfigManager.create_config_set(
        name="Global Configuration",
        config_type=ConfigType.GLOBAL,
        scope="global"
    )
    
    # Set some default values
    ConfigManager.set_config_value(
        config_id=global_config.id,
        key="discovery.parallel_threads",
        value=10,
        user="system",
        description="Default number of parallel threads for resource discovery"
    )
    
    ConfigManager.set_config_value(
        config_id=global_config.id,
        key="discovery.cache_ttl_seconds",
        value=300,
        user="system",
        description="Default cache TTL for discovered resources"
    )
    
    ConfigManager.set_config_value(
        config_id=global_config.id,
        key="deployment.max_concurrent",
        value=5,
        user="system",
        description="Default maximum concurrent deployments"
    )
    
    logger.info(f"Initialized global configuration with ID: {global_config.id}")
    return global_config.id 