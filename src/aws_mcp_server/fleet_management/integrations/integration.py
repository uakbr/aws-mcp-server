"""
Integration System for AWS Fleet Management.

This module provides base infrastructure for external system integrations.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    """Types of integrations supported by the system."""
    WEBHOOK = "webhook"
    REST_API = "rest_api"
    GRAPHQL = "graphql"
    GRPC = "grpc"
    EVENT_BUS = "event_bus"
    MESSAGE_QUEUE = "message_queue"
    DATABASE = "database"
    FILE = "file"
    CUSTOM = "custom"


class Direction(Enum):
    """Direction of data flow for the integration."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"


class AuthType(Enum):
    """Authentication types for integrations."""
    NONE = "none"
    API_KEY = "api_key"
    BASIC = "basic"
    BEARER_TOKEN = "bearer_token"
    OAUTH2 = "oauth2"
    OAUTH1 = "oauth1"
    AWS_SIG_V4 = "aws_sig_v4"
    CERTIFICATE = "certificate"
    CUSTOM = "custom"


class IntegrationStatus(Enum):
    """Status of an integration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    CONFIGURING = "configuring"
    TESTING = "testing"
    DEPRECATED = "deprecated"


@dataclass
class HealthCheckConfig:
    """Configuration for integration health checks."""
    enabled: bool = True
    interval_seconds: int = 300
    timeout_seconds: int = 30
    failure_threshold: int = 3
    success_threshold: int = 1
    endpoint: Optional[str] = None
    method: str = "GET"
    expected_status_code: int = 200
    body: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    enabled: bool = True
    max_attempts: int = 3
    initial_backoff_seconds: float = 1.0
    max_backoff_seconds: float = 60.0
    backoff_multiplier: float = 2.0
    retry_on_status_codes: List[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])


@dataclass
class AuthConfig:
    """Authentication configuration for integration."""
    type: AuthType = AuthType.NONE
    credentials_key: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntegrationConfig:
    """Configuration for an integration."""
    name: str
    description: str
    type: IntegrationType
    direction: Direction
    version: str = "1.0.0"
    auth: AuthConfig = field(default_factory=AuthConfig)
    health_check: HealthCheckConfig = field(default_factory=HealthCheckConfig)
    retry: RetryConfig = field(default_factory=RetryConfig)
    timeout_seconds: int = 30
    rate_limit_per_minute: int = 60
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class Integration:
    """
    Base class for all integrations.
    
    This class defines the common interface and base functionality
    for all integration types.
    """
    id: str
    config: IntegrationConfig
    status: IntegrationStatus = IntegrationStatus.INACTIVE
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    failure_count: int = 0
    success_count: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    async def initialize(self) -> bool:
        """
        Initialize the integration.
        
        Returns:
            True if initialization was successful, False otherwise
        """
        logger.info(f"Initializing integration: {self.config.name} ({self.id})")
        
        try:
            # Perform any necessary setup
            self.status = IntegrationStatus.ACTIVE
            self.updated_at = datetime.utcnow()
            return True
        except Exception as e:
            logger.error(f"Failed to initialize integration {self.id}: {str(e)}")
            self.status = IntegrationStatus.ERROR
            self.updated_at = datetime.utcnow()
            self.last_failure = datetime.utcnow()
            self.failure_count += 1
            return False
    
    async def shutdown(self) -> None:
        """Shut down the integration and clean up resources."""
        logger.info(f"Shutting down integration: {self.config.name} ({self.id})")
        self.status = IntegrationStatus.INACTIVE
        self.updated_at = datetime.utcnow()
    
    async def health_check(self) -> bool:
        """
        Perform a health check for the integration.
        
        Returns:
            True if the integration is healthy, False otherwise
        """
        if not self.config.health_check.enabled or self.status != IntegrationStatus.ACTIVE:
            return self.status == IntegrationStatus.ACTIVE
        
        try:
            logger.debug(f"Performing health check for integration: {self.id}")
            # Perform health check based on configuration
            # This is a base implementation that should be overridden by subclasses
            
            # Update status based on health check
            self.last_success = datetime.utcnow()
            self.success_count += 1
            
            # If we've had failures and now we're successful, reset failure count
            if self.failure_count >= self.config.health_check.failure_threshold:
                logger.info(f"Integration {self.id} recovered after {self.failure_count} failures")
                self.failure_count = 0
                
            return True
        except Exception as e:
            logger.warning(f"Health check failed for integration {self.id}: {str(e)}")
            self.last_failure = datetime.utcnow()
            self.failure_count += 1
            
            # If we've crossed the failure threshold, mark as error
            if self.failure_count >= self.config.health_check.failure_threshold:
                logger.error(f"Integration {self.id} marked as ERROR after {self.failure_count} failures")
                self.status = IntegrationStatus.ERROR
                
            return False
    
    async def to_dict(self) -> Dict[str, Any]:
        """Convert the integration to a dictionary."""
        return {
            "id": self.id,
            "config": {
                "name": self.config.name,
                "description": self.config.description,
                "type": self.config.type.value,
                "direction": self.config.direction.value,
                "version": self.config.version,
                "enabled": self.config.enabled,
                "timeout_seconds": self.config.timeout_seconds,
                "rate_limit_per_minute": self.config.rate_limit_per_minute,
                "tags": self.config.tags,
                "metadata": self.config.metadata,
            },
            "status": self.status.value,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_failure": self.last_failure.isoformat() if self.last_failure else None,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
    
    @classmethod
    async def from_dict(cls, data: Dict[str, Any]) -> 'Integration':
        """
        Create an integration from a dictionary.
        
        Args:
            data: Dictionary of integration data
            
        Returns:
            Integration instance
        """
        config_data = data.get("config", {})
        
        integration_type = IntegrationType(config_data.get("type", "custom"))
        direction = Direction(config_data.get("direction", "bidirectional"))
        
        # Create auth config
        auth_data = config_data.get("auth", {})
        auth_config = AuthConfig(
            type=AuthType(auth_data.get("type", "none")),
            credentials_key=auth_data.get("credentials_key"),
            config=auth_data.get("config", {})
        )
        
        # Create health check config
        health_check_data = config_data.get("health_check", {})
        health_check_config = HealthCheckConfig(
            enabled=health_check_data.get("enabled", True),
            interval_seconds=health_check_data.get("interval_seconds", 300),
            timeout_seconds=health_check_data.get("timeout_seconds", 30),
            failure_threshold=health_check_data.get("failure_threshold", 3),
            success_threshold=health_check_data.get("success_threshold", 1),
            endpoint=health_check_data.get("endpoint"),
            method=health_check_data.get("method", "GET"),
            expected_status_code=health_check_data.get("expected_status_code", 200),
            body=health_check_data.get("body"),
            headers=health_check_data.get("headers", {})
        )
        
        # Create retry config
        retry_data = config_data.get("retry", {})
        retry_config = RetryConfig(
            enabled=retry_data.get("enabled", True),
            max_attempts=retry_data.get("max_attempts", 3),
            initial_backoff_seconds=retry_data.get("initial_backoff_seconds", 1.0),
            max_backoff_seconds=retry_data.get("max_backoff_seconds", 60.0),
            backoff_multiplier=retry_data.get("backoff_multiplier", 2.0),
            retry_on_status_codes=retry_data.get("retry_on_status_codes", [429, 500, 502, 503, 504])
        )
        
        # Create integration config
        integration_config = IntegrationConfig(
            name=config_data.get("name", "Unknown"),
            description=config_data.get("description", ""),
            type=integration_type,
            direction=direction,
            version=config_data.get("version", "1.0.0"),
            auth=auth_config,
            health_check=health_check_config,
            retry=retry_config,
            timeout_seconds=config_data.get("timeout_seconds", 30),
            rate_limit_per_minute=config_data.get("rate_limit_per_minute", 60),
            tags=config_data.get("tags", {}),
            metadata=config_data.get("metadata", {}),
            enabled=config_data.get("enabled", True)
        )
        
        # Create integration instance
        integration = cls(
            id=data.get("id", ""),
            config=integration_config,
            status=IntegrationStatus(data.get("status", "inactive")),
            failure_count=data.get("failure_count", 0),
            success_count=data.get("success_count", 0),
            created_at=datetime.fromisoformat(data.get("created_at", datetime.utcnow().isoformat())),
            updated_at=datetime.fromisoformat(data.get("updated_at", datetime.utcnow().isoformat())),
        )
        
        # Set optional fields
        if data.get("last_success"):
            integration.last_success = datetime.fromisoformat(data["last_success"])
        
        if data.get("last_failure"):
            integration.last_failure = datetime.fromisoformat(data["last_failure"])
        
        return integration


class IntegrationRegistry:
    """
    Registry for managing integrations.
    
    This class handles registration, lookup, and lifecycle management
    of all integrations in the system.
    """
    
    def __init__(self, data_dir: Optional[str] = None):
        """
        Initialize the integration registry.
        
        Args:
            data_dir: Optional directory for persisting integration data
        """
        self.integrations: Dict[str, Integration] = {}
        self.data_dir = Path(data_dir) if data_dir else None
        self._health_check_task = None
        
        # Initialize base plugin types
        self.plugin_types: Dict[IntegrationType, Type[Integration]] = {
            IntegrationType.WEBHOOK: Integration,
            IntegrationType.REST_API: Integration,
            IntegrationType.GRAPHQL: Integration,
            IntegrationType.GRPC: Integration,
            IntegrationType.EVENT_BUS: Integration,
            IntegrationType.MESSAGE_QUEUE: Integration,
            IntegrationType.DATABASE: Integration,
            IntegrationType.FILE: Integration,
            IntegrationType.CUSTOM: Integration,
        }
    
    async def initialize(self) -> None:
        """Initialize the registry and load existing integrations."""
        logger.info("Initializing integration registry")
        
        if self.data_dir:
            self.data_dir.mkdir(exist_ok=True, parents=True)
            await self._load_integrations()
        
        # Start health check task
        self._health_check_task = asyncio.create_task(self._health_check_loop())
    
    async def shutdown(self) -> None:
        """Shut down the registry and all integrations."""
        logger.info("Shutting down integration registry")
        
        # Cancel health check task
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        # Shut down all integrations
        for integration in self.integrations.values():
            await integration.shutdown()
        
        # Save integration data
        if self.data_dir:
            await self._save_integrations()
    
    async def register_integration(self, config: IntegrationConfig) -> str:
        """
        Register a new integration.
        
        Args:
            config: Integration configuration
            
        Returns:
            ID of the registered integration
            
        Raises:
            ValueError: If an integration with the same name already exists
        """
        # Check if integration with the same name already exists
        for integration in self.integrations.values():
            if integration.config.name == config.name:
                raise ValueError(f"Integration with name '{config.name}' already exists")
        
        # Generate a unique ID
        integration_id = f"{config.name.lower().replace(' ', '_')}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        # Create integration instance
        integration_class = self.plugin_types.get(config.type, Integration)
        integration = integration_class(
            id=integration_id,
            config=config,
            status=IntegrationStatus.CONFIGURING
        )
        
        # Initialize the integration
        success = await integration.initialize()
        
        if success:
            # Add to registry
            self.integrations[integration_id] = integration
            
            # Save integration data
            if self.data_dir:
                await self._save_integration(integration)
            
            logger.info(f"Registered integration: {config.name} ({integration_id})")
            return integration_id
        else:
            logger.error(f"Failed to register integration: {config.name}")
            raise ValueError(f"Failed to initialize integration: {config.name}")
    
    async def update_integration(self, integration_id: str, config: IntegrationConfig) -> bool:
        """
        Update an existing integration.
        
        Args:
            integration_id: ID of the integration to update
            config: New integration configuration
            
        Returns:
            True if successful, False if integration not found
            
        Raises:
            ValueError: If the update fails
        """
        # Check if integration exists
        if integration_id not in self.integrations:
            return False
        
        # Get existing integration
        integration = self.integrations[integration_id]
        
        # Shut down existing integration
        await integration.shutdown()
        
        # Update config
        integration.config = config
        integration.updated_at = datetime.utcnow()
        
        # Re-initialize
        success = await integration.initialize()
        
        if success:
            # Save integration data
            if self.data_dir:
                await self._save_integration(integration)
            
            logger.info(f"Updated integration: {config.name} ({integration_id})")
            return True
        else:
            logger.error(f"Failed to update integration: {integration_id}")
            raise ValueError(f"Failed to initialize updated integration: {integration_id}")
    
    async def delete_integration(self, integration_id: str) -> bool:
        """
        Delete an integration.
        
        Args:
            integration_id: ID of the integration to delete
            
        Returns:
            True if successful, False if integration not found
        """
        # Check if integration exists
        if integration_id not in self.integrations:
            return False
        
        # Get integration
        integration = self.integrations[integration_id]
        
        # Shut down integration
        await integration.shutdown()
        
        # Remove from registry
        del self.integrations[integration_id]
        
        # Delete integration data
        if self.data_dir:
            data_file = self.data_dir / f"{integration_id}.json"
            if data_file.exists():
                data_file.unlink()
        
        logger.info(f"Deleted integration: {integration.config.name} ({integration_id})")
        return True
    
    async def get_integration(self, integration_id: str) -> Optional[Integration]:
        """
        Get an integration by ID.
        
        Args:
            integration_id: ID of the integration to get
            
        Returns:
            Integration if found, None otherwise
        """
        return self.integrations.get(integration_id)
    
    async def get_integrations(
        self,
        type_filter: Optional[IntegrationType] = None,
        status_filter: Optional[IntegrationStatus] = None,
        enabled_only: bool = False
    ) -> List[Integration]:
        """
        Get all integrations matching the given filters.
        
        Args:
            type_filter: Optional filter by integration type
            status_filter: Optional filter by integration status
            enabled_only: If True, only return enabled integrations
            
        Returns:
            List of matching integrations
        """
        result = []
        
        for integration in self.integrations.values():
            if type_filter and integration.config.type != type_filter:
                continue
                
            if status_filter and integration.status != status_filter:
                continue
                
            if enabled_only and not integration.config.enabled:
                continue
                
            result.append(integration)
            
        return result
    
    async def register_plugin_type(
        self,
        integration_type: IntegrationType,
        plugin_class: Type[Integration]
    ) -> None:
        """
        Register a custom plugin type.
        
        Args:
            integration_type: Type of integration
            plugin_class: Class for the integration type
            
        Raises:
            ValueError: If the plugin class is not a subclass of Integration
        """
        if not issubclass(plugin_class, Integration):
            raise ValueError(f"Plugin class must be a subclass of Integration: {plugin_class.__name__}")
            
        self.plugin_types[integration_type] = plugin_class
        logger.info(f"Registered plugin type: {integration_type.value} -> {plugin_class.__name__}")
    
    async def _health_check_loop(self) -> None:
        """Periodically check the health of all integrations."""
        try:
            while True:
                # Find the smallest health check interval
                min_interval = 300  # Default: 5 minutes
                
                for integration in self.integrations.values():
                    if integration.config.enabled and integration.config.health_check.enabled:
                        min_interval = min(min_interval, integration.config.health_check.interval_seconds)
                
                # Sleep for the minimum interval
                await asyncio.sleep(min_interval)
                
                # Check each integration
                for integration_id, integration in list(self.integrations.items()):
                    if not integration.config.enabled or not integration.config.health_check.enabled:
                        continue
                        
                    try:
                        # Check if it's time to run this integration's health check
                        current_time = datetime.utcnow().timestamp()
                        last_check_time = (integration.last_success or integration.last_failure or integration.created_at).timestamp()
                        
                        if current_time - last_check_time >= integration.config.health_check.interval_seconds:
                            is_healthy = await integration.health_check()
                            
                            logger.debug(f"Health check for {integration_id}: {'healthy' if is_healthy else 'unhealthy'}")
                            
                            # Save updated status
                            if self.data_dir:
                                await self._save_integration(integration)
                    except Exception as e:
                        logger.error(f"Error during health check for integration {integration_id}: {str(e)}")
        except asyncio.CancelledError:
            logger.info("Health check loop cancelled")
        except Exception as e:
            logger.error(f"Unexpected error in health check loop: {str(e)}")
    
    async def _load_integrations(self) -> None:
        """Load integrations from the data directory."""
        if not self.data_dir or not self.data_dir.exists():
            return
            
        for data_file in self.data_dir.glob("*.json"):
            try:
                with open(data_file, "r") as f:
                    integration_data = json.load(f)
                    
                integration = await Integration.from_dict(integration_data)
                
                # Initialize the integration
                success = await integration.initialize()
                
                if success:
                    self.integrations[integration.id] = integration
                    logger.info(f"Loaded integration: {integration.config.name} ({integration.id})")
                else:
                    logger.error(f"Failed to initialize loaded integration: {integration.id}")
            except Exception as e:
                logger.error(f"Error loading integration from {data_file}: {str(e)}")
    
    async def _save_integrations(self) -> None:
        """Save all integrations to the data directory."""
        if not self.data_dir:
            return
            
        self.data_dir.mkdir(exist_ok=True, parents=True)
        
        for integration in self.integrations.values():
            await self._save_integration(integration)
    
    async def _save_integration(self, integration: Integration) -> None:
        """Save an integration to the data directory."""
        if not self.data_dir:
            return
            
        self.data_dir.mkdir(exist_ok=True, parents=True)
        
        try:
            data = await integration.to_dict()
            
            with open(self.data_dir / f"{integration.id}.json", "w") as f:
                json.dump(data, f, indent=2)
                
            logger.debug(f"Saved integration data: {integration.id}")
        except Exception as e:
            logger.error(f"Error saving integration {integration.id}: {str(e)}") 