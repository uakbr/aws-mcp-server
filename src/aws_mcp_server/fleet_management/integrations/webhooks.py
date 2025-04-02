"""
Webhook Integration System for AWS Fleet Management.

This module provides capabilities for integrating with external systems
via webhooks, including both outbound notifications and inbound webhooks.
"""

import hashlib
import hmac
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .integration import AuthConfig, Integration, IntegrationConfig
from .integration import IntegrationStatus, IntegrationType

logger = logging.getLogger(__name__)


class WebhookMethod(Enum):
    """HTTP methods supported for webhooks."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class WebhookContentType(Enum):
    """Content types supported for webhooks."""
    JSON = "application/json"
    XML = "application/xml"
    FORM = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    TEXT = "text/plain"
    HTML = "text/html"
    RAW = "application/octet-stream"


class SignatureMethod(Enum):
    """Signature methods for webhook verification."""
    HMAC_SHA256 = "hmac-sha256"
    HMAC_SHA1 = "hmac-sha1"
    HMAC_MD5 = "hmac-md5"
    BASIC_AUTH = "basic-auth"
    API_KEY = "api-key"
    CUSTOM = "custom"


@dataclass
class WebhookSignatureConfig:
    """Configuration for webhook signature verification."""
    enabled: bool = False
    method: SignatureMethod = SignatureMethod.HMAC_SHA256
    secret_key: Optional[str] = None
    header_name: str = "X-Signature"
    query_param: Optional[str] = None
    include_timestamp: bool = False
    timestamp_header: str = "X-Timestamp"
    timestamp_tolerance_seconds: int = 300


@dataclass
class WebhookConfig:
    """Configuration for a webhook."""
    path: str
    methods: List[WebhookMethod] = field(default_factory=lambda: [WebhookMethod.POST])
    content_types: List[WebhookContentType] = field(default_factory=lambda: [WebhookContentType.JSON])
    signature: WebhookSignatureConfig = field(default_factory=WebhookSignatureConfig)
    description: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    rate_limit_per_minute: int = 60
    timeout_seconds: int = 30


@dataclass
class WebhookRequest:
    """Representation of a webhook request."""
    id: str
    path: str
    method: WebhookMethod
    headers: Dict[str, str]
    query_params: Dict[str, str]
    body: Any
    content_type: WebhookContentType
    source_ip: str
    timestamp: datetime
    signature: Optional[str] = None


@dataclass
class WebhookResponse:
    """Representation of a webhook response."""
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Any] = None
    content_type: WebhookContentType = WebhookContentType.JSON


@dataclass
class WebhookContext:
    """Context for webhook processing."""
    request: WebhookRequest
    webhook: 'Webhook'
    timestamp: datetime = field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WebhookHandlerResult:
    """Result of webhook handler execution."""
    success: bool
    response: WebhookResponse
    error_message: Optional[str] = None
    execution_time_ms: float = 0


class WebhookHandler:
    """
    Base class for webhook handlers.
    
    This class defines the interface for webhook handlers that process
    incoming webhook requests and produce responses.
    """
    
    def __init__(self, name: str):
        """
        Initialize a webhook handler.
        
        Args:
            name: Name of the handler
        """
        self.name = name
    
    async def handle(self, context: WebhookContext) -> WebhookHandlerResult:
        """
        Handle a webhook request.
        
        Args:
            context: Webhook context
            
        Returns:
            Result of handling the webhook
        """
        start_time = time.time()
        
        try:
            # Default implementation just returns success
            response = WebhookResponse(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body={"message": "Webhook received successfully"},
                content_type=WebhookContentType.JSON
            )
            
            execution_time = (time.time() - start_time) * 1000
            
            return WebhookHandlerResult(
                success=True,
                response=response,
                execution_time_ms=execution_time
            )
        except Exception as e:
            logger.error(f"Error in webhook handler {self.name}: {str(e)}")
            
            execution_time = (time.time() - start_time) * 1000
            
            return WebhookHandlerResult(
                success=False,
                response=WebhookResponse(
                    status_code=500,
                    headers={"Content-Type": "application/json"},
                    body={"error": "Internal server error"},
                    content_type=WebhookContentType.JSON
                ),
                error_message=str(e),
                execution_time_ms=execution_time
            )


@dataclass
class WebhookEvent:
    """Event details for a webhook execution."""
    webhook_id: str
    request_id: str
    timestamp: datetime
    success: bool
    status_code: int
    execution_time_ms: float
    error_message: Optional[str] = None


class Webhook(Integration):
    """
    Webhook implementation.
    
    This class represents a webhook endpoint that can receive
    and process incoming HTTP requests.
    """
    
    def __init__(
        self,
        id: str,
        config: IntegrationConfig,
        webhook_config: WebhookConfig,
        handler: Optional[WebhookHandler] = None,
        status: IntegrationStatus = IntegrationStatus.INACTIVE
    ):
        """
        Initialize a webhook.
        
        Args:
            id: Unique ID for the webhook
            config: Integration configuration
            webhook_config: Webhook-specific configuration
            handler: Optional webhook handler
            status: Initial status
        """
        super().__init__(id, config, status)
        self.webhook_config = webhook_config
        self.handler = handler or WebhookHandler(config.name)
        self.events: List[WebhookEvent] = []
        self.request_counter = 0
        self._rate_limit_tokens = webhook_config.rate_limit_per_minute
        self._last_token_refill = datetime.utcnow()
    
    async def initialize(self) -> bool:
        """
        Initialize the webhook.
        
        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            # Validate webhook configuration
            if not self.webhook_config.path:
                raise ValueError("Webhook path is required")
                
            if not self.webhook_config.methods:
                raise ValueError("At least one HTTP method must be specified")
                
            # Initialize rate limiting
            self._rate_limit_tokens = self.webhook_config.rate_limit_per_minute
            self._last_token_refill = datetime.utcnow()
            
            # Call parent initialization
            return await super().initialize()
        except Exception as e:
            logger.error(f"Failed to initialize webhook {self.id}: {str(e)}")
            self.status = IntegrationStatus.ERROR
            self.updated_at = datetime.utcnow()
            self.last_failure = datetime.utcnow()
            self.failure_count += 1
            return False
    
    async def process_request(self, request: WebhookRequest) -> WebhookResponse:
        """
        Process an incoming webhook request.
        
        Args:
            request: Webhook request to process
            
        Returns:
            Response to the webhook request
        """
        # Check if webhook is active
        if self.status != IntegrationStatus.ACTIVE:
            logger.warning(f"Webhook {self.id} is not active, rejecting request")
            return WebhookResponse(
                status_code=503,
                headers={"Content-Type": "application/json"},
                body={"error": "Webhook is not active"},
                content_type=WebhookContentType.JSON
            )
        
        # Check if method is allowed
        if request.method not in self.webhook_config.methods:
            logger.warning(f"Method {request.method.value} not allowed for webhook {self.id}")
            return WebhookResponse(
                status_code=405,
                headers={"Content-Type": "application/json", "Allow": ",".join([m.value for m in self.webhook_config.methods])},
                body={"error": "Method not allowed"},
                content_type=WebhookContentType.JSON
            )
        
        # Check if content type is allowed
        if request.content_type not in self.webhook_config.content_types:
            logger.warning(f"Content type {request.content_type.value} not allowed for webhook {self.id}")
            return WebhookResponse(
                status_code=415,
                headers={"Content-Type": "application/json"},
                body={"error": "Unsupported media type"},
                content_type=WebhookContentType.JSON
            )
        
        # Check rate limit
        if not await self._check_rate_limit():
            logger.warning(f"Rate limit exceeded for webhook {self.id}")
            return WebhookResponse(
                status_code=429,
                headers={"Content-Type": "application/json", "Retry-After": "60"},
                body={"error": "Rate limit exceeded"},
                content_type=WebhookContentType.JSON
            )
        
        # Verify signature if enabled
        if self.webhook_config.signature.enabled:
            if not await self._verify_signature(request):
                logger.warning(f"Invalid signature for webhook {self.id}")
                return WebhookResponse(
                    status_code=401,
                    headers={"Content-Type": "application/json"},
                    body={"error": "Invalid signature"},
                    content_type=WebhookContentType.JSON
                )
        
        # Create context
        context = WebhookContext(
            request=request,
            webhook=self
        )
        
        # Process request with handler
        try:
            result = await self.handler.handle(context)
            
            # Record event
            event = WebhookEvent(
                webhook_id=self.id,
                request_id=request.id,
                timestamp=datetime.utcnow(),
                success=result.success,
                status_code=result.response.status_code,
                execution_time_ms=result.execution_time_ms,
                error_message=result.error_message
            )
            
            self.events.append(event)
            
            # Limit event history
            if len(self.events) > 100:
                self.events = self.events[-100:]
            
            # Update metrics
            if result.success:
                self.success_count += 1
                self.last_success = datetime.utcnow()
            else:
                self.failure_count += 1
                self.last_failure = datetime.utcnow()
            
            return result.response
        except Exception as e:
            logger.error(f"Unhandled error processing webhook {self.id}: {str(e)}")
            
            # Record event
            event = WebhookEvent(
                webhook_id=self.id,
                request_id=request.id,
                timestamp=datetime.utcnow(),
                success=False,
                status_code=500,
                execution_time_ms=0,
                error_message=str(e)
            )
            
            self.events.append(event)
            self.failure_count += 1
            self.last_failure = datetime.utcnow()
            
            return WebhookResponse(
                status_code=500,
                headers={"Content-Type": "application/json"},
                body={"error": "Internal server error"},
                content_type=WebhookContentType.JSON
            )
    
    async def _check_rate_limit(self) -> bool:
        """
        Check if request is within rate limits.
        
        Returns:
            True if request is within rate limit, False otherwise
        """
        # Refill tokens based on time elapsed
        now = datetime.utcnow()
        time_elapsed = (now - self._last_token_refill).total_seconds() / 60.0  # Convert to minutes
        tokens_to_add = time_elapsed * self.webhook_config.rate_limit_per_minute
        
        self._rate_limit_tokens = min(
            self.webhook_config.rate_limit_per_minute,
            self._rate_limit_tokens + tokens_to_add
        )
        
        self._last_token_refill = now
        
        # Check if we have at least one token available
        if self._rate_limit_tokens < 1:
            return False
        
        # Consume one token
        self._rate_limit_tokens -= 1
        return True
    
    async def _verify_signature(self, request: WebhookRequest) -> bool:
        """
        Verify webhook signature.
        
        Args:
            request: Webhook request
            
        Returns:
            True if signature is valid, False otherwise
        """
        # If signature verification is not enabled, return True
        if not self.webhook_config.signature.enabled:
            return True
        
        # Check if we have a signature
        signature = None
        
        # Check header first
        if self.webhook_config.signature.header_name in request.headers:
            signature = request.headers[self.webhook_config.signature.header_name]
        
        # Check query param if header not found
        elif self.webhook_config.signature.query_param in request.query_params:
            signature = request.query_params[self.webhook_config.signature.query_param]
        
        # If no signature found, fail verification
        if not signature:
            logger.warning(f"No signature found for webhook {self.id}")
            return False
        
        # Store signature in request for reference
        request.signature = signature
        
        # Get secret key
        secret_key = self.webhook_config.signature.secret_key
        if not secret_key:
            logger.warning(f"No secret key configured for webhook {self.id}")
            return False
        
        # Verify based on the signature method
        method = self.webhook_config.signature.method
        
        # Get timestamp if needed
        timestamp = None
        if self.webhook_config.signature.include_timestamp:
            timestamp_header = self.webhook_config.signature.timestamp_header
            
            if timestamp_header in request.headers:
                try:
                    timestamp_str = request.headers[timestamp_header]
                    timestamp = int(timestamp_str)
                    
                    # Check timestamp tolerance
                    now = int(time.time())
                    tolerance = self.webhook_config.signature.timestamp_tolerance_seconds
                    
                    if abs(now - timestamp) > tolerance:
                        logger.warning(f"Timestamp outside tolerance window for webhook {self.id}")
                        return False
                except ValueError:
                    logger.warning(f"Invalid timestamp format for webhook {self.id}")
                    return False
            else:
                logger.warning(f"Timestamp header not found for webhook {self.id}")
                return False
        
        # Verify signature based on method
        if method == SignatureMethod.HMAC_SHA256:
            return await self._verify_hmac(request, signature, secret_key, "sha256", timestamp)
        
        elif method == SignatureMethod.HMAC_SHA1:
            return await self._verify_hmac(request, signature, secret_key, "sha1", timestamp)
        
        elif method == SignatureMethod.HMAC_MD5:
            return await self._verify_hmac(request, signature, secret_key, "md5", timestamp)
        
        elif method == SignatureMethod.API_KEY:
            return signature == secret_key
        
        elif method == SignatureMethod.BASIC_AUTH:
            # Basic auth is typically in Authorization header
            auth_header = request.headers.get("Authorization", "")
            
            if not auth_header.startswith("Basic "):
                return False
                
            auth_value = auth_header[6:]  # Remove "Basic " prefix
            return auth_value == secret_key
        
        elif method == SignatureMethod.CUSTOM:
            # Custom signature logic should be implemented in the webhook handler
            return True
        
        logger.warning(f"Unsupported signature method for webhook {self.id}: {method.value}")
        return False
    
    async def _verify_hmac(
        self,
        request: WebhookRequest,
        signature: str,
        secret_key: str,
        hash_algorithm: str,
        timestamp: Optional[int] = None
    ) -> bool:
        """
        Verify HMAC signature.
        
        Args:
            request: Webhook request
            signature: Signature to verify
            secret_key: Secret key for verification
            hash_algorithm: Hash algorithm to use
            timestamp: Optional timestamp to include in signature
            
        Returns:
            True if signature is valid, False otherwise
        """
        # Convert request body to bytes if it's a string
        if isinstance(request.body, str):
            body_bytes = request.body.encode("utf-8")
        elif isinstance(request.body, bytes):
            body_bytes = request.body
        elif isinstance(request.body, dict) or isinstance(request.body, list):
            body_bytes = json.dumps(request.body).encode("utf-8")
        else:
            body_bytes = str(request.body).encode("utf-8")
        
        # Create message to sign
        if timestamp is not None:
            message = f"{timestamp}.".encode("utf-8") + body_bytes
        else:
            message = body_bytes
        
        # Create HMAC
        key_bytes = secret_key.encode("utf-8")
        
        if hash_algorithm == "sha256":
            hmac_obj = hmac.new(key_bytes, message, hashlib.sha256)
        elif hash_algorithm == "sha1":
            hmac_obj = hmac.new(key_bytes, message, hashlib.sha1)
        elif hash_algorithm == "md5":
            hmac_obj = hmac.new(key_bytes, message, hashlib.md5)
        else:
            logger.warning(f"Unsupported hash algorithm for webhook {self.id}: {hash_algorithm}")
            return False
        
        # Get expected signature
        expected_signature = hmac_obj.hexdigest()
        
        # Compare signatures (constant time comparison to prevent timing attacks)
        return hmac.compare_digest(signature.lower(), expected_signature.lower())
    
    async def to_dict(self) -> Dict[str, Any]:
        """Convert the webhook to a dictionary."""
        base_dict = await super().to_dict()
        
        # Add webhook-specific fields
        base_dict["webhook_config"] = {
            "path": self.webhook_config.path,
            "methods": [method.value for method in self.webhook_config.methods],
            "content_types": [content_type.value for content_type in self.webhook_config.content_types],
            "signature": {
                "enabled": self.webhook_config.signature.enabled,
                "method": self.webhook_config.signature.method.value,
                "header_name": self.webhook_config.signature.header_name,
                "query_param": self.webhook_config.signature.query_param,
                "include_timestamp": self.webhook_config.signature.include_timestamp,
                "timestamp_header": self.webhook_config.signature.timestamp_header,
                "timestamp_tolerance_seconds": self.webhook_config.signature.timestamp_tolerance_seconds
            },
            "description": self.webhook_config.description,
            "tags": self.webhook_config.tags,
            "metadata": self.webhook_config.metadata,
            "rate_limit_per_minute": self.webhook_config.rate_limit_per_minute,
            "timeout_seconds": self.webhook_config.timeout_seconds
        }
        
        # Don't include sensitive information
        if "secret_key" in base_dict["webhook_config"]["signature"]:
            del base_dict["webhook_config"]["signature"]["secret_key"]
        
        # Add recent events
        base_dict["recent_events"] = []
        for event in self.events[-10:]:  # Include only the 10 most recent events
            base_dict["recent_events"].append({
                "request_id": event.request_id,
                "timestamp": event.timestamp.isoformat(),
                "success": event.success,
                "status_code": event.status_code,
                "execution_time_ms": event.execution_time_ms,
                "error_message": event.error_message
            })
        
        return base_dict
    
    @classmethod
    async def from_dict(cls, data: Dict[str, Any]) -> 'Webhook':
        """
        Create a webhook from a dictionary.
        
        Args:
            data: Dictionary of webhook data
            
        Returns:
            Webhook instance
        """
        # Create base integration
        integration = await super().from_dict(data)
        
        # Get webhook config
        webhook_config_data = data.get("webhook_config", {})
        
        # Parse methods
        methods = []
        for method_str in webhook_config_data.get("methods", ["POST"]):
            try:
                methods.append(WebhookMethod(method_str))
            except ValueError:
                logger.warning(f"Unknown webhook method: {method_str}, using POST")
                methods.append(WebhookMethod.POST)
        
        # Parse content types
        content_types = []
        for content_type_str in webhook_config_data.get("content_types", ["application/json"]):
            try:
                content_types.append(WebhookContentType(content_type_str))
            except ValueError:
                logger.warning(f"Unknown content type: {content_type_str}, using JSON")
                content_types.append(WebhookContentType.JSON)
        
        # Parse signature config
        signature_data = webhook_config_data.get("signature", {})
        
        try:
            signature_method = SignatureMethod(signature_data.get("method", "hmac-sha256"))
        except ValueError:
            logger.warning(f"Unknown signature method: {signature_data.get('method')}, using HMAC-SHA256")
            signature_method = SignatureMethod.HMAC_SHA256
        
        signature_config = WebhookSignatureConfig(
            enabled=signature_data.get("enabled", False),
            method=signature_method,
            secret_key=signature_data.get("secret_key"),
            header_name=signature_data.get("header_name", "X-Signature"),
            query_param=signature_data.get("query_param"),
            include_timestamp=signature_data.get("include_timestamp", False),
            timestamp_header=signature_data.get("timestamp_header", "X-Timestamp"),
            timestamp_tolerance_seconds=signature_data.get("timestamp_tolerance_seconds", 300)
        )
        
        # Create webhook config
        webhook_config = WebhookConfig(
            path=webhook_config_data.get("path", "/webhook"),
            methods=methods,
            content_types=content_types,
            signature=signature_config,
            description=webhook_config_data.get("description", ""),
            tags=webhook_config_data.get("tags", {}),
            metadata=webhook_config_data.get("metadata", {}),
            rate_limit_per_minute=webhook_config_data.get("rate_limit_per_minute", 60),
            timeout_seconds=webhook_config_data.get("timeout_seconds", 30)
        )
        
        # Create webhook
        webhook = cls(
            id=integration.id,
            config=integration.config,
            webhook_config=webhook_config,
            status=integration.status
        )
        
        # Copy fields from base integration
        webhook.last_success = integration.last_success
        webhook.last_failure = integration.last_failure
        webhook.failure_count = integration.failure_count
        webhook.success_count = integration.success_count
        webhook.created_at = integration.created_at
        webhook.updated_at = integration.updated_at
        
        # Load events if available
        events = []
        for event_data in data.get("recent_events", []):
            try:
                event = WebhookEvent(
                    webhook_id=webhook.id,
                    request_id=event_data.get("request_id", str(uuid.uuid4())),
                    timestamp=datetime.fromisoformat(event_data.get("timestamp", datetime.utcnow().isoformat())),
                    success=event_data.get("success", False),
                    status_code=event_data.get("status_code", 500),
                    execution_time_ms=event_data.get("execution_time_ms", 0),
                    error_message=event_data.get("error_message")
                )
                events.append(event)
            except Exception as e:
                logger.warning(f"Error parsing webhook event: {str(e)}")
        
        webhook.events = events
        
        return webhook


class WebhookRegistry:
    """
    Registry for webhooks.
    
    This class handles registration, routing, and management of webhooks.
    """
    
    def __init__(self, integration_registry):
        """
        Initialize the webhook registry.
        
        Args:
            integration_registry: Integration registry for webhooks
        """
        self.integration_registry = integration_registry
        self.path_map: Dict[str, List[str]] = {}  # Maps paths to webhook IDs
    
    async def initialize(self) -> None:
        """Initialize the webhook registry."""
        logger.info("Initializing webhook registry")
        
        # Load existing webhooks
        webhooks = await self.integration_registry.get_integrations(
            type_filter=IntegrationType.WEBHOOK
        )
        
        # Add to path map
        for webhook in webhooks:
            if isinstance(webhook, Webhook):
                self.path_map.setdefault(webhook.webhook_config.path, []).append(webhook.id)
    
    async def register_webhook(
        self,
        config: IntegrationConfig,
        webhook_config: WebhookConfig,
        handler: Optional[WebhookHandler] = None
    ) -> str:
        """
        Register a new webhook.
        
        Args:
            config: Integration configuration
            webhook_config: Webhook configuration
            handler: Optional webhook handler
            
        Returns:
            ID of the registered webhook
            
        Raises:
            ValueError: If registration fails
        """
        # Create webhook
        webhook = Webhook(
            id="",  # Will be assigned by integration registry
            config=config,
            webhook_config=webhook_config,
            handler=handler,
            status=IntegrationStatus.CONFIGURING
        )
        
        # Register with integration registry
        webhook_id = await self.integration_registry.register_integration(config)
        
        # Update webhook ID and status
        webhook.id = webhook_id
        webhook.status = IntegrationStatus.ACTIVE
        
        # Add to path map
        self.path_map.setdefault(webhook_config.path, []).append(webhook_id)
        
        return webhook_id
    
    async def get_webhooks_for_path(self, path: str) -> List[Webhook]:
        """
        Get all webhooks registered for a specific path.
        
        Args:
            path: Path to get webhooks for
            
        Returns:
            List of webhooks for the path
        """
        webhook_ids = self.path_map.get(path, [])
        webhooks = []
        
        for webhook_id in webhook_ids:
            webhook = await self.integration_registry.get_integration(webhook_id)
            if webhook and isinstance(webhook, Webhook):
                webhooks.append(webhook)
        
        return webhooks
    
    async def unregister_webhook(self, webhook_id: str) -> bool:
        """
        Unregister a webhook.
        
        Args:
            webhook_id: ID of the webhook to unregister
            
        Returns:
            True if successful, False otherwise
        """
        # Get webhook
        webhook = await self.integration_registry.get_integration(webhook_id)
        
        if not webhook or not isinstance(webhook, Webhook):
            return False
        
        # Remove from path map
        path = webhook.webhook_config.path
        if path in self.path_map and webhook_id in self.path_map[path]:
            self.path_map[path].remove(webhook_id)
            
            # Remove path if no more webhooks
            if not self.path_map[path]:
                del self.path_map[path]
        
        # Delete from integration registry
        return await self.integration_registry.delete_integration(webhook_id)
    
    async def process_request(
        self,
        path: str,
        method: str,
        headers: Dict[str, str],
        query_params: Dict[str, str],
        body: Any,
        content_type: str,
        source_ip: str
    ) -> Tuple[Optional[WebhookResponse], Optional[str]]:
        """
        Process an incoming webhook request.
        
        Args:
            path: Request path
            method: HTTP method
            headers: Request headers
            query_params: Query parameters
            body: Request body
            content_type: Content type
            source_ip: Source IP address
            
        Returns:
            Tuple of (response, webhook_id) if a webhook was found and processed,
            or (None, None) if no webhook was found
        """
        # Get webhooks for path
        webhooks = await self.get_webhooks_for_path(path)
        
        if not webhooks:
            logger.warning(f"No webhooks found for path: {path}")
            return None, None
        
        # Convert method to enum
        try:
            method_enum = WebhookMethod(method)
        except ValueError:
            logger.warning(f"Unknown webhook method: {method}")
            return None, None
        
        # Convert content type to enum
        content_type_enum = None
        for ct in WebhookContentType:
            if ct.value == content_type or content_type.startswith(ct.value):
                content_type_enum = ct
                break
        
        if not content_type_enum:
            logger.warning(f"Unknown content type: {content_type}")
            content_type_enum = WebhookContentType.RAW
        
        # Create request object
        request = WebhookRequest(
            id=str(uuid.uuid4()),
            path=path,
            method=method_enum,
            headers=headers,
            query_params=query_params,
            body=body,
            content_type=content_type_enum,
            source_ip=source_ip,
            timestamp=datetime.utcnow()
        )
        
        # Find first webhook that can handle this request
        for webhook in webhooks:
            if method_enum in webhook.webhook_config.methods and content_type_enum in webhook.webhook_config.content_types:
                response = await webhook.process_request(request)
                return response, webhook.id
        
        # No webhook found that can handle this request
        logger.warning(f"No webhook found for path {path} that accepts method {method} and content type {content_type}")
        return None, None 