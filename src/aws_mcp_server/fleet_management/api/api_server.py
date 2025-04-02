"""
API Server Implementation for AWS Fleet Management.

This module implements a RESTful API server using FastAPI to expose
fleet management capabilities over HTTP.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer

from .auth import AuthManager, Permission, User
from .rate_limiter import RateLimiter
from ..alerts import AlertRegistry
from ..configuration import ConfigManager
from ..deployment import DeploymentManager
from ..logs import LogManager
from ..models import ResourceRegistry
from ..monitoring import MetricRegistry

logger = logging.getLogger(__name__)


@dataclass
class APIConfig:
    """Configuration for the API server."""
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False
    enable_cors: bool = True
    allow_origins: List[str] = field(default_factory=lambda: ["*"])
    allow_credentials: bool = True
    allow_methods: List[str] = field(default_factory=lambda: ["*"])
    allow_headers: List[str] = field(default_factory=lambda: ["*"])
    enable_docs: bool = True
    docs_url: str = "/docs"
    redoc_url: str = "/redoc"
    openapi_url: str = "/openapi.json"
    title: str = "AWS Fleet Management API"
    description: str = "API for managing AWS resources across a fleet of accounts and regions"
    version: str = "0.1.0"


class APIServer:
    """
    RESTful API server for AWS Fleet Management.
    
    This class implements a FastAPI server that exposes fleet management
    capabilities over HTTP, including authentication, rate limiting,
    and comprehensive documentation.
    """
    
    def __init__(
        self, 
        config: Optional[APIConfig] = None,
        auth_manager: Optional[AuthManager] = None,
        rate_limiter: Optional[RateLimiter] = None,
        metric_registry: Optional[MetricRegistry] = None,
        alert_registry: Optional[AlertRegistry] = None,
        resource_registry: Optional[ResourceRegistry] = None,
        config_manager: Optional[ConfigManager] = None,
        deployment_manager: Optional[DeploymentManager] = None,
        log_manager: Optional[LogManager] = None
    ):
        """Initialize the API server with optional dependencies."""
        self.config = config or APIConfig()
        self.auth_manager = auth_manager or AuthManager()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.metric_registry = metric_registry
        self.alert_registry = alert_registry
        self.resource_registry = resource_registry
        self.config_manager = config_manager
        self.deployment_manager = deployment_manager
        self.log_manager = log_manager
        
        self.app = FastAPI(
            title=self.config.title,
            description=self.config.description,
            version=self.config.version,
            docs_url=self.config.docs_url if self.config.enable_docs else None,
            redoc_url=self.config.redoc_url if self.config.enable_docs else None,
            openapi_url=self.config.openapi_url if self.config.enable_docs else None,
        )
        
        # Set up CORS if enabled
        if self.config.enable_cors:
            self.app.add_middleware(
                CORSMiddleware,
                allow_origins=self.config.allow_origins,
                allow_credentials=self.config.allow_credentials,
                allow_methods=self.config.allow_methods,
                allow_headers=self.config.allow_headers,
            )
        
        # Set up authentication
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
        
        # Initialize routes
        self._init_routes()
    
    def _init_routes(self):
        """Initialize API routes."""
        # Authentication routes
        self.app.post("/token")(self.login)
        
        # Health check
        self.app.get("/health")(self.health_check)
        
        # Resource management routes
        self.app.get("/resources")(self.get_resources)
        self.app.get("/resources/{resource_id}")(self.get_resource)
        
        # Configuration management routes
        self.app.get("/configurations")(self.get_configurations)
        self.app.get("/configurations/{config_id}")(self.get_configuration)
        self.app.post("/configurations")(self.create_configuration)
        self.app.put("/configurations/{config_id}")(self.update_configuration)
        self.app.delete("/configurations/{config_id}")(self.delete_configuration)
        
        # Deployment management routes
        self.app.get("/deployments")(self.get_deployments)
        self.app.get("/deployments/{deployment_id}")(self.get_deployment)
        self.app.post("/deployments")(self.create_deployment)
        
        # Monitoring routes
        self.app.get("/metrics")(self.get_metrics)
        self.app.get("/metrics/{metric_id}")(self.get_metric)
        
        # Alerting routes
        self.app.get("/alerts")(self.get_alerts)
        self.app.get("/alerts/{alert_id}")(self.get_alert)
        self.app.post("/alerts")(self.create_alert)
        self.app.put("/alerts/{alert_id}")(self.update_alert)
        self.app.delete("/alerts/{alert_id}")(self.delete_alert)
        
        # Log management routes
        self.app.get("/logs")(self.search_logs)
        
        # Use the dependency injector to fix Depends() issues
        for route in self.app.routes:
            if hasattr(route, "endpoint") and route.endpoint.__name__ != "login" and route.endpoint.__name__ != "health_check":
                # Get all parameters from the endpoint
                parameters = list(route.endpoint.__annotations__.keys())
                if "user" in parameters:
                    # Add dependency for user parameter
                    route.dependencies.append(Depends(self.get_current_user()))
    
    async def _get_current_user_impl(self, token: str = Depends(OAuth2PasswordBearer(tokenUrl="token"))):
        """Get the current user from the token."""
        user = await self.auth_manager.validate_token(token)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user
    
    def get_current_user(self):
        """Return the current user function for dependency injection."""
        return self._get_current_user_impl
    
    async def check_permission(self, user: User, permission: Permission):
        """Check if the user has the required permission."""
        has_permission = await self.auth_manager.check_permission(user, permission)
        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Not authorized to perform this action. Required permission: {permission.value}",
            )
    
    @staticmethod
    async def health_check():
        """Health check endpoint."""
        return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
    
    async def login(self, request: Request):
        """Login endpoint to get an authentication token."""
        try:
            body = await request.json()
            username = body.get("username")
            password = body.get("password")
            
            if not username or not password:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username and password are required",
                )
            
            token = await self.auth_manager.authenticate(username, password)
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            return {"access_token": token, "token_type": "bearer"}
        except json.JSONDecodeError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON body",
            ) from err
    
    async def get_resources(self, request: Request, user: User):
        """Get all resources."""
        await self.check_permission(user, Permission.READ_RESOURCES)
        await self.rate_limiter.check_rate_limit(request, user)
        
        if not self.resource_registry:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Resource registry not available",
            )
        
        # Parse query parameters for filtering
        query_params = dict(request.query_params)
        
        resources = await self.resource_registry.get_resources(**query_params)
        return {"resources": resources}
    
    async def get_resource(self, resource_id: str, user: User):
        """Get a specific resource by ID."""
        await self.check_permission(user, Permission.READ_RESOURCES)
        
        if not self.resource_registry:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Resource registry not available",
            )
        
        resource = await self.resource_registry.get_resource_by_id(resource_id)
        if not resource:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Resource with ID {resource_id} not found",
            )
        
        return resource
    
    async def get_configurations(self, request: Request, user: User):
        """Get all configurations."""
        await self.check_permission(user, Permission.READ_CONFIGURATIONS)
        await self.rate_limiter.check_rate_limit(request, user)
        
        if not self.config_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Configuration manager not available",
            )
        
        # Parse query parameters for filtering
        query_params = dict(request.query_params)
        
        configs = await self.config_manager.get_configurations(**query_params)
        return {"configurations": configs}
    
    async def get_configuration(self, config_id: str, user: User):
        """Get a specific configuration by ID."""
        await self.check_permission(user, Permission.READ_CONFIGURATIONS)
        
        if not self.config_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Configuration manager not available",
            )
        
        config = await self.config_manager.get_configuration_by_id(config_id)
        if not config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Configuration with ID {config_id} not found",
            )
        
        return config
    
    async def create_configuration(self, request: Request, user: User):
        """Create a new configuration."""
        await self.check_permission(user, Permission.WRITE_CONFIGURATIONS)
        await self.rate_limiter.check_rate_limit(request, user)
        
        if not self.config_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Configuration manager not available",
            )
        
        try:
            config_data = await request.json()
            config_id = await self.config_manager.create_configuration(config_data)
            return {"id": config_id, "status": "created"}
        except json.JSONDecodeError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON body",
            ) from err
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e
    
    async def update_configuration(self, config_id: str, request: Request, user: User):
        """Update an existing configuration."""
        await self.check_permission(user, Permission.WRITE_CONFIGURATIONS)
        await self.rate_limiter.check_rate_limit(request, user)
        
        if not self.config_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Configuration manager not available",
            )
        
        try:
            config_data = await request.json()
            success = await self.config_manager.update_configuration(config_id, config_data)
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Configuration with ID {config_id} not found",
                )
            
            return {"id": config_id, "status": "updated"}
        except json.JSONDecodeError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON body",
            ) from err
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e
    
    async def delete_configuration(self, config_id: str, user: User):
        """Delete a configuration."""
        await self.check_permission(user, Permission.DELETE_CONFIGURATIONS)
        
        if not self.config_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Configuration manager not available",
            )
        
        success = await self.config_manager.delete_configuration(config_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Configuration with ID {config_id} not found",
            )
        
        return {"id": config_id, "status": "deleted"}
    
    async def get_deployments(self, request: Request, user: User):
        """Get all deployments."""
        await self.check_permission(user, Permission.READ_DEPLOYMENTS)
        await self.rate_limiter.check_rate_limit(request, user)
        
        if not self.deployment_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Deployment manager not available",
            )
        
        # Parse query parameters for filtering
        query_params = dict(request.query_params)
        
        deployments = await self.deployment_manager.get_deployments(**query_params)
        return {"deployments": deployments}
    
    async def get_deployment(self, deployment_id: str, user: User):
        """Get a specific deployment by ID."""
        await self.check_permission(user, Permission.READ_DEPLOYMENTS)
        
        if not self.deployment_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Deployment manager not available",
            )
        
        deployment = await self.deployment_manager.get_deployment_by_id(deployment_id)
        if not deployment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Deployment with ID {deployment_id} not found",
            )
        
        return deployment
    
    async def create_deployment(self, request: Request, user: User):
        """Create a new deployment."""
        await self.check_permission(user, Permission.WRITE_DEPLOYMENTS)
        await self.rate_limiter.check_rate_limit(request, user)
        
        if not self.deployment_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Deployment manager not available",
            )
        
        try:
            deployment_data = await request.json()
            deployment_id = await self.deployment_manager.create_deployment(deployment_data)
            return {"id": deployment_id, "status": "created"}
        except json.JSONDecodeError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON body",
            ) from err
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e
    
    async def get_metrics(self, request: Request, user: User):
        """Get all metrics."""
        await self.check_permission(user, Permission.READ_METRICS)
        await self.rate_limiter.check_rate_limit(request, user)
        
        if not self.metric_registry:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Metric registry not available",
            )
        
        # Parse query parameters for filtering
        query_params = dict(request.query_params)
        
        metrics = await self.metric_registry.get_metrics(**query_params)
        return {"metrics": metrics}
    
    async def get_metric(self, metric_id: str, user: User):
        """Get a specific metric by ID."""
        await self.check_permission(user, Permission.READ_METRICS)
        
        if not self.metric_registry:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Metric registry not available",
            )
        
        metric = await self.metric_registry.get_metric_by_id(metric_id)
        if not metric:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Metric with ID {metric_id} not found",
            )
        
        return metric
    
    async def get_alerts(self, request: Request, user: User):
        """Get all alerts."""
        await self.check_permission(user, Permission.READ_ALERTS)
        await self.rate_limiter.check_rate_limit(request, user)
        
        if not self.alert_registry:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Alert registry not available",
            )
        
        # Parse query parameters for filtering
        query_params = dict(request.query_params)
        
        alerts = await self.alert_registry.get_alerts(**query_params)
        return {"alerts": alerts}
    
    async def get_alert(self, alert_id: str, user: User):
        """Get a specific alert by ID."""
        await self.check_permission(user, Permission.READ_ALERTS)
        
        if not self.alert_registry:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Alert registry not available",
            )
        
        alert = await self.alert_registry.get_alert_by_id(alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert with ID {alert_id} not found",
            )
        
        return alert
    
    async def create_alert(self, request: Request, user: User):
        """Create a new alert."""
        await self.check_permission(user, Permission.WRITE_ALERTS)
        await self.rate_limiter.check_rate_limit(request, user)
        
        if not self.alert_registry:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Alert registry not available",
            )
        
        try:
            alert_data = await request.json()
            alert_id = await self.alert_registry.create_alert(alert_data)
            return {"id": alert_id, "status": "created"}
        except json.JSONDecodeError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON body",
            ) from err
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e
    
    async def update_alert(self, alert_id: str, request: Request, user: User):
        """Update an existing alert."""
        await self.check_permission(user, Permission.WRITE_ALERTS)
        await self.rate_limiter.check_rate_limit(request, user)
        
        if not self.alert_registry:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Alert registry not available",
            )
        
        try:
            alert_data = await request.json()
            success = await self.alert_registry.update_alert(alert_id, alert_data)
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Alert with ID {alert_id} not found",
                )
            
            return {"id": alert_id, "status": "updated"}
        except json.JSONDecodeError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON body",
            ) from err
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e
    
    async def delete_alert(self, alert_id: str, user: User):
        """Delete an alert."""
        await self.check_permission(user, Permission.DELETE_ALERTS)
        
        if not self.alert_registry:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Alert registry not available",
            )
        
        success = await self.alert_registry.delete_alert(alert_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert with ID {alert_id} not found",
            )
        
        return {"id": alert_id, "status": "deleted"}
    
    async def search_logs(self, request: Request, user: User):
        """Search logs with filtering."""
        await self.check_permission(user, Permission.READ_LOGS)
        await self.rate_limiter.check_rate_limit(request, user)
        
        if not self.log_manager:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Log manager not available",
            )
        
        # Parse query parameters for filtering
        query_params = dict(request.query_params)
        
        logs = await self.log_manager.search_logs(**query_params)
        return {"logs": logs}
    
    async def start(self):
        """Start the API server."""
        logger.info(f"Starting API server on {self.config.host}:{self.config.port}")
        
        config = uvicorn.Config(
            app=self.app,
            host=self.config.host,
            port=self.config.port,
            log_level="info" if not self.config.debug else "debug",
            reload=self.config.debug
        )
        
        server = uvicorn.Server(config)
        await server.serve()
    
    def run(self):
        """Run the API server synchronously."""
        asyncio.run(self.start()) 