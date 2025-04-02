"""
API Tools for AWS MCP Server.

This module provides tools for integrating the API layer with the
AWS MCP Server's Model Context Protocol.
"""

import json
import asyncio
import logging
import subprocess
from typing import Dict, List, Any, Optional, Union
from dataclasses import asdict

from ..tools import Tool, ToolSchema
from .api_server import APIServer, APIConfig
from .auth import AuthManager, AuthConfig, User, Role, Permission
from .rate_limiter import RateLimiter, RateLimitConfig, UserRateLimit

logger = logging.getLogger(__name__)


class StartAPIServerTool(Tool):
    """Tool for starting the API server."""
    
    def __init__(self):
        """Initialize the tool."""
        super().__init__(
            name="start_api_server",
            schema=ToolSchema(
                description="Start the API server for fleet management",
                parameters={
                    "host": {
                        "description": "The host address to bind to",
                        "type": "string",
                        "default": "127.0.0.1"
                    },
                    "port": {
                        "description": "The port to listen on",
                        "type": "integer",
                        "default": 8000
                    },
                    "debug": {
                        "description": "Enable debug mode",
                        "type": "boolean",
                        "default": False
                    },
                    "enable_cors": {
                        "description": "Enable CORS support",
                        "type": "boolean",
                        "default": True
                    },
                    "allow_origins": {
                        "description": "List of allowed origins for CORS",
                        "type": "array",
                        "items": {"type": "string"},
                        "default": ["*"]
                    }
                },
                returns={
                    "description": "Status of the API server startup",
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "message": {"type": "string"}
                    }
                }
            )
        )
        self._server_instance = None
        self._server_task = None
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        # Extract parameters
        host = parameters.get("host", "127.0.0.1")
        port = parameters.get("port", 8000)
        debug = parameters.get("debug", False)
        enable_cors = parameters.get("enable_cors", True)
        allow_origins = parameters.get("allow_origins", ["*"])
        
        # Create API server configuration
        api_config = APIConfig(
            host=host,
            port=port,
            debug=debug,
            enable_cors=enable_cors,
            allow_origins=allow_origins
        )
        
        # Create auth configuration with a secure random key
        auth_config = AuthConfig()
        
        # Create rate limit configuration
        rate_limit_config = RateLimitConfig()
        
        # Create server components
        auth_manager = AuthManager(auth_config)
        rate_limiter = RateLimiter(rate_limit_config)
        
        # Create API server
        api_server = APIServer(
            config=api_config,
            auth_manager=auth_manager,
            rate_limiter=rate_limiter
        )
        
        # Store server instance
        self._server_instance = api_server
        
        # Start the server in a separate task
        if self._server_task:
            # Cancel existing task if running
            self._server_task.cancel()
            try:
                await self._server_task
            except asyncio.CancelledError:
                pass
        
        self._server_task = asyncio.create_task(api_server.start())
        
        return {
            "status": "started",
            "host": host,
            "port": port,
            "message": f"API server started on {host}:{port}"
        }


class StopAPIServerTool(Tool):
    """Tool for stopping the API server."""
    
    def __init__(self, start_tool: StartAPIServerTool):
        """
        Initialize the tool.
        
        Args:
            start_tool: The start API server tool instance
        """
        super().__init__(
            name="stop_api_server",
            schema=ToolSchema(
                description="Stop the running API server",
                parameters={},
                returns={
                    "description": "Status of the API server shutdown",
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "message": {"type": "string"}
                    }
                }
            )
        )
        self._start_tool = start_tool
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        # Check if server is running
        if not self._start_tool._server_task or self._start_tool._server_task.done():
            return {
                "status": "not_running",
                "message": "API server is not running"
            }
        
        # Cancel the server task
        self._start_tool._server_task.cancel()
        try:
            await self._start_tool._server_task
        except asyncio.CancelledError:
            pass
        
        # Clear references
        self._start_tool._server_instance = None
        self._start_tool._server_task = None
        
        return {
            "status": "stopped",
            "message": "API server stopped successfully"
        }


class CreateUserTool(Tool):
    """Tool for creating a new user."""
    
    def __init__(self, start_tool: StartAPIServerTool):
        """
        Initialize the tool.
        
        Args:
            start_tool: The start API server tool instance
        """
        super().__init__(
            name="create_api_user",
            schema=ToolSchema(
                description="Create a new user for API access",
                parameters={
                    "username": {
                        "description": "The username for the new user",
                        "type": "string"
                    },
                    "password": {
                        "description": "The password for the new user",
                        "type": "string"
                    },
                    "email": {
                        "description": "The email address for the new user",
                        "type": "string"
                    },
                    "full_name": {
                        "description": "The full name of the user",
                        "type": "string"
                    },
                    "roles": {
                        "description": "The roles to assign to the user",
                        "type": "array",
                        "items": {"type": "string"},
                        "default": ["readonly"]
                    }
                },
                returns={
                    "description": "Result of user creation",
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "username": {"type": "string"},
                        "email": {"type": "string"},
                        "roles": {"type": "array"}
                    }
                }
            )
        )
        self._start_tool = start_tool
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        # Check if server is running
        if not self._start_tool._server_instance:
            return {
                "error": "API server is not running"
            }
        
        # Extract parameters
        username = parameters.get("username")
        password = parameters.get("password")
        email = parameters.get("email")
        full_name = parameters.get("full_name")
        roles = parameters.get("roles", ["readonly"])
        
        if not username or not password:
            return {
                "error": "Username and password are required"
            }
        
        # Create user
        auth_manager = self._start_tool._server_instance.auth_manager
        
        try:
            user_data = {
                "username": username,
                "password": password,
                "email": email,
                "full_name": full_name,
                "roles": roles
            }
            
            user_id = await auth_manager.create_user(user_data)
            
            return {
                "id": user_id,
                "username": username,
                "email": email,
                "roles": roles
            }
        except ValueError as e:
            return {
                "error": str(e)
            }


class CreateRoleTool(Tool):
    """Tool for creating a new role."""
    
    def __init__(self, start_tool: StartAPIServerTool):
        """
        Initialize the tool.
        
        Args:
            start_tool: The start API server tool instance
        """
        super().__init__(
            name="create_api_role",
            schema=ToolSchema(
                description="Create a new role for API access",
                parameters={
                    "name": {
                        "description": "The name of the new role",
                        "type": "string"
                    },
                    "description": {
                        "description": "Description of the role",
                        "type": "string"
                    },
                    "permissions": {
                        "description": "The permissions to assign to the role",
                        "type": "array",
                        "items": {"type": "string"}
                    }
                },
                returns={
                    "description": "Result of role creation",
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "description": {"type": "string"},
                        "permissions": {"type": "array"}
                    }
                }
            )
        )
        self._start_tool = start_tool
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        # Check if server is running
        if not self._start_tool._server_instance:
            return {
                "error": "API server is not running"
            }
        
        # Extract parameters
        name = parameters.get("name")
        description = parameters.get("description", "")
        permissions = parameters.get("permissions", [])
        
        if not name:
            return {
                "error": "Role name is required"
            }
        
        # Create role
        auth_manager = self._start_tool._server_instance.auth_manager
        
        try:
            role_data = {
                "name": name,
                "description": description,
                "permissions": permissions
            }
            
            role_name = await auth_manager.create_role(role_data)
            
            return {
                "name": role_name,
                "description": description,
                "permissions": permissions
            }
        except ValueError as e:
            return {
                "error": str(e)
            }


class SetRateLimitTool(Tool):
    """Tool for setting rate limits."""
    
    def __init__(self, start_tool: StartAPIServerTool):
        """
        Initialize the tool.
        
        Args:
            start_tool: The start API server tool instance
        """
        super().__init__(
            name="set_api_rate_limit",
            schema=ToolSchema(
                description="Set rate limits for a user or role",
                parameters={
                    "user_id": {
                        "description": "The user ID to set rate limit for",
                        "type": "string"
                    },
                    "role": {
                        "description": "The role to set rate limit for",
                        "type": "string"
                    },
                    "requests_per_minute": {
                        "description": "Maximum requests per minute",
                        "type": "integer",
                        "default": 60
                    },
                    "burst_limit": {
                        "description": "Maximum burst limit",
                        "type": "integer",
                        "default": 100
                    }
                },
                returns={
                    "description": "Result of setting rate limit",
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "target": {"type": "string"},
                        "limits": {"type": "object"}
                    }
                }
            )
        )
        self._start_tool = start_tool
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        # Check if server is running
        if not self._start_tool._server_instance:
            return {
                "error": "API server is not running"
            }
        
        # Extract parameters
        user_id = parameters.get("user_id")
        role = parameters.get("role")
        requests_per_minute = parameters.get("requests_per_minute", 60)
        burst_limit = parameters.get("burst_limit", 100)
        
        if not user_id and not role:
            return {
                "error": "Either user_id or role must be specified"
            }
        
        # Set rate limit
        rate_limiter = self._start_tool._server_instance.rate_limiter
        
        try:
            rate_limit = UserRateLimit(
                user_id=user_id,
                role=role,
                requests_per_minute=requests_per_minute,
                burst_limit=burst_limit
            )
            
            await rate_limiter.set_user_rate_limit(rate_limit)
            
            target_type = "user" if user_id else "role"
            target_id = user_id if user_id else role
            
            return {
                "status": "success",
                "target": f"{target_type}:{target_id}",
                "limits": {
                    "requests_per_minute": requests_per_minute,
                    "burst_limit": burst_limit
                }
            }
        except ValueError as e:
            return {
                "error": str(e)
            }


class GetAPIStatusTool(Tool):
    """Tool for getting API server status."""
    
    def __init__(self, start_tool: StartAPIServerTool):
        """
        Initialize the tool.
        
        Args:
            start_tool: The start API server tool instance
        """
        super().__init__(
            name="get_api_status",
            schema=ToolSchema(
                description="Get status of the API server",
                parameters={},
                returns={
                    "description": "API server status",
                    "type": "object",
                    "properties": {
                        "running": {"type": "boolean"},
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "user_count": {"type": "integer"},
                        "role_count": {"type": "integer"}
                    }
                }
            )
        )
        self._start_tool = start_tool
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        # Check if server is running
        server = self._start_tool._server_instance
        task = self._start_tool._server_task
        
        if not server or not task or task.done():
            return {
                "running": False,
                "message": "API server is not running"
            }
        
        # Get server stats
        auth_manager = server.auth_manager
        
        return {
            "running": True,
            "host": server.config.host,
            "port": server.config.port,
            "user_count": len(auth_manager.users),
            "role_count": len(auth_manager.roles)
        }


class GenerateClientLibraryTool(Tool):
    """Tool for generating a client library for the API."""
    
    def __init__(self, start_tool: StartAPIServerTool):
        """
        Initialize the tool.
        
        Args:
            start_tool: The start API server tool instance
        """
        super().__init__(
            name="generate_api_client",
            schema=ToolSchema(
                description="Generate a client library for the API",
                parameters={
                    "language": {
                        "description": "The programming language for the client library",
                        "type": "string",
                        "enum": ["python", "javascript", "go", "java", "rust"]
                    },
                    "output_dir": {
                        "description": "Directory to output the client library",
                        "type": "string",
                        "default": "./client"
                    },
                    "package_name": {
                        "description": "Name of the client package",
                        "type": "string",
                        "default": "fleet_management_client"
                    },
                    "version": {
                        "description": "Version of the client library",
                        "type": "string",
                        "default": "0.1.0"
                    }
                },
                returns={
                    "description": "Result of client library generation",
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "language": {"type": "string"},
                        "output_dir": {"type": "string"},
                        "files": {"type": "array"}
                    }
                }
            )
        )
        self._start_tool = start_tool
    
    async def _execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with the given parameters.
        
        Args:
            parameters: Tool parameters
            
        Returns:
            Tool execution result
        """
        # Check if server is running
        if not self._start_tool._server_instance:
            return {
                "error": "API server is not running"
            }
        
        # Extract parameters
        language = parameters.get("language")
        output_dir = parameters.get("output_dir", "./client")
        package_name = parameters.get("package_name", "fleet_management_client")
        version = parameters.get("version", "0.1.0")
        
        if not language:
            return {
                "error": "Language is required"
            }
        
        # Get OpenAPI spec from server
        server = self._start_tool._server_instance
        
        # For now, we'll simulate generating a client library 
        # by creating a few template files
        import os
        import subprocess
        
        os.makedirs(output_dir, exist_ok=True)
        
        files = []
        
        if language == "python":
            # Create Python client files
            with open(f"{output_dir}/__init__.py", "w") as f:
                f.write(f'''"""
AWS Fleet Management API Client.

Version: {version}
"""

from .client import FleetManagementClient

__version__ = "{version}"
''')
                files.append(f"{output_dir}/__init__.py")
            
            with open(f"{output_dir}/client.py", "w") as f:
                f.write(f'''"""
Fleet Management API Client implementation.
"""

import requests
from typing import Dict, List, Any, Optional

class FleetManagementClient:
    """Client for the Fleet Management API."""
    
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        """
        Initialize the client.
        
        Args:
            base_url: Base URL of the API
            api_key: Optional API key for authentication
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({{"Authorization": f"Bearer {{api_key}}"}})
    
    def login(self, username: str, password: str) -> str:
        """
        Login to get an access token.
        
        Args:
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            Access token
        """
        response = self.session.post(
            f"{{self.base_url}}/token",
            json={{"username": username, "password": password}}
        )
        response.raise_for_status()
        data = response.json()
        
        token = data.get("access_token")
        if token:
            self.session.headers.update({{"Authorization": f"Bearer {{token}}"}})
        
        return token
    
    def get_resources(self, **params) -> List[Dict[str, Any]]:
        """
        Get resources matching the given parameters.
        
        Returns:
            List of resources
        """
        response = self.session.get(f"{{self.base_url}}/resources", params=params)
        response.raise_for_status()
        return response.json().get("resources", [])
    
    def get_resource(self, resource_id: str) -> Dict[str, Any]:
        """
        Get a resource by ID.
        
        Args:
            resource_id: ID of the resource
            
        Returns:
            Resource details
        """
        response = self.session.get(f"{{self.base_url}}/resources/{{resource_id}}")
        response.raise_for_status()
        return response.json()
    
    # Add more methods for configurations, deployments, metrics, alerts, logs, etc.
''')
                files.append(f"{output_dir}/client.py")
            
            with open(f"{output_dir}/setup.py", "w") as f:
                f.write(f'''
from setuptools import setup, find_packages

setup(
    name="{package_name}",
    version="{version}",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
    ],
    author="AWS MCP Server",
    author_email="example@example.com",
    description="Client library for AWS Fleet Management API",
    keywords="aws, fleet, management, api",
    url="https://github.com/example/aws-mcp-server",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    python_requires=">=3.8",
)
''')
                files.append(f"{output_dir}/setup.py")
        
        elif language == "javascript":
            # Create JavaScript client files
            with open(f"{output_dir}/package.json", "w") as f:
                f.write(f'''{{
  "name": "{package_name}",
  "version": "{version}",
  "description": "Client library for AWS Fleet Management API",
  "main": "index.js",
  "scripts": {{
    "test": "echo \\"Error: no test specified\\" && exit 1"
  }},
  "author": "",
  "license": "MIT",
  "dependencies": {{
    "axios": "^0.24.0"
  }}
}}
''')
                files.append(f"{output_dir}/package.json")
            
            with open(f"{output_dir}/index.js", "w") as f:
                f.write(f'''/**
 * AWS Fleet Management API Client
 * @module fleet-management-client
 */

const axios = require('axios');

/**
 * Client for the Fleet Management API
 */
class FleetManagementClient {{
  /**
   * Create a new client instance
   * @param {{string}} baseUrl - Base URL of the API
   * @param {{string}} [apiKey] - Optional API key for authentication
   */
  constructor(baseUrl, apiKey) {{
    this.baseUrl = baseUrl.replace(/\\/+$/, '');
    this.apiKey = apiKey;
    
    this.client = axios.create({{
      baseURL: this.baseUrl,
      headers: apiKey ? {{ 'Authorization': `Bearer ${{apiKey}}` }} : {{}}
    }});
  }}
  
  /**
   * Login to get an access token
   * @param {{string}} username - Username for authentication
   * @param {{string}} password - Password for authentication
   * @returns {{Promise<string>}} Access token
   */
  async login(username, password) {{
    const response = await this.client.post('/token', {{ username, password }});
    const {{ access_token: token }} = response.data;
    
    if (token) {{
      this.client.defaults.headers.common['Authorization'] = `Bearer ${{token}}`;
    }}
    
    return token;
  }}
  
  /**
   * Get resources matching the given parameters
   * @param {{Object}} [params] - Query parameters
   * @returns {{Promise<Array>}} List of resources
   */
  async getResources(params = {{}}) {{
    const response = await this.client.get('/resources', {{ params }});
    return response.data.resources || [];
  }}
  
  /**
   * Get a resource by ID
   * @param {{string}} resourceId - ID of the resource
   * @returns {{Promise<Object>}} Resource details
   */
  async getResource(resourceId) {{
    const response = await this.client.get(`/resources/${{resourceId}}`);
    return response.data;
  }}
  
  // Add more methods for configurations, deployments, metrics, alerts, logs, etc.
}}

module.exports = FleetManagementClient;
''')
                files.append(f"{output_dir}/index.js")
        
        elif language in ["go", "java", "rust"]:
            # Just create README files for now
            with open(f"{output_dir}/README.md", "w") as f:
                f.write(f'''# AWS Fleet Management API Client for {language}

This is a client library for the AWS Fleet Management API.

## Installation

TBD

## Usage

TBD

## API Reference

TBD
''')
                files.append(f"{output_dir}/README.md")
        
        return {
            "status": "success",
            "language": language,
            "output_dir": output_dir,
            "files": files
        }


# Create instances of the tools
_start_api_server_tool = StartAPIServerTool()
_stop_api_server_tool = StopAPIServerTool(_start_api_server_tool)
_create_user_tool = CreateUserTool(_start_api_server_tool)
_create_role_tool = CreateRoleTool(_start_api_server_tool)
_set_rate_limit_tool = SetRateLimitTool(_start_api_server_tool)
_get_api_status_tool = GetAPIStatusTool(_start_api_server_tool)
_generate_client_library_tool = GenerateClientLibraryTool(_start_api_server_tool)

# List of tools to register with the server
api_tools = [
    _start_api_server_tool,
    _stop_api_server_tool,
    _create_user_tool,
    _create_role_tool,
    _set_rate_limit_tool,
    _get_api_status_tool,
    _generate_client_library_tool
] 