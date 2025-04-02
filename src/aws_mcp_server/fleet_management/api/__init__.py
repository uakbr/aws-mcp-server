"""
API & Integration Layer for AWS Fleet Management.

This module provides a RESTful API for interacting with the AWS Fleet Management
system, including authentication, authorization, and rate limiting capabilities.
"""

from .api_server import APIServer
from .auth import AuthManager
from .rate_limiter import RateLimiter
from .api_tools import api_tools

__version__ = "0.1.0"

# Export tools for registration with the MCP server
all_api_tools = api_tools 