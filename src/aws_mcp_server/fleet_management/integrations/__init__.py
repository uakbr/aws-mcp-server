"""
External Integrations for AWS Fleet Management.

This module provides capabilities for integrating the fleet management system
with external third-party systems via webhooks, APIs, and other mechanisms.
"""

from .integration_tools import integration_tools
from .webhook_tools import webhook_tools
from .transform_tools import transform_tools
from .credential_tools import credential_tools

__version__ = "0.1.0"

# Export tools for registration with the MCP server
all_integration_tools = (
    integration_tools +
    webhook_tools +
    transform_tools +
    credential_tools
) 