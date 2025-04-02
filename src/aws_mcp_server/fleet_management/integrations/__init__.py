"""
Integrations Package for AWS Fleet Management.

This package provides integration capabilities with external systems.
"""

from .credential_tools import credential_tools
from .integration_tools import integration_tools
from .transform_tools import transform_tools
from .webhook_tools import webhook_tools

__version__ = "0.1.0"

# Export tools for registration with the MCP server
all_integration_tools = (
    integration_tools +
    webhook_tools +
    transform_tools +
    credential_tools
) 