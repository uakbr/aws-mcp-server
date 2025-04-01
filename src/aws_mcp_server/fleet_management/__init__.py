"""
Fleet Management Extension for AWS MCP Server.

This module extends the AWS MCP Server to provide comprehensive 
fleet management capabilities for AWS resources.
"""

from .tools import fleet_management_tools
from .deployment_tools import deployment_tools

__version__ = "0.1.0"

# Export tools for registration with the MCP server
all_tools = fleet_management_tools + deployment_tools 