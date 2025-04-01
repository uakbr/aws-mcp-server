"""
Fleet Management Extension for AWS MCP Server.

This module extends the AWS MCP Server to provide comprehensive 
fleet management capabilities for AWS resources.
"""

from .tools import fleet_management_tools
from .deployment_tools import deployment_tools
from .configuration_tools import configuration_tools
from .execution_tools import execution_tools
from .monitoring_tools import monitoring_tools
from .alerts_tools import alerts_tools
from .logs_tools import logs_tools

__version__ = "0.1.0"

# Export tools for registration with the MCP server
all_tools = (
    fleet_management_tools + 
    deployment_tools + 
    configuration_tools + 
    execution_tools + 
    monitoring_tools + 
    alerts_tools + 
    logs_tools
) 