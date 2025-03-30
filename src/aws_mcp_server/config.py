"""Configuration settings for the AWS MCP Server.

This module contains configuration settings for the AWS MCP Server.

Environment variables:
- AWS_MCP_TIMEOUT: Custom timeout in seconds (default: 30)
- AWS_MCP_MAX_OUTPUT: Maximum output size in characters (default: 10000)
- AWS_MCP_TRANSPORT: Transport protocol to use ("stdio" or "sse", default: "stdio")
- AWS_PROFILE: AWS profile to use (default: "default")
- AWS_REGION: AWS region to use (default: "us-east-1")
"""

import os
from pathlib import Path

# Server information
SERVER_INFO = {"name": "AWS MCP Server", "version": "1.0.0"}

# Command execution settings
DEFAULT_TIMEOUT = int(os.environ.get("AWS_MCP_TIMEOUT", "300"))
MAX_OUTPUT_SIZE = int(os.environ.get("AWS_MCP_MAX_OUTPUT", "100000"))

# Transport protocol
TRANSPORT = os.environ.get("AWS_MCP_TRANSPORT", "stdio")

# AWS CLI settings
AWS_PROFILE = os.environ.get("AWS_PROFILE", "default")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Instructions displayed to client during initialization
INSTRUCTIONS = """
AWS MCP Server provides a simple interface to the AWS CLI.
- Use the describe_command tool to get AWS CLI documentation
- Use the execute_command tool to run AWS CLI commands
- The execute_command tool supports Unix pipes (|) to filter or transform AWS CLI output:
  Example: aws s3api list-buckets --query 'Buckets[*].Name' --output text | sort
- Use the built-in prompt templates for common AWS tasks following best practices:
  - create_resource: Create AWS resources with proper security settings
  - security_audit: Perform comprehensive service security audits
  - cost_optimization: Find cost optimization opportunities
  - resource_inventory: Create resource inventories
  - troubleshoot_service: Troubleshoot service issues 
  - iam_policy_generator: Generate least-privilege IAM policies
  - service_monitoring: Set up monitoring and alerting
  - disaster_recovery: Implement DR solutions
  - compliance_check: Check compliance with standards
  - resource_cleanup: Safely clean up unused resources
"""

# Application paths
BASE_DIR = Path(__file__).parent.parent.parent
