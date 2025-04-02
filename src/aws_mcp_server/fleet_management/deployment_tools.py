"""
Deployment Tools for AWS Fleet Management.

This module provides tools for interacting with the deployment system.
"""

import json
import logging
from typing import Any, Dict

from ..tools import Tool, ToolSchema
from .deployment import (
    DeploymentManager, DeploymentTemplate, 
    TemplateParameter, TemplateRegistry
)

logger = logging.getLogger(__name__)


class DeploymentTool(Tool):
    """Base class for deployment tools."""
    pass


class ListTemplatesTool(DeploymentTool):
    """Tool for listing available deployment templates."""
    
    name = "list_deployment_templates"
    description = "List available deployment templates for AWS resources"
    
    schema = ToolSchema(
        properties={
            "filter": {
                "type": "string",
                "description": "Optional filter for template names"
            }
        }
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the list templates tool."""
        filter_text = params.get("filter", "")
        
        try:
            templates = TemplateRegistry.list_templates()
            
            # Apply filter if provided
            if filter_text:
                templates = [
                    t for t in templates 
                    if filter_text.lower() in t["name"].lower() or 
                    filter_text.lower() in t["description"].lower()
                ]
            
            return json.dumps({
                "templates": templates,
                "count": len(templates)
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing templates: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetTemplateDetailsTool(DeploymentTool):
    """Tool for getting details of a deployment template."""
    
    name = "get_deployment_template"
    description = "Get details of a specific deployment template"
    
    schema = ToolSchema(
        properties={
            "name": {
                "type": "string",
                "description": "Name of the template"
            },
            "version": {
                "type": "string",
                "description": "Version of the template (optional, defaults to latest)"
            }
        },
        required=["name"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get template details tool."""
        name = params.get("name")
        version = params.get("version")
        
        try:
            template = TemplateRegistry.get_template(name, version)
            
            if not template:
                return json.dumps({
                    "error": f"Template not found: {name}" + (f":{version}" if version else "")
                })
            
            return json.dumps({
                "template": template.to_dict()
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting template details: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class CreateDeploymentTool(DeploymentTool):
    """Tool for creating a new deployment from a template."""
    
    name = "create_deployment"
    description = "Create a new deployment from a template"
    
    schema = ToolSchema(
        properties={
            "template_name": {
                "type": "string",
                "description": "Name of the template to use"
            },
            "template_version": {
                "type": "string",
                "description": "Version of the template to use (optional, defaults to latest)"
            },
            "parameters": {
                "type": "object",
                "description": "Parameter values for the template"
            },
            "dry_run": {
                "type": "boolean",
                "description": "If true, validate but don't actually deploy"
            }
        },
        required=["template_name", "parameters"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the create deployment tool."""
        template_name = params.get("template_name")
        template_version = params.get("template_version")
        parameters = params.get("parameters", {})
        dry_run = params.get("dry_run", False)
        
        try:
            # Get the template
            template = TemplateRegistry.get_template(template_name, template_version)
            
            if not template:
                return json.dumps({
                    "error": f"Template not found: {template_name}" + 
                             (f":{template_version}" if template_version else "")
                })
            
            # Validate parameters
            validation = template.validate(parameters)
            
            if validation["status"].value == "invalid":
                return json.dumps({
                    "valid": False,
                    "errors": validation["errors"]
                }, indent=2)
            
            # Return validation result if dry run
            if dry_run:
                return json.dumps({
                    "valid": True,
                    "message": "Template parameters are valid"
                }, indent=2)
            
            # Create the deployment
            result = await DeploymentManager.create_deployment(
                template_name=template_name,
                template_version=template_version,
                parameter_values=parameters
            )
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error creating deployment: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class GetDeploymentStatusTool(DeploymentTool):
    """Tool for getting the status of a deployment."""
    
    name = "get_deployment_status"
    description = "Get the status of a deployment"
    
    schema = ToolSchema(
        properties={
            "execution_id": {
                "type": "string",
                "description": "ID of the deployment execution"
            },
            "include_logs": {
                "type": "boolean",
                "description": "Whether to include detailed logs"
            }
        },
        required=["execution_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the get deployment status tool."""
        execution_id = params.get("execution_id")
        include_logs = params.get("include_logs", True)
        
        try:
            result = DeploymentManager.get_deployment_status(execution_id)
            
            # Remove logs if not requested
            if not include_logs and "logs" in result:
                del result["logs"]
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error getting deployment status: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


class RollbackDeploymentTool(DeploymentTool):
    """Tool for rolling back a failed deployment."""
    
    name = "rollback_deployment"
    description = "Rollback a failed deployment"
    
    schema = ToolSchema(
        properties={
            "execution_id": {
                "type": "string",
                "description": "ID of the deployment execution to rollback"
            }
        },
        required=["execution_id"]
    )
    
    async def _run(self, params: Dict[str, Any]) -> str:
        """Run the rollback deployment tool."""
        execution_id = params.get("execution_id")
        
        try:
            result = await DeploymentManager.rollback_deployment(execution_id)
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error rolling back deployment: {e}", exc_info=True)
            return json.dumps({"error": str(e)})


# Create a sample template for testing
def create_sample_templates():
    """Create sample deployment templates for testing."""
    # Basic EC2 instance template
    ec2_template = DeploymentTemplate(
        name="basic-ec2-instance",
        description="Deploy a basic EC2 instance with configurable settings",
        version="1.0.0",
        parameters={
            "instance_name": TemplateParameter(
                name="instance_name",
                description="Name for the EC2 instance",
                type="string",
                required=True
            ),
            "instance_type": TemplateParameter(
                name="instance_type",
                description="EC2 instance type",
                type="string",
                default="t2.micro",
                allowed_values=["t2.micro", "t2.small", "t2.medium"]
            ),
            "ami_id": TemplateParameter(
                name="ami_id",
                description="AMI ID to use",
                type="string",
                default="ami-0c55b159cbfafe1f0"  # Example AMI ID
            ),
            "subnet_id": TemplateParameter(
                name="subnet_id",
                description="Subnet to deploy into",
                type="string",
                required=True
            ),
            "security_group_ids": TemplateParameter(
                name="security_group_ids",
                description="Security groups to attach",
                type="array",
                default=[]
            )
        }
    )
    
    # Register the template
    TemplateRegistry.register_template(ec2_template)
    
    # Web application template
    web_app_template = DeploymentTemplate(
        name="web-application-stack",
        description="Deploy a complete web application with load balancer, EC2 instances, and RDS",
        version="1.0.0",
        parameters={
            "app_name": TemplateParameter(
                name="app_name",
                description="Name for the application",
                type="string",
                required=True
            ),
            "environment": TemplateParameter(
                name="environment",
                description="Deployment environment",
                type="string",
                default="dev",
                allowed_values=["dev", "staging", "prod"]
            ),
            "instance_count": TemplateParameter(
                name="instance_count",
                description="Number of EC2 instances",
                type="number",
                default=2
            ),
            "instance_type": TemplateParameter(
                name="instance_type",
                description="EC2 instance type",
                type="string",
                default="t2.small"
            ),
            "db_instance_type": TemplateParameter(
                name="db_instance_type",
                description="RDS instance type",
                type="string",
                default="db.t2.small"
            ),
            "vpc_id": TemplateParameter(
                name="vpc_id",
                description="VPC ID for deployment",
                type="string",
                required=True
            )
        }
    )
    
    # Register the template
    TemplateRegistry.register_template(web_app_template)


# Initialize sample templates
create_sample_templates()

# List of deployment tools to register with the server
deployment_tools = [
    ListTemplatesTool(),
    GetTemplateDetailsTool(),
    CreateDeploymentTool(),
    GetDeploymentStatusTool(),
    RollbackDeploymentTool(),
] 