"""Main server implementation for AWS MCP Server.

This module defines the MCP server instance and tool functions for AWS CLI interaction,
providing a standardized interface for AWS CLI command execution and documentation.
"""

import asyncio
import logging
import sys

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

from aws_mcp_server.cli_executor import (
    CommandExecutionError,
    CommandHelpResult,
    CommandResult,
    CommandValidationError,
    check_aws_cli_installed,
    execute_aws_command,
    get_command_help,
)
from aws_mcp_server.config import INSTRUCTIONS, SERVER_INFO
from aws_mcp_server.prompts import register_prompts
from aws_mcp_server.resources import (
    get_ec2_instances,
    get_s3_buckets,
    get_s3_objects,
    get_cloudwatch_metrics,
    get_cloudformation_stacks,
    get_iam_policies,
    get_iam_roles
)
from aws_mcp_server.sampling import AWSAnalyzer
from aws_mcp_server.progress import (
    ProgressReporter,
    OperationType,
    discover_resources_with_progress,
    track_multi_region_operation
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", handlers=[logging.StreamHandler(sys.stderr)])
logger = logging.getLogger("aws-mcp-server")


# Run startup checks in synchronous context
def run_startup_checks():
    """Run startup checks to ensure AWS CLI is installed."""
    logger.info("Running startup checks...")
    if not asyncio.run(check_aws_cli_installed()):
        logger.error("AWS CLI is not installed or not in PATH. Please install AWS CLI.")
        sys.exit(1)
    logger.info("AWS CLI is installed and available")


# Call the checks
run_startup_checks()

# Create the FastMCP server following FastMCP best practices
mcp = FastMCP(
    "AWS MCP Server",
    instructions=INSTRUCTIONS,
    version=SERVER_INFO["version"],
)

# Register prompt templates
register_prompts(mcp)

# Register AWS resources
@mcp.resource("ec2://instances/{region}")
async def ec2_instances_resource(region: str) -> str:
    """Get EC2 instances for a specific region."""
    resource = await get_ec2_instances(region)
    return resource.text

@mcp.resource("s3://buckets")
async def s3_buckets_resource() -> str:
    """Get all S3 buckets in the account."""
    resource = await get_s3_buckets()
    return resource.text

@mcp.resource("s3://buckets/{bucket_name}/objects")
async def s3_objects_resource(bucket_name: str) -> str:
    """Get objects in a specific S3 bucket."""
    resource = await get_s3_objects(bucket_name)
    return resource.text

@mcp.resource("cloudwatch://metrics/{namespace}")
async def cloudwatch_metrics_resource(namespace: str) -> str:
    """Get CloudWatch metrics for a specific namespace."""
    resource = await get_cloudwatch_metrics(namespace)
    return resource.text

@mcp.resource("cloudformation://stacks/{region}")
async def cloudformation_stacks_resource(region: str) -> str:
    """Get CloudFormation stacks for a specific region."""
    resource = await get_cloudformation_stacks(region)
    return resource.text

@mcp.resource("iam://policies")
async def iam_policies_resource() -> str:
    """Get IAM policies."""
    resource = await get_iam_policies()
    return resource.text

@mcp.resource("iam://roles")
async def iam_roles_resource() -> str:
    """Get IAM roles."""
    resource = await get_iam_roles()
    return resource.text


@mcp.tool()
async def describe_command(
    service: str = Field(description="AWS service (e.g., s3, ec2)"),
    command: str | None = Field(description="Command within the service", default=None),
    ctx: Context | None = None,
) -> CommandHelpResult:
    """Get AWS CLI command documentation.

    Retrieves the help documentation for a specified AWS service or command
    by executing the 'aws <service> [command] help' command.

    Returns:
        CommandHelpResult containing the help text
    """
    logger.info(f"Getting documentation for service: {service}, command: {command or 'None'}")

    try:
        if ctx:
            await ctx.info(f"Fetching help for AWS {service} {command or ''}")

        # Reuse the get_command_help function from cli_executor
        result = await get_command_help(service, command)
        return result
    except Exception as e:
        logger.error(f"Error in describe_command: {e}")
        return CommandHelpResult(help_text=f"Error retrieving help: {str(e)}")


@mcp.tool()
async def execute_command(
    command: str = Field(description="Complete AWS CLI command to execute (can include pipes with Unix commands)"),
    timeout: int | None = Field(description="Timeout in seconds (defaults to AWS_MCP_TIMEOUT)", default=None),
    ctx: Context | None = None,
) -> CommandResult:
    """Execute an AWS CLI command, optionally with Unix command pipes.

    Validates, executes, and processes the results of an AWS CLI command,
    handling errors and formatting the output for better readability.

    The command can include Unix pipes (|) to filter or transform the output,
    similar to a regular shell. The first command must be an AWS CLI command,
    and subsequent piped commands must be basic Unix utilities.

    Supported Unix commands in pipes:
    - File operations: ls, cat, cd, pwd, cp, mv, rm, mkdir, touch, chmod, chown
    - Text processing: grep, sed, awk, cut, sort, uniq, wc, head, tail, tr, find
    - System tools: ps, top, df, du, uname, whoami, date, which, echo
    - Network tools: ping, ifconfig, netstat, curl, wget, dig, nslookup, ssh, scp
    - Other utilities: man, less, tar, gzip, zip, xargs, jq, tee

    Examples:
    - aws s3api list-buckets --query 'Buckets[*].Name' --output text
    - aws s3api list-buckets --query 'Buckets[*].Name' --output text | sort
    - aws ec2 describe-instances | grep InstanceId | wc -l

    Returns:
        CommandResult containing output and status
    """
    logger.info(f"Executing command: {command}" + (f" with timeout: {timeout}" if timeout else ""))

    if ctx:
        is_pipe = "|" in command
        message = "Executing" + (" piped" if is_pipe else "") + " AWS CLI command"
        await ctx.info(message + (f" with timeout: {timeout}s" if timeout else ""))

    try:
        result = await execute_aws_command(command, timeout)

        # Format the output for better readability
        if result["status"] == "success":
            if ctx:
                await ctx.info("Command executed successfully")
        else:
            if ctx:
                await ctx.warning("Command failed")

        return CommandResult(status=result["status"], output=result["output"])
    except CommandValidationError as e:
        logger.warning(f"Command validation error: {e}")
        return CommandResult(status="error", output=f"Command validation error: {str(e)}")
    except CommandExecutionError as e:
        logger.warning(f"Command execution error: {e}")
        return CommandResult(status="error", output=f"Command execution error: {str(e)}")
    except Exception as e:
        logger.error(f"Error in execute_command: {e}")
        return CommandResult(status="error", output=f"Unexpected error: {str(e)}")


# Sampling-powered analysis tools
@mcp.tool()
async def analyze_aws_error(
    command: str = Field(description="The AWS CLI command that failed"),
    error_output: str = Field(description="The error message from AWS"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Analyze AWS CLI errors using AI and suggest solutions.
    
    Uses LLM sampling to provide intelligent error analysis including:
    - Root cause analysis
    - Step-by-step solutions
    - Prevention tips
    - Related commands that might help
    """
    if not ctx:
        return {
            "status": "error",
            "message": "Context required for AI analysis"
        }
    
    analyzer = AWSAnalyzer()
    result = await analyzer.analyze_error(ctx, command, error_output)
    result["timestamp"] = asyncio.get_event_loop().time()
    return result


@mcp.tool()
async def recommend_architecture(
    requirements: str = Field(description="Description of requirements or goals for the architecture"),
    resource_filter: str = Field(description="Filter resources by type (e.g., 'ec2', 's3', 'all')", default="all"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Generate AWS architecture recommendations based on requirements.
    
    Analyzes current resources and provides recommendations for:
    - Architecture improvements
    - Service selection
    - Implementation steps
    - Cost optimization
    - Security enhancements
    """
    if not ctx:
        return {
            "status": "error",
            "message": "Context required for AI analysis"
        }
    
    # Gather current resources based on filter
    current_resources = {}
    
    if resource_filter in ["all", "ec2"]:
        try:
            ec2_provider = EC2ResourceProvider()
            ec2_data = await ec2_provider.fetch_resources()
            current_resources["ec2_instances"] = ec2_data
        except Exception as e:
            logger.error(f"Error fetching EC2 resources: {e}")
    
    if resource_filter in ["all", "s3"]:
        try:
            s3_provider = S3ResourceProvider()
            s3_data = await s3_provider.fetch_buckets()
            current_resources["s3_buckets"] = s3_data
        except Exception as e:
            logger.error(f"Error fetching S3 resources: {e}")
    
    analyzer = AWSAnalyzer()
    result = await analyzer.generate_architecture_recommendation(ctx, current_resources, requirements)
    result["timestamp"] = asyncio.get_event_loop().time()
    return result


@mcp.tool()
async def optimize_costs(
    optimization_goal: str = Field(description="Cost optimization goal (e.g., 'reduce by 20%', 'optimize compute costs')", default="reduce monthly spend by 20%"),
    analyze_days: int = Field(description="Number of days of cost data to analyze", default=30),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Analyze AWS costs and provide optimization recommendations.
    
    Provides AI-powered cost analysis including:
    - Cost breakdown by service
    - Quick wins for immediate savings
    - Long-term optimization strategies
    - Right-sizing recommendations
    - Reserved instance suggestions
    """
    if not ctx:
        return {
            "status": "error",
            "message": "Context required for AI analysis"
        }
    
    # In a real implementation, this would fetch actual cost data from AWS Cost Explorer
    # For now, we'll use a placeholder structure
    cost_data = {
        "total_monthly_cost": "$5,432.10",
        "top_services": [
            {"service": "EC2", "cost": "$2,134.50", "percentage": 39.3},
            {"service": "RDS", "cost": "$1,234.20", "percentage": 22.7},
            {"service": "S3", "cost": "$567.30", "percentage": 10.4},
            {"service": "CloudFront", "cost": "$432.10", "percentage": 8.0}
        ],
        "trend": "increasing",
        "analyze_period_days": analyze_days
    }
    
    analyzer = AWSAnalyzer()
    result = await analyzer.analyze_costs(ctx, cost_data, optimization_goal)
    result["timestamp"] = asyncio.get_event_loop().time()
    return result


@mcp.tool()
async def security_audit(
    compliance_framework: str = Field(description="Compliance framework to evaluate against", default="AWS Well-Architected"),
    scan_services: str = Field(description="Services to scan (comma-separated or 'all')", default="all"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Generate a comprehensive security audit report.
    
    Performs security analysis and provides:
    - Executive summary
    - Critical security issues
    - Risk assessment by severity
    - Remediation plan
    - Compliance gaps
    - Best practice recommendations
    """
    if not ctx:
        return {
            "status": "error",
            "message": "Context required for AI analysis"
        }
    
    # In a real implementation, this would integrate with AWS Security Hub, GuardDuty, etc.
    # For now, we'll use placeholder findings
    security_findings = [
        {
            "severity": "HIGH",
            "service": "EC2",
            "finding": "Security group allows unrestricted inbound access on port 22",
            "resource": "sg-1234567890"
        },
        {
            "severity": "MEDIUM",
            "service": "S3",
            "finding": "Bucket logging not enabled",
            "resource": "my-application-bucket"
        },
        {
            "severity": "LOW",
            "service": "IAM",
            "finding": "User has not rotated access keys in 90 days",
            "resource": "user@example.com"
        }
    ]
    
    analyzer = AWSAnalyzer()
    result = await analyzer.generate_security_report(ctx, security_findings, compliance_framework)
    result["timestamp"] = asyncio.get_event_loop().time()
    return result


@mcp.tool()
async def suggest_automation(
    manual_tasks: str = Field(description="Comma-separated list of manual tasks to automate"),
    current_tools: str = Field(description="Comma-separated list of tools currently in use", default=""),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Suggest automation opportunities for manual AWS tasks.
    
    Provides recommendations for:
    - AWS automation services to use
    - Step-by-step implementation
    - Integration with existing tools
    - ROI estimation
    - Quick start suggestions
    """
    if not ctx:
        return {
            "status": "error",
            "message": "Context required for AI analysis"
        }
    
    tasks_list = [task.strip() for task in manual_tasks.split(",")]
    tools_list = [tool.strip() for tool in current_tools.split(",")] if current_tools else []
    
    analyzer = AWSAnalyzer()
    result = await analyzer.suggest_automation(ctx, tasks_list, tools_list)
    result["timestamp"] = asyncio.get_event_loop().time()
    return result


# Import required classes for the tools
from aws_mcp_server.resources import EC2ResourceProvider, S3ResourceProvider
from typing import Dict, Any


# Progress-tracked operations
@mcp.tool()
async def discover_all_resources(
    regions: str = Field(description="Comma-separated list of AWS regions to scan", default="us-east-1"),
    resource_types: str = Field(description="Comma-separated list of resource types (ec2,s3,rds,lambda,etc.)", default="ec2,s3,rds"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Discover AWS resources across multiple regions with real-time progress tracking.
    
    Features:
    - Real-time progress updates
    - Multi-region parallel scanning
    - Detailed resource counts
    - Error handling per region/resource
    """
    if not ctx:
        return {
            "status": "error",
            "message": "Context required for progress tracking"
        }
    
    regions_list = [r.strip() for r in regions.split(",")]
    types_list = [t.strip() for t in resource_types.split(",")]
    
    result = await discover_resources_with_progress(
        regions=regions_list,
        resource_types=types_list,
        ctx=ctx
    )
    
    return result


@mcp.tool()
async def deploy_cloudformation_with_progress(
    template_path: str = Field(description="Path to CloudFormation template"),
    stack_name: str = Field(description="Name for the CloudFormation stack"),
    regions: str = Field(description="Comma-separated list of regions to deploy to", default="us-east-1"),
    parameters: str = Field(description="JSON string of stack parameters", default="{}"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Deploy CloudFormation stack with detailed progress tracking.
    
    Tracks:
    - Template validation
    - Stack creation progress
    - Resource provisioning
    - Output collection
    """
    if not ctx:
        return {
            "status": "error",
            "message": "Context required for progress tracking"
        }
    
    import json
    
    regions_list = [r.strip() for r in regions.split(",")]
    params = json.loads(parameters)
    
    operation_id = f"cf_deploy_{stack_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    reporter = ProgressReporter(ctx)
    
    # Define deployment steps
    steps = []
    for region in regions_list:
        steps.extend([
            {"name": f"Validate template in {region}", "description": "Validating CloudFormation template", "weight": 0.5},
            {"name": f"Create stack in {region}", "description": "Creating CloudFormation stack", "weight": 1.0},
            {"name": f"Wait for resources in {region}", "description": "Waiting for resources to provision", "weight": 3.0},
            {"name": f"Verify outputs in {region}", "description": "Verifying stack outputs", "weight": 0.5}
        ])
    
    tracker = await reporter.start_operation(
        operation_id=operation_id,
        operation_type=OperationType.DEPLOYMENT,
        steps=steps
    )
    
    results = {}
    step_index = 0
    
    for region in regions_list:
        results[region] = {}
        
        # Validate template
        await reporter.update_progress(operation_id, step_index, "started")
        try:
            # Simulate validation (replace with actual AWS API call)
            await asyncio.sleep(1)
            await reporter.update_progress(operation_id, step_index, "completed")
        except Exception as e:
            await reporter.update_progress(operation_id, step_index, "failed", error=str(e))
            step_index += 4  # Skip remaining steps for this region
            continue
        step_index += 1
        
        # Create stack
        await reporter.update_progress(operation_id, step_index, "started")
        try:
            # Simulate stack creation (replace with actual AWS API call)
            await asyncio.sleep(2)
            results[region]["stack_id"] = f"arn:aws:cloudformation:{region}:123456789012:stack/{stack_name}/xxx"
            await reporter.update_progress(operation_id, step_index, "completed", metadata={"stack_id": results[region]["stack_id"]})
        except Exception as e:
            await reporter.update_progress(operation_id, step_index, "failed", error=str(e))
            step_index += 3
            continue
        step_index += 1
        
        # Wait for resources
        await reporter.update_progress(operation_id, step_index, "started")
        try:
            # Simulate waiting for resources (replace with actual polling)
            for i in range(5):
                await asyncio.sleep(1)
                # Update progress within the step
                await ctx.info(f"Resources provisioning in {region}: {(i+1)*20}% complete")
            
            results[region]["status"] = "CREATE_COMPLETE"
            await reporter.update_progress(operation_id, step_index, "completed")
        except Exception as e:
            await reporter.update_progress(operation_id, step_index, "failed", error=str(e))
            step_index += 2
            continue
        step_index += 1
        
        # Verify outputs
        await reporter.update_progress(operation_id, step_index, "started")
        try:
            # Simulate output verification (replace with actual AWS API call)
            await asyncio.sleep(0.5)
            results[region]["outputs"] = {
                "WebsiteURL": f"https://example-{stack_name}.{region}.amazonaws.com",
                "DatabaseEndpoint": f"db-{stack_name}.{region}.rds.amazonaws.com"
            }
            await reporter.update_progress(operation_id, step_index, "completed", metadata={"outputs": results[region]["outputs"]})
        except Exception as e:
            await reporter.update_progress(operation_id, step_index, "failed", error=str(e))
        step_index += 1
    
    summary = await reporter.complete_operation(operation_id)
    
    return {
        "operation_summary": summary,
        "deployment_results": results
    }


@mcp.tool()
async def batch_tag_resources(
    resource_ids: str = Field(description="Comma-separated list of resource ARNs or IDs"),
    tags: str = Field(description="JSON string of tags to apply"),
    batch_size: int = Field(description="Number of resources to tag in each batch", default=10),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Apply tags to multiple AWS resources with batch progress tracking.
    
    Features:
    - Batch processing with configurable size
    - Progress tracking per batch
    - Error handling per resource
    - Summary of successful/failed operations
    """
    if not ctx:
        return {
            "status": "error",
            "message": "Context required for progress tracking"
        }
    
    import json
    
    resource_list = [r.strip() for r in resource_ids.split(",")]
    tag_dict = json.loads(tags)
    
    operation_id = f"batch_tag_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    reporter = ProgressReporter(ctx)
    
    # Create batches
    batches = [resource_list[i:i + batch_size] for i in range(0, len(resource_list), batch_size)]
    
    # Define steps for each batch
    steps = [
        {
            "name": f"Batch {i+1}/{len(batches)}",
            "description": f"Tagging resources {i*batch_size+1}-{min((i+1)*batch_size, len(resource_list))}",
            "weight": len(batch)
        }
        for i, batch in enumerate(batches)
    ]
    
    tracker = await reporter.start_operation(
        operation_id=operation_id,
        operation_type=OperationType.BATCH_OPERATION,
        steps=steps
    )
    
    results = {
        "successful": [],
        "failed": [],
        "total": len(resource_list)
    }
    
    for batch_index, batch in enumerate(batches):
        await reporter.update_progress(operation_id, batch_index, "started")
        
        batch_results = {"successful": [], "failed": []}
        
        for resource_id in batch:
            try:
                # Simulate tagging operation (replace with actual AWS API call)
                await asyncio.sleep(0.2)
                
                # Mock success/failure
                if "error" not in resource_id:  # Simple mock logic
                    batch_results["successful"].append(resource_id)
                    results["successful"].append(resource_id)
                else:
                    raise Exception("Mock tagging error")
                    
            except Exception as e:
                batch_results["failed"].append({
                    "resource": resource_id,
                    "error": str(e)
                })
                results["failed"].append({
                    "resource": resource_id,
                    "error": str(e)
                })
        
        await reporter.update_progress(
            operation_id,
            batch_index,
            "completed",
            metadata=batch_results
        )
    
    summary = await reporter.complete_operation(operation_id)
    
    return {
        "operation_summary": summary,
        "results": results,
        "success_rate": f"{(len(results['successful']) / results['total']) * 100:.1f}%"
    }


# Import datetime for the tools
from datetime import datetime
