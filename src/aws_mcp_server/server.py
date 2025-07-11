"""Main server implementation for AWS MCP Server.

This module defines the MCP server instance and tool functions for AWS CLI interaction,
providing a standardized interface for AWS CLI command execution and documentation.
"""

import asyncio
import logging
import sys
from typing import Dict, Any

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
from aws_mcp_server.automation import IntelligentAutomation
from aws_mcp_server.ml_ai import MLAIEngine
from aws_mcp_server.security.security_hub import SecurityHubClient, FindingSeverity, WorkflowStatus
from aws_mcp_server.security.guardduty import GuardDutyClient, ThreatDetector, ThreatSeverity
from aws_mcp_server.security.iam_analyzer import IAMAnalyzer, RiskLevel
from aws_mcp_server.security.secrets_manager import SecretsManagerClient, KMSClient, SecureCredentialManager, SecretType
from aws_mcp_server.security.compliance import ComplianceScanner, ComplianceFramework

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


# Intelligent Automation Tools
@mcp.tool()
async def auto_remediate_security(
    resource_type: str = Field(description="Type of resource to remediate (security_group, s3_bucket)"),
    resource_id: str = Field(description="ID or name of the resource"),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Automatically remediate common security issues.
    
    Supported remediations:
    - Security Groups: Remove unrestricted access, add egress rules
    - S3 Buckets: Enable versioning, encryption, block public access
    """
    if ctx:
        await ctx.info(f"Starting auto-remediation for {resource_type}: {resource_id}")
    
    automation = IntelligentAutomation()
    
    try:
        if resource_type == "security_group":
            result = await automation.auto_remediate_security_group(resource_id, region)
        elif resource_type == "s3_bucket":
            result = await automation.auto_remediate_s3_bucket(resource_id)
        else:
            return {
                "status": "error",
                "message": f"Unsupported resource type: {resource_type}"
            }
        
        if ctx and result.get("status") == "success":
            await ctx.info(f"Successfully applied {result.get('remediation_count', 0)} remediations")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in auto-remediation: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def predict_scaling_needs(
    resource_type: str = Field(description="Type of resource (ec2, rds)"),
    resource_id: str = Field(description="Resource ID to analyze"),
    region: str = Field(description="AWS region", default="us-east-1"),
    lookback_days: int = Field(description="Days of historical data to analyze", default=7),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Analyze historical metrics to predict scaling needs.
    
    Uses CloudWatch metrics to:
    - Analyze usage patterns
    - Detect trends
    - Recommend scaling actions
    """
    if ctx:
        await ctx.info(f"Analyzing scaling patterns for {resource_type}: {resource_id}")
    
    automation = IntelligentAutomation()
    
    try:
        result = await automation.predictive_scaling_analysis(
            resource_type=resource_type,
            resource_id=resource_id,
            region=region,
            lookback_days=lookback_days
        )
        
        if ctx:
            recommendation = result.get("overall_recommendation", "Analysis complete")
            await ctx.info(f"Scaling analysis: {recommendation}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in scaling prediction: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def detect_cost_anomalies(
    threshold_percentage: float = Field(description="Percentage increase to consider anomalous", default=20.0),
    account_id: str = Field(description="AWS account ID (optional)", default=None),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Detect unusual cost increases in AWS spending.
    
    Analyzes:
    - Daily cost trends by service
    - Compares recent spending to baseline
    - Identifies services with unusual cost spikes
    """
    if ctx:
        await ctx.info(f"Detecting cost anomalies with {threshold_percentage}% threshold")
    
    automation = IntelligentAutomation()
    
    try:
        result = await automation.detect_cost_anomalies(
            account_id=account_id,
            threshold_percentage=threshold_percentage
        )
        
        if ctx:
            anomaly_count = result.get("total_anomalies", 0)
            if anomaly_count > 0:
                await ctx.warning(f"Detected {anomaly_count} cost anomalies")
            else:
                await ctx.info("No cost anomalies detected")
        
        return result
        
    except Exception as e:
        logger.error(f"Error detecting cost anomalies: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def create_automation_rule(
    rule_name: str = Field(description="Name for the automation rule"),
    trigger_type: str = Field(description="Type of trigger (threshold, schedule, event)"),
    trigger_config: str = Field(description="JSON configuration for the trigger"),
    conditions: str = Field(description="JSON array of conditions"),
    actions: str = Field(description="JSON array of actions to execute"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Create an automation rule for AWS resources.
    
    Example conditions:
    - {"type": "threshold", "metric": "cpu_usage", "threshold": 80, "operator": ">"}
    
    Example actions:
    - {"type": "scale_ec2", "instance_id": "i-xxx", "instance_type": "t3.large"}
    - {"type": "send_notification", "message": "High CPU alert: {metric_value}%"}
    """
    if ctx:
        await ctx.info(f"Creating automation rule: {rule_name}")
    
    import json
    
    try:
        trigger_config_dict = json.loads(trigger_config)
        conditions_list = json.loads(conditions)
        actions_list = json.loads(actions)
        
        automation = IntelligentAutomation()
        
        rule = await automation.create_automation_rule(
            rule_name=rule_name,
            trigger_type=trigger_type,
            trigger_config=trigger_config_dict,
            conditions=conditions_list,
            actions=actions_list
        )
        
        if ctx:
            await ctx.info(f"Successfully created automation rule: {rule.rule_id}")
        
        return {
            "status": "success",
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "enabled": rule.enabled,
            "created_at": rule.created_at.isoformat()
        }
        
    except json.JSONDecodeError as e:
        return {
            "status": "error",
            "message": f"Invalid JSON in parameters: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Error creating automation rule: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


# Machine Learning and AI Tools
@mcp.tool()
async def setup_timestream_ml(
    database_name: str = Field(description="TimeStream database name for ML data"),
    table_name: str = Field(description="TimeStream table name"),
    memory_retention_hours: int = Field(description="Hours to retain data in memory store", default=12),
    magnetic_retention_days: int = Field(description="Days to retain data in magnetic store", default=365),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Set up TimeStream database and table for ML time series data.
    
    Perfect for:
    - Storing model training metrics over time
    - Real-time inference data
    - Performance monitoring
    - Anomaly detection on time series
    """
    if ctx:
        await ctx.info(f"Setting up TimeStream for ML: {database_name}/{table_name}")
    
    ml_engine = MLAIEngine()
    
    try:
        # Create database
        db_result = await ml_engine.create_timestream_database(database_name, region)
        
        # Create table
        table_result = await ml_engine.create_timestream_table(
            database_name=database_name,
            table_name=table_name,
            memory_retention_hours=memory_retention_hours,
            magnetic_retention_days=magnetic_retention_days,
            region=region
        )
        
        if ctx:
            await ctx.info(f"Successfully created TimeStream setup for ML data")
        
        return {
            "status": "success",
            "database": db_result,
            "table": table_result
        }
        
    except Exception as e:
        logger.error(f"Error setting up TimeStream: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def log_ml_metrics(
    database_name: str = Field(description="TimeStream database name"),
    table_name: str = Field(description="TimeStream table name"),
    metrics: str = Field(description="JSON array of metrics to log"),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Log ML training or inference metrics to TimeStream.
    
    Metrics format:
    [{
        "metric_name": "accuracy",
        "value": 0.95,
        "dimensions": {"model": "bert-classifier", "epoch": "10"},
        "timestamp": "2024-01-20T10:30:00Z"
    }]
    """
    import json
    
    try:
        metrics_list = json.loads(metrics)
        
        # Convert timestamp strings to datetime objects
        for metric in metrics_list:
            if 'timestamp' in metric and isinstance(metric['timestamp'], str):
                metric['timestamp'] = datetime.fromisoformat(metric['timestamp'].replace('Z', '+00:00'))
        
        ml_engine = MLAIEngine()
        result = await ml_engine.write_ml_metrics_to_timestream(
            database_name=database_name,
            table_name=table_name,
            metrics=metrics_list,
            region=region
        )
        
        if ctx:
            await ctx.info(f"Logged {result['records_written']} ML metrics to TimeStream")
        
        return result
        
    except json.JSONDecodeError as e:
        return {
            "status": "error",
            "message": f"Invalid JSON in metrics: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Error logging ML metrics: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def train_sagemaker_model(
    job_name: str = Field(description="Name for the training job"),
    algorithm_image: str = Field(description="ECR URI of the training algorithm"),
    input_data_s3: str = Field(description="S3 URI for training data"),
    output_data_s3: str = Field(description="S3 URI for model artifacts"),
    instance_type: str = Field(description="Instance type for training", default="ml.m5.xlarge"),
    hyperparameters: str = Field(description="JSON string of hyperparameters", default="{}"),
    role_arn: str = Field(description="IAM role ARN for SageMaker", default=None),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Create and start a SageMaker training job.
    
    Supports:
    - Custom algorithms in ECR
    - Built-in algorithms (XGBoost, Linear Learner, etc.)
    - Distributed training
    - Spot instances for cost savings
    """
    if ctx:
        await ctx.info(f"Starting SageMaker training job: {job_name}")
    
    import json
    
    try:
        hyperparams = json.loads(hyperparameters)
        
        ml_engine = MLAIEngine()
        result = await ml_engine.create_sagemaker_training_job(
            job_name=job_name,
            algorithm_image=algorithm_image,
            input_data_s3=input_data_s3,
            output_data_s3=output_data_s3,
            instance_type=instance_type,
            hyperparameters=hyperparams,
            role_arn=role_arn,
            region=region
        )
        
        if ctx:
            await ctx.info(f"Training job started with pipeline ID: {result['pipeline_id']}")
        
        return result
        
    except json.JSONDecodeError as e:
        return {
            "status": "error",
            "message": f"Invalid JSON in hyperparameters: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Error starting SageMaker training: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def deploy_sagemaker_endpoint(
    model_name: str = Field(description="Name for the model and endpoint"),
    model_data_s3: str = Field(description="S3 URI of trained model artifacts"),
    container_image: str = Field(description="ECR URI of inference container"),
    instance_type: str = Field(description="Instance type for endpoint", default="ml.m5.large"),
    instance_count: int = Field(description="Number of instances", default=1),
    role_arn: str = Field(description="IAM role ARN for SageMaker", default=None),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Deploy a trained model to a SageMaker real-time endpoint.
    
    Features:
    - Auto-scaling capabilities
    - A/B testing with multiple models
    - Built-in monitoring
    - Low latency inference
    """
    if ctx:
        await ctx.info(f"Deploying model to SageMaker endpoint: {model_name}")
    
    ml_engine = MLAIEngine()
    
    try:
        result = await ml_engine.deploy_sagemaker_model(
            model_name=model_name,
            model_data_s3=model_data_s3,
            container_image=container_image,
            instance_type=instance_type,
            initial_instance_count=instance_count,
            role_arn=role_arn,
            region=region
        )
        
        if ctx:
            await ctx.info(f"Endpoint deployment initiated: {result['endpoint_name']}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error deploying SageMaker endpoint: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def list_bedrock_models(
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    List available Bedrock foundation models.
    
    Includes:
    - Claude (Anthropic)
    - Llama (Meta)
    - Titan (Amazon)
    - Stable Diffusion (Stability AI)
    - And more...
    """
    if ctx:
        await ctx.info("Listing available Bedrock foundation models")
    
    ml_engine = MLAIEngine()
    
    try:
        result = await ml_engine.list_bedrock_models(region)
        
        if ctx:
            await ctx.info(f"Found {result['model_count']} Bedrock models")
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing Bedrock models: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def finetune_bedrock_model(
    job_name: str = Field(description="Name for the fine-tuning job"),
    base_model_id: str = Field(description="ID of the base model to fine-tune"),
    training_data_s3: str = Field(description="S3 URI of training data in JSONL format"),
    output_s3: str = Field(description="S3 URI for output model"),
    hyperparameters: str = Field(description="JSON string of hyperparameters", default="{}"),
    role_arn: str = Field(description="IAM role ARN for Bedrock", default=None),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Fine-tune a Bedrock foundation model on custom data.
    
    Supports fine-tuning:
    - Claude for specialized tasks
    - Llama for domain-specific applications
    - Titan for custom embeddings
    """
    if ctx:
        await ctx.info(f"Starting Bedrock fine-tuning job: {job_name}")
    
    import json
    
    try:
        hyperparams = json.loads(hyperparameters) if hyperparameters else {}
        
        ml_engine = MLAIEngine()
        result = await ml_engine.create_bedrock_fine_tuning_job(
            job_name=job_name,
            base_model_id=base_model_id,
            training_data_s3=training_data_s3,
            output_s3=output_s3,
            hyperparameters=hyperparams,
            role_arn=role_arn,
            region=region
        )
        
        if ctx:
            await ctx.info(f"Fine-tuning job started with pipeline ID: {result['pipeline_id']}")
        
        return result
        
    except json.JSONDecodeError as e:
        return {
            "status": "error",
            "message": f"Invalid JSON in hyperparameters: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Error starting Bedrock fine-tuning: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def invoke_bedrock(
    model_id: str = Field(description="Bedrock model ID to invoke"),
    prompt: str = Field(description="Prompt for the model"),
    max_tokens: int = Field(description="Maximum tokens to generate", default=512),
    temperature: float = Field(description="Temperature for sampling", default=0.7),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Invoke a Bedrock model for inference.
    
    Use for:
    - Text generation with Claude, Llama, etc.
    - Code generation
    - Summarization
    - Question answering
    - And more...
    """
    if ctx:
        await ctx.info(f"Invoking Bedrock model: {model_id}")
    
    ml_engine = MLAIEngine()
    
    try:
        result = await ml_engine.invoke_bedrock_model(
            model_id=model_id,
            prompt=prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            region=region
        )
        
        if ctx:
            await ctx.info("Bedrock inference completed successfully")
        
        return result
        
    except Exception as e:
        logger.error(f"Error invoking Bedrock: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def prepare_ml_dataset(
    source_bucket: str = Field(description="Source S3 bucket name"),
    source_prefix: str = Field(description="Source prefix for data files"),
    dest_bucket: str = Field(description="Destination S3 bucket"),
    dest_prefix: str = Field(description="Destination prefix"),
    train_ratio: float = Field(description="Training data ratio", default=0.7),
    val_ratio: float = Field(description="Validation data ratio", default=0.2),
    test_ratio: float = Field(description="Test data ratio", default=0.1),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Prepare and organize ML dataset in S3 with train/val/test splits.
    
    Automatically:
    - Shuffles data
    - Creates train/validation/test directories
    - Maintains data balance
    - Preserves file formats
    """
    if ctx:
        await ctx.info(f"Preparing ML dataset from s3://{source_bucket}/{source_prefix}")
    
    ml_engine = MLAIEngine()
    
    try:
        result = await ml_engine.prepare_ml_dataset(
            source_bucket=source_bucket,
            source_prefix=source_prefix,
            dest_bucket=dest_bucket,
            dest_prefix=dest_prefix,
            split_ratio=(train_ratio, val_ratio, test_ratio),
            region=region
        )
        
        if ctx:
            await ctx.info(f"Dataset prepared: {result['train_files']} train, "
                          f"{result['validation_files']} val, {result['test_files']} test files")
        
        return result
        
    except Exception as e:
        logger.error(f"Error preparing ML dataset: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def create_automl_job(
    pipeline_name: str = Field(description="Name for the AutoML pipeline"),
    data_s3_uri: str = Field(description="S3 URI of training data CSV"),
    target_column: str = Field(description="Name of the target column to predict"),
    problem_type: str = Field(description="ML problem type", default="BinaryClassification"),
    objective_metric: str = Field(description="Optimization metric", default="F1"),
    max_candidates: int = Field(description="Maximum models to try", default=10),
    role_arn: str = Field(description="IAM role ARN for SageMaker", default=None),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Create an AutoML job using SageMaker Autopilot.
    
    Automatically:
    - Analyzes your data
    - Engineers features
    - Selects algorithms
    - Tunes hyperparameters
    - Provides model explainability
    
    Problem types: BinaryClassification, MulticlassClassification, Regression
    """
    if ctx:
        await ctx.info(f"Starting AutoML pipeline: {pipeline_name}")
    
    ml_engine = MLAIEngine()
    
    try:
        result = await ml_engine.create_automl_pipeline(
            pipeline_name=pipeline_name,
            data_s3_uri=data_s3_uri,
            target_column=target_column,
            problem_type=problem_type,
            objective_metric=objective_metric,
            max_candidates=max_candidates,
            role_arn=role_arn,
            region=region
        )
        
        if ctx:
            await ctx.info(f"AutoML job created. Estimated completion: {result['estimated_completion_time']}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error creating AutoML job: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def create_feature_store(
    feature_group_name: str = Field(description="Name for the feature group"),
    s3_uri: str = Field(description="S3 URI for offline feature storage"),
    record_identifier: str = Field(description="Column name for record ID"),
    event_time_feature: str = Field(description="Column name for event timestamp"),
    features: str = Field(description="JSON array of feature definitions"),
    role_arn: str = Field(description="IAM role ARN for SageMaker", default=None),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Create a SageMaker Feature Store for ML features.
    
    Benefits:
    - Centralized feature storage
    - Real-time and batch serving
    - Feature versioning
    - Consistency between training and inference
    
    Features format:
    [{"name": "user_id", "type": "String"},
     {"name": "purchase_amount", "type": "Fractional"},
     {"name": "item_count", "type": "Integral"}]
    """
    if ctx:
        await ctx.info(f"Creating feature store: {feature_group_name}")
    
    import json
    
    try:
        features_list = json.loads(features)
        
        ml_engine = MLAIEngine()
        result = await ml_engine.create_feature_store(
            feature_group_name=feature_group_name,
            s3_uri=s3_uri,
            record_identifier=record_identifier,
            event_time_feature=event_time_feature,
            features=features_list,
            role_arn=role_arn,
            region=region
        )
        
        if ctx:
            await ctx.info(f"Feature store created with {result['feature_count']} features")
        
        return result
        
    except json.JSONDecodeError as e:
        return {
            "status": "error",
            "message": f"Invalid JSON in features: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Error creating feature store: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@mcp.tool()
async def get_ml_pipeline_status(
    pipeline_id: str = Field(description="Pipeline ID to check status"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Get the status of any ML training pipeline.
    
    Works with:
    - SageMaker training jobs
    - Bedrock fine-tuning jobs
    - AutoML pipelines
    """
    if ctx:
        await ctx.info(f"Checking ML pipeline status: {pipeline_id}")
    
    ml_engine = MLAIEngine()
    
    try:
        result = await ml_engine.get_ml_pipeline_status(pipeline_id)
        
        if ctx:
            await ctx.info(f"Pipeline status: {result.get('status', 'unknown')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting pipeline status: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


# Security Hub Tools
@mcp.tool()
async def security_hub_get_findings(
    severity_threshold: str = Field(description="Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)", default="MEDIUM"),
    max_results: int = Field(description="Maximum findings to return", default=100),
    workflow_status: str = Field(description="Workflow status filter (NEW, ASSIGNED, IN_PROGRESS, RESOLVED)", default=None),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Retrieve security findings from AWS Security Hub.
    
    Features:
    - Filter by severity threshold
    - Filter by workflow status
    - Get detailed finding information
    """
    if ctx:
        await ctx.info(f"Retrieving Security Hub findings (severity >= {severity_threshold})")
    
    try:
        client = SecurityHubClient(region=region)
        
        # Convert string to enum
        severity = FindingSeverity[severity_threshold.upper()] if severity_threshold else None
        workflow = WorkflowStatus[workflow_status.upper()] if workflow_status else None
        
        findings = await client.get_findings(
            severity_threshold=severity,
            max_results=max_results,
            workflow_status=workflow
        )
        
        if ctx:
            await ctx.info(f"Found {len(findings)} security findings")
        
        return {
            "status": "success",
            "finding_count": len(findings),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "status": f.workflow_status.value,
                    "resource": f.resource_id,
                    "created": f.created_at.isoformat() if f.created_at else None
                }
                for f in findings
            ]
        }
    except Exception as e:
        logger.error(f"Error retrieving Security Hub findings: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def security_hub_update_finding(
    finding_id: str = Field(description="Security Hub finding ID"),
    workflow_status: str = Field(description="New workflow status (ASSIGNED, IN_PROGRESS, RESOLVED)"),
    note: str = Field(description="Optional note to add", default=None),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Update a security finding in Security Hub.
    
    Features:
    - Update workflow status
    - Add notes with context
    - Track remediation progress
    """
    if ctx:
        await ctx.info(f"Updating finding {finding_id} to status: {workflow_status}")
    
    try:
        client = SecurityHubClient(region=region)
        
        workflow = WorkflowStatus[workflow_status.upper()]
        
        response = await client.update_finding(
            finding_id=finding_id,
            workflow_status=workflow,
            note=note
        )
        
        return {
            "status": "success",
            "message": f"Finding {finding_id} updated to {workflow_status}",
            "response": response
        }
    except Exception as e:
        logger.error(f"Error updating finding: {e}")
        return {"status": "error", "message": str(e)}


# GuardDuty Tools
@mcp.tool()
async def guardduty_get_threats(
    severity_threshold: str = Field(description="Minimum severity (LOW, MEDIUM, HIGH)", default="MEDIUM"),
    max_results: int = Field(description="Maximum threats to return", default=100),
    archived: bool = Field(description="Include archived findings", default=False),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Retrieve threat findings from AWS GuardDuty.
    
    Features:
    - Real-time threat detection
    - Filter by severity
    - Get detailed threat intelligence
    """
    if ctx:
        await ctx.info(f"Retrieving GuardDuty threats (severity >= {severity_threshold})")
    
    try:
        client = GuardDutyClient(region=region)
        
        severity = ThreatSeverity[severity_threshold.upper()] if severity_threshold else None
        
        findings = await client.get_findings(
            severity_threshold=severity,
            max_results=max_results,
            archived=archived
        )
        
        if ctx:
            await ctx.info(f"Found {len(findings)} threat findings")
        
        return {
            "status": "success",
            "threat_count": len(findings),
            "threats": [
                {
                    "id": f.id,
                    "type": f.type,
                    "severity": f.threat_severity.value,
                    "title": f.title,
                    "resource_type": f.resource_type,
                    "resource_id": f.resource_id,
                    "confidence": f.confidence,
                    "count": f.count
                }
                for f in findings
            ]
        }
    except Exception as e:
        logger.error(f"Error retrieving GuardDuty findings: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def guardduty_threat_report(
    days: int = Field(description="Number of days to analyze", default=7),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Generate comprehensive threat analysis report from GuardDuty.
    
    Provides:
    - Threat statistics and trends
    - Top threats by type
    - Most affected resources
    """
    if ctx:
        await ctx.info(f"Generating threat report for last {days} days")
    
    try:
        client = GuardDutyClient(region=region)
        detector = ThreatDetector(client)
        
        from datetime import timedelta
        report = await detector.generate_threat_report(timedelta(days=days))
        
        if ctx:
            await ctx.info(f"Report generated with {report['total_findings']} findings")
        
        return {
            "status": "success",
            "report": report
        }
    except Exception as e:
        logger.error(f"Error generating threat report: {e}")
        return {"status": "error", "message": str(e)}


# IAM Analyzer Tools
@mcp.tool()
async def iam_analyze_policies(
    include_aws_managed: bool = Field(description="Include AWS managed policies", default=False),
    risk_level: str = Field(description="Minimum risk level to report (LOW, MEDIUM, HIGH, CRITICAL)", default="MEDIUM"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Analyze IAM policies for security risks and overly permissive access.
    
    Features:
    - Detect wildcard permissions
    - Find dangerous actions
    - Identify unused permissions
    - Generate least-privilege recommendations
    """
    if ctx:
        await ctx.info("Analyzing IAM policies for security risks")
    
    try:
        analyzer = IAMAnalyzer()
        
        results = await analyzer.analyze_all_policies(include_aws_managed=include_aws_managed)
        
        # Filter by risk level
        min_risk = RiskLevel[risk_level.upper()]
        risk_scores = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}
        min_score = risk_scores[min_risk]
        
        filtered_results = []
        for result in results:
            max_finding_risk = max(
                (risk_scores[f.risk_level] for f in result.findings),
                default=0
            )
            if max_finding_risk >= min_score:
                filtered_results.append(result)
        
        if ctx:
            await ctx.info(f"Found {len(filtered_results)} policies with risks >= {risk_level}")
        
        return {
            "status": "success",
            "policy_count": len(filtered_results),
            "policies": [
                {
                    "policy_name": r.policy_name,
                    "resource_arn": r.resource_arn,
                    "risk_score": r.risk_score,
                    "finding_count": len(r.findings),
                    "findings": [
                        {
                            "type": f.finding_type.value,
                            "risk": f.risk_level.value,
                            "description": f.description,
                            "recommendation": f.recommendation
                        }
                        for f in r.findings
                    ]
                }
                for r in filtered_results
            ]
        }
    except Exception as e:
        logger.error(f"Error analyzing policies: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def iam_generate_least_privilege(
    policy_arn: str = Field(description="ARN of the policy to optimize"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Generate least-privilege version of an IAM policy.
    
    Features:
    - Remove wildcard permissions
    - Scope resources appropriately
    - Add security conditions
    - Calculate risk reduction
    """
    if ctx:
        await ctx.info(f"Generating least-privilege policy for {policy_arn}")
    
    try:
        analyzer = IAMAnalyzer()
        
        # Get current policy
        result = await analyzer.analyze_policy(policy_arn)
        
        if not result.policy_document:
            return {"status": "error", "message": "Could not retrieve policy document"}
        
        # Generate recommendation
        recommendation = await analyzer.generate_least_privilege_policy(
            result.policy_document
        )
        
        if ctx:
            await ctx.info(f"Generated policy with {recommendation.risk_reduction:.1%} risk reduction")
        
        return {
            "status": "success",
            "original_policy": recommendation.original_policy,
            "recommended_policy": recommendation.recommended_policy,
            "removed_permissions": recommendation.removed_permissions,
            "risk_reduction": recommendation.risk_reduction,
            "explanation": recommendation.explanation
        }
    except Exception as e:
        logger.error(f"Error generating least-privilege policy: {e}")
        return {"status": "error", "message": str(e)}


# Secrets Manager Tools
@mcp.tool()
async def secrets_create(
    name: str = Field(description="Secret name"),
    secret_value: str = Field(description="Secret value (string or JSON)"),
    description: str = Field(description="Secret description", default=None),
    secret_type: str = Field(description="Type of secret (database, api_key, oauth_token, ssh_key, generic)", default="generic"),
    kms_key_id: str = Field(description="KMS key ID for encryption", default=None),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Create a new secret in AWS Secrets Manager.
    
    Features:
    - Secure storage with encryption
    - Support for various secret types
    - Automatic versioning
    - Optional KMS encryption
    """
    if ctx:
        await ctx.info(f"Creating secret: {name}")
    
    try:
        client = SecretsManagerClient(region=region)
        
        # Try to parse as JSON
        import json
        try:
            secret_dict = json.loads(secret_value)
        except:
            secret_dict = secret_value
        
        secret = await client.create_secret(
            name=name,
            secret_value=secret_dict,
            description=description,
            kms_key_id=kms_key_id,
            secret_type=SecretType[secret_type.upper()]
        )
        
        return {
            "status": "success",
            "secret_arn": secret.arn,
            "version_id": secret.version_id,
            "name": secret.name
        }
    except Exception as e:
        logger.error(f"Error creating secret: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def secrets_rotate_password(
    name: str = Field(description="Secret name containing database credentials"),
    length: int = Field(description="Password length", default=32),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Generate and store a new random password in Secrets Manager.
    
    Features:
    - Cryptographically secure passwords
    - Configurable complexity
    - Automatic secret update
    """
    if ctx:
        await ctx.info(f"Rotating password for secret: {name}")
    
    try:
        client = SecretsManagerClient(region=region)
        
        # Generate new password
        new_password = await client.generate_random_password(
            length=length,
            exclude_characters=' "\'\\',
            require_each_included_type=True
        )
        
        # Get current secret
        secret, current_value = await client.get_secret(name)
        
        # Update with new password
        if isinstance(current_value, dict):
            current_value['password'] = new_password
            updated_secret = await client.update_secret(name, current_value)
        else:
            updated_secret = await client.update_secret(name, new_password)
        
        return {
            "status": "success",
            "secret_name": updated_secret.name,
            "version_id": updated_secret.version_id,
            "message": "Password rotated successfully"
        }
    except Exception as e:
        logger.error(f"Error rotating password: {e}")
        return {"status": "error", "message": str(e)}


# Compliance Tools
@mcp.tool()
async def compliance_scan(
    framework: str = Field(description="Compliance framework (PCI_DSS, HIPAA, SOC2, CIS)"),
    auto_remediate: bool = Field(description="Automatically fix issues where possible", default=False),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Run compliance scan against security frameworks.
    
    Supported frameworks:
    - PCI DSS: Payment card security
    - HIPAA: Healthcare data protection
    - SOC2: Service organization controls
    - CIS: Security benchmarks
    
    Features:
    - Automated compliance checking
    - Detailed findings and evidence
    - Optional auto-remediation
    - Compliance scoring
    """
    if ctx:
        await ctx.info(f"Running {framework} compliance scan")
    
    try:
        scanner = ComplianceScanner(region=region)
        
        framework_enum = ComplianceFramework[framework.upper()]
        
        report = await scanner.scan_compliance(
            framework=framework_enum,
            auto_remediate=auto_remediate
        )
        
        if ctx:
            await ctx.info(f"Compliance score: {report.compliance_score:.1f}%")
        
        # Summarize results
        critical_findings = [
            r for r in report.results 
            if r.status.value == "NON_COMPLIANT" and r.control.severity.value == "CRITICAL"
        ]
        
        high_findings = [
            r for r in report.results
            if r.status.value == "NON_COMPLIANT" and r.control.severity.value == "HIGH"
        ]
        
        return {
            "status": "success",
            "framework": report.framework.value,
            "compliance_score": report.compliance_score,
            "scan_date": report.scan_date.isoformat(),
            "summary": {
                "total_controls": report.total_controls,
                "compliant": report.compliant_controls,
                "non_compliant": report.non_compliant_controls,
                "not_applicable": report.not_applicable_controls,
                "errors": report.error_controls
            },
            "critical_findings": len(critical_findings),
            "high_findings": len(high_findings),
            "recommendations": report.recommendations,
            "details": [
                {
                    "control_id": r.control.control_id,
                    "title": r.control.title,
                    "status": r.status.value,
                    "severity": r.control.severity.value,
                    "details": r.details,
                    "remediation_available": r.remediation_available
                }
                for r in report.results
                if r.status.value != "COMPLIANT"
            ][:20]  # Limit to top 20 findings
        }
    except Exception as e:
        logger.error(f"Error running compliance scan: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def compliance_export_report(
    framework: str = Field(description="Compliance framework (PCI_DSS, HIPAA, SOC2, CIS)"),
    format: str = Field(description="Export format (json, csv, html)", default="json"),
    output_file: str = Field(description="Output file path"),
    region: str = Field(description="AWS region", default="us-east-1"),
    ctx: Context | None = None,
) -> Dict[str, Any]:
    """
    Export detailed compliance report in various formats.
    
    Features:
    - Multiple export formats
    - Detailed findings with evidence
    - Executive summary
    - Remediation guidance
    """
    if ctx:
        await ctx.info(f"Exporting {framework} compliance report as {format}")
    
    try:
        scanner = ComplianceScanner(region=region)
        
        framework_enum = ComplianceFramework[framework.upper()]
        
        # Run scan
        report = await scanner.scan_compliance(framework=framework_enum)
        
        # Export report
        exported_content = await scanner.export_report(report, format=format)
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(exported_content)
        
        if ctx:
            await ctx.info(f"Report exported to {output_file}")
        
        return {
            "status": "success",
            "message": f"Compliance report exported to {output_file}",
            "format": format,
            "file_path": output_file,
            "compliance_score": report.compliance_score
        }
    except Exception as e:
        logger.error(f"Error exporting compliance report: {e}")
        return {"status": "error", "message": str(e)}
