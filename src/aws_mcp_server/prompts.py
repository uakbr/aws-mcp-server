"""AWS CLI prompt definitions for the AWS MCP Server.

This module provides a collection of useful prompt templates for common AWS use cases.
These prompts help ensure consistent best practices and efficient AWS resource management.
"""

import logging

logger = logging.getLogger(__name__)


def register_prompts(mcp):
    """Register all prompts with the MCP server instance.

    Args:
        mcp: The FastMCP server instance
    """
    logger.info("Registering AWS prompt templates")

    @mcp.prompt()
    def create_resource(resource_type: str, resource_name: str) -> str:
        """Generate AWS CLI commands to create common AWS resources with best practices.

        Args:
            resource_type: Type of AWS resource to create (e.g., s3-bucket, ec2-instance, lambda)
            resource_name: Name for the new resource

        Returns:
            Formatted prompt string for resource creation
        """
        return f"""Generate the AWS CLI commands to create a new {resource_type} named {resource_name} 
following AWS best practices.

Please include:
1. The primary creation command with appropriate security settings
2. Any supporting resources needed (roles, policies, etc.)
3. Tagging commands to ensure proper resource management
4. Verification commands to confirm successful creation

For security, follow the principle of least privilege and explain any important 
security considerations specific to this resource type."""

    @mcp.prompt()
    def security_audit(service: str) -> str:
        """Generate AWS CLI commands for performing a security audit on a service.

        Args:
            service: AWS service to audit (e.g., s3, ec2, iam, rds)

        Returns:
            Formatted prompt string for security auditing
        """
        return f"""Generate AWS CLI commands to perform a comprehensive security audit
of {service} resources in my AWS account.

Include commands to:
1. Identify resources with public access or excessive permissions
2. Detect weak or unused security configurations
3. Check for unencrypted data or transport
4. Verify compliance with AWS best practices
5. List potential improvements to enhance security posture

Also provide a prioritized list of follow-up actions based on typical findings."""

    @mcp.prompt()
    def cost_optimization(service: str) -> str:
        """Generate AWS CLI commands for cost optimization recommendations.

        Args:
            service: AWS service to optimize costs for

        Returns:
            Formatted prompt string for cost optimization
        """
        return f"""Generate AWS CLI commands to identify cost optimization opportunities 
for {service} in my AWS account.

Include commands to:
1. Find unused or underutilized resources
2. Identify resources that could be downsized or use a different pricing model
3. Detect patterns of usage that could benefit from Reserved Instances or Savings Plans
4. List resources without proper cost allocation tags
5. Generate a cost breakdown by resource for the past 30 days

Also provide recommendations for automated cost management tools or practices."""

    @mcp.prompt()
    def resource_inventory(service: str, region: str = "all") -> str:
        """Generate AWS CLI commands to inventory resources for a service.

        Args:
            service: AWS service to inventory (e.g., s3, ec2, rds)
            region: AWS region or "all" for multi-region inventory

        Returns:
            Formatted prompt string for resource inventory
        """
        region_text = f"in the {region} region" if region != "all" else "across all regions"

        return f"""Generate AWS CLI commands to create a comprehensive inventory 
of all {service} resources {region_text}.

Include commands to:
1. List all resources with their key properties and metadata
2. Show resource relationships and dependencies
3. Display resource tags and ownership information
4. Identify untagged or potentially abandoned resources
5. Export the inventory in a structured format

Structure the commands to reuse existing code and patterns where possible."""

    @mcp.prompt()
    def troubleshoot_service(service: str, resource_id: str) -> str:
        """Generate AWS CLI commands for troubleshooting service issues.

        Args:
            service: AWS service to troubleshoot (e.g., ec2, rds, lambda)
            resource_id: ID of the specific resource having issues

        Returns:
            Formatted prompt string for troubleshooting
        """
        return f"""Generate AWS CLI commands to troubleshoot issues with {service} 
resource {resource_id}.

Include commands to:
1. Check resource status, configuration, and health
2. Review recent changes or modifications
3. Examine logs, metrics, and performance data
4. Verify network connectivity and security settings
5. Identify common failure points or bottlenecks
6. Compare against AWS best practices

Structure the troubleshooting as a systematic process from basic to advanced checks."""

    @mcp.prompt()
    def iam_policy_generator(service: str, actions: str, resource_pattern: str = "*") -> str:
        """Generate least-privilege IAM policies for specific services and actions.

        Args:
            service: AWS service for the policy (e.g., s3, dynamodb)
            actions: Comma-separated list of actions (e.g., "GetObject,PutObject")
            resource_pattern: Resource ARN pattern (e.g., "arn:aws:s3:::my-bucket/*")

        Returns:
            Formatted prompt string for IAM policy generation
        """
        return f"""Generate a least-privilege IAM policy that allows only the required permissions
for {service} with these specific actions: {actions}.

Resource pattern: {resource_pattern}

The policy should:
1. Follow AWS security best practices
2. Include only the minimum permissions needed
3. Use proper condition keys to further restrict access when appropriate
4. Include explanatory comments for each permission block
5. Be ready to use with the AWS CLI for policy creation

Also provide the AWS CLI command to apply this policy to a role or user."""

    @mcp.prompt()
    def service_monitoring(service: str, metric_type: str = "performance") -> str:
        """Generate AWS CLI commands to set up monitoring for a service.

        Args:
            service: AWS service to monitor (e.g., ec2, rds, lambda)
            metric_type: Type of metrics to monitor (e.g., performance, cost, security)

        Returns:
            Formatted prompt string for monitoring setup
        """
        return f"""Generate AWS CLI commands to set up comprehensive {metric_type} monitoring 
for {service} resources.

Include commands to:
1. Create CloudWatch dashboards with relevant metrics
2. Set up appropriate CloudWatch alarms for critical thresholds
3. Configure detailed logging with Log Insights queries
4. Enable any service-specific monitoring features
5. Create an SNS topic and subscription for notifications

The monitoring solution should be reusable across multiple resources and 
follow operational excellence best practices."""

    @mcp.prompt()
    def disaster_recovery(service: str, recovery_point_objective: str = "1 hour") -> str:
        """Generate AWS CLI commands to implement disaster recovery for a service.

        Args:
            service: AWS service to protect (e.g., ec2, rds, dynamodb)
            recovery_point_objective: Target RPO (e.g., "1 hour", "15 minutes")

        Returns:
            Formatted prompt string for DR setup
        """
        return f"""Generate AWS CLI commands to implement a disaster recovery solution
for {service} with a Recovery Point Objective (RPO) of {recovery_point_objective}.

Include commands to:
1. Configure appropriate backup mechanisms (snapshots, replication, etc.)
2. Set up cross-region or cross-account redundancy
3. Create automation for recovery processes
4. Implement monitoring and alerting for backup failures
5. Define validation procedures to verify recovery readiness

The solution should balance cost effectiveness with meeting the specified RPO
and follow AWS Well-Architected best practices for reliability."""

    @mcp.prompt()
    def compliance_check(compliance_standard: str, service: str = "all") -> str:
        """Generate AWS CLI commands to check compliance with standards.

        Args:
            compliance_standard: Compliance standard to check (e.g., "HIPAA", "PCI", "GDPR")
            service: Specific AWS service or "all" for account-wide checks

        Returns:
            Formatted prompt string for compliance checking
        """
        service_scope = f"for {service}" if service != "all" else "across all relevant services"

        return f"""Generate AWS CLI commands to assess {compliance_standard} compliance {service_scope}.

Include commands to:
1. Identify resources that may not meet compliance requirements
2. Check encryption settings and data protection measures
3. Audit access controls and authentication mechanisms
4. Verify logging and monitoring configurations
5. Assess network security and isolation

Also provide remediation commands for common compliance gaps and explain
the specific {compliance_standard} requirements being checked."""

    @mcp.prompt()
    def resource_cleanup(service: str, criteria: str = "unused") -> str:
        """Generate AWS CLI commands to identify and cleanup unused resources.

        Args:
            service: AWS service to cleanup (e.g., ec2, ebs, rds)
            criteria: Criteria for cleanup (e.g., "unused", "old", "untagged")

        Returns:
            Formatted prompt string for resource cleanup
        """
        return f"""Generate AWS CLI commands to identify and safely clean up {criteria} {service} resources.

Include commands to:
1. Identify resources matching the {criteria} criteria with appropriate filters
2. Generate a report of resources before deletion for review
3. Create backups or snapshots where appropriate before removal
4. Safely delete or terminate the identified resources
5. Verify successful cleanup and calculate cost savings

The commands should include appropriate safeguards to prevent accidental deletion
of critical resources and follow AWS operational best practices."""

    logger.info("Successfully registered all AWS prompt templates")
