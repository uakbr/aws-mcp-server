"""AWS Security Hub integration for centralized security findings management.

This module provides integration with AWS Security Hub to:
- Retrieve and analyze security findings across multiple AWS services
- Create custom findings for application-specific security issues
- Implement automated remediation workflows
- Generate security reports and metrics
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class FindingSeverity(Enum):
    """Security finding severity levels."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ComplianceStatus(Enum):
    """Compliance status for security findings."""

    PASSED = "PASSED"
    WARNING = "WARNING"
    FAILED = "FAILED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class WorkflowStatus(Enum):
    """Workflow status for security findings."""

    NEW = "NEW"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    DEFERRED = "DEFERRED"
    RESOLVED = "RESOLVED"


class RecordState(Enum):
    """Record state for security findings."""

    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


@dataclass
class SecurityFinding:
    """Represents a security finding from Security Hub."""

    id: str
    title: str
    description: str
    severity: FindingSeverity
    compliance_status: Optional[ComplianceStatus] = None
    workflow_status: WorkflowStatus = WorkflowStatus.NEW
    record_state: RecordState = RecordState.ACTIVE
    product_arn: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    region: Optional[str] = None
    account_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    remediation: Optional[dict[str, Any]] = None
    source_url: Optional[str] = None
    types: list[str] = field(default_factory=list)
    network_path: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    related_findings: list[dict[str, Any]] = field(default_factory=list)
    user_defined_fields: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_aws_finding(cls, finding: dict[str, Any]) -> "SecurityFinding":
        """Create SecurityFinding from AWS Security Hub finding format."""
        resources = finding.get("Resources", [{}])[0] if finding.get("Resources") else {}

        return cls(
            id=finding.get("Id", ""),
            title=finding.get("Title", ""),
            description=finding.get("Description", ""),
            severity=FindingSeverity(finding.get("Severity", {}).get("Label", "INFORMATIONAL")),
            compliance_status=ComplianceStatus(finding.get("Compliance", {}).get("Status")) if finding.get("Compliance", {}).get("Status") else None,
            workflow_status=WorkflowStatus(finding.get("Workflow", {}).get("Status", "NEW")),
            record_state=RecordState(finding.get("RecordState", "ACTIVE")),
            product_arn=finding.get("ProductArn"),
            resource_type=resources.get("Type"),
            resource_id=resources.get("Id"),
            region=resources.get("Region"),
            account_id=finding.get("AwsAccountId"),
            created_at=datetime.fromisoformat(finding.get("CreatedAt", "").replace("Z", "+00:00")) if finding.get("CreatedAt") else None,
            updated_at=datetime.fromisoformat(finding.get("UpdatedAt", "").replace("Z", "+00:00")) if finding.get("UpdatedAt") else None,
            remediation=finding.get("Remediation"),
            source_url=finding.get("SourceUrl"),
            types=finding.get("Types", []),
            network_path=finding.get("NetworkPath", []),
            vulnerabilities=finding.get("Vulnerabilities", []),
            related_findings=finding.get("RelatedFindings", []),
            user_defined_fields=finding.get("UserDefinedFields", {}),
        )


class SecurityHubClient:
    """Client for interacting with AWS Security Hub."""

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """Initialize Security Hub client.

        Args:
            region: AWS region for Security Hub
            profile: AWS profile to use for authentication
        """
        self.region = region or "us-east-1"
        self.profile = profile

        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.client = session.client("securityhub", region_name=self.region)
        self._hub_arn: Optional[str] = None

    async def enable_security_hub(self, enable_default_standards: bool = True) -> dict[str, Any]:
        """Enable Security Hub in the current account/region.

        Args:
            enable_default_standards: Whether to enable default security standards

        Returns:
            Response from Security Hub enablement
        """
        try:
            response = await asyncio.to_thread(self.client.enable_security_hub, EnableDefaultStandards=enable_default_standards)
            logger.info(f"Security Hub enabled in region {self.region}")
            return response
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceConflictException":
                logger.info("Security Hub is already enabled")
                return {"message": "Security Hub already enabled"}
            raise

    async def get_findings(
        self,
        filters: Optional[dict[str, Any]] = None,
        max_results: int = 100,
        severity_threshold: Optional[FindingSeverity] = None,
        compliance_status: Optional[ComplianceStatus] = None,
        workflow_status: Optional[WorkflowStatus] = None,
    ) -> list[SecurityFinding]:
        """Retrieve security findings from Security Hub.

        Args:
            filters: Custom filters for findings query
            max_results: Maximum number of findings to return
            severity_threshold: Minimum severity level to include
            compliance_status: Filter by compliance status
            workflow_status: Filter by workflow status

        Returns:
            List of security findings
        """
        if filters is None:
            filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}

        # Add severity filter if threshold specified
        if severity_threshold:
            severity_values = self._get_severities_above_threshold(severity_threshold)
            filters["SeverityLabel"] = [{"Value": sev.value, "Comparison": "EQUALS"} for sev in severity_values]

        # Add compliance status filter
        if compliance_status:
            filters["ComplianceStatus"] = [{"Value": compliance_status.value, "Comparison": "EQUALS"}]

        # Add workflow status filter
        if workflow_status:
            filters["WorkflowStatus"] = [{"Value": workflow_status.value, "Comparison": "EQUALS"}]

        findings = []
        paginator = self.client.get_paginator("get_findings")

        try:
            async for page in self._async_paginate(paginator, Filters=filters, MaxResults=min(max_results, 100)):
                for finding in page.get("Findings", []):
                    findings.append(SecurityFinding.from_aws_finding(finding))
                    if len(findings) >= max_results:
                        return findings[:max_results]
        except ClientError as e:
            logger.error(f"Error retrieving findings: {e}")
            raise

        return findings

    async def create_finding(self, finding: SecurityFinding, product_arn: Optional[str] = None) -> dict[str, Any]:
        """Create a custom security finding in Security Hub.

        Args:
            finding: Security finding to create
            product_arn: Product ARN for the finding (uses default if not specified)

        Returns:
            Response from Security Hub
        """
        if not product_arn:
            product_arn = await self._get_default_product_arn()

        finding_dict = {
            "SchemaVersion": "2018-10-08",
            "Id": finding.id,
            "ProductArn": product_arn,
            "GeneratorId": f"aws-mcp-server/{finding.resource_type or 'custom'}",
            "AwsAccountId": finding.account_id or await self._get_account_id(),
            "CreatedAt": (finding.created_at or datetime.now(timezone.utc)).isoformat(),
            "UpdatedAt": (finding.updated_at or datetime.now(timezone.utc)).isoformat(),
            "Title": finding.title,
            "Description": finding.description,
            "Severity": {"Label": finding.severity.value},
            "Types": finding.types or ["Software and Configuration Checks"],
            "RecordState": finding.record_state.value,
            "Workflow": {"Status": finding.workflow_status.value},
        }

        # Add optional fields
        if finding.compliance_status:
            finding_dict["Compliance"] = {"Status": finding.compliance_status.value}

        if finding.resource_id and finding.resource_type:
            finding_dict["Resources"] = [
                {
                    "Type": finding.resource_type,
                    "Id": finding.resource_id,
                    "Region": finding.region or self.region,
                }
            ]

        if finding.remediation:
            finding_dict["Remediation"] = finding.remediation

        if finding.source_url:
            finding_dict["SourceUrl"] = finding.source_url

        if finding.user_defined_fields:
            finding_dict["UserDefinedFields"] = finding.user_defined_fields

        try:
            response = await asyncio.to_thread(self.client.batch_import_findings, Findings=[finding_dict])
            if response["FailedCount"] > 0:
                logger.error(f"Failed to import finding: {response['FailedFindings']}")
                raise Exception(f"Failed to import finding: {response['FailedFindings']}")
            return response
        except ClientError as e:
            logger.error(f"Error creating finding: {e}")
            raise

    async def update_finding(
        self,
        finding_id: str,
        workflow_status: Optional[WorkflowStatus] = None,
        user_defined_fields: Optional[dict[str, str]] = None,
        note: Optional[str] = None,
    ) -> dict[str, Any]:
        """Update an existing security finding.

        Args:
            finding_id: ID of the finding to update
            workflow_status: New workflow status
            user_defined_fields: User-defined fields to update
            note: Note to add to the finding

        Returns:
            Response from Security Hub
        """
        filters = {"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]}

        update = {}
        if workflow_status:
            update["Workflow"] = {"Status": workflow_status.value}

        if user_defined_fields:
            update["UserDefinedFields"] = user_defined_fields

        if note:
            update["Note"] = {"Text": note, "UpdatedBy": "aws-mcp-server"}

        try:
            response = await asyncio.to_thread(self.client.update_findings, Filters=filters, **update)
            return response
        except ClientError as e:
            logger.error(f"Error updating finding: {e}")
            raise

    async def get_insights(self) -> list[dict[str, Any]]:
        """Get Security Hub insights (aggregated finding data).

        Returns:
            List of insights with their results
        """
        insights = []
        paginator = self.client.get_paginator("get_insights")

        try:
            async for page in self._async_paginate(paginator):
                for insight in page.get("Insights", []):
                    # Get results for each insight
                    insight_arn = insight["InsightArn"]
                    results = await self._get_insight_results(insight_arn)
                    insights.append({"insight": insight, "results": results})
        except ClientError as e:
            logger.error(f"Error retrieving insights: {e}")
            raise

        return insights

    async def enable_security_standard(self, standards_arn: str) -> dict[str, Any]:
        """Enable a security standard in Security Hub.

        Args:
            standards_arn: ARN of the security standard to enable

        Returns:
            Response from Security Hub
        """
        try:
            response = await asyncio.to_thread(self.client.batch_enable_standards, StandardsSubscriptionRequests=[{"StandardsArn": standards_arn}])
            return response
        except ClientError as e:
            logger.error(f"Error enabling security standard: {e}")
            raise

    async def get_compliance_summary(self) -> dict[str, dict[str, int]]:
        """Get compliance summary across all enabled standards.

        Returns:
            Dictionary mapping standard names to compliance counts
        """
        summary = {}

        # Get enabled standards
        standards = await self._get_enabled_standards()

        for standard in standards:
            standard_name = standard["StandardsArn"].split("/")[-1]

            # Get findings for this standard
            filters = {
                "ProductArn": [{"Value": standard["StandardsArn"], "Comparison": "PREFIX"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            }

            findings = await self.get_findings(filters=filters, max_results=1000)

            # Count by compliance status
            compliance_counts = {"PASSED": 0, "WARNING": 0, "FAILED": 0, "NOT_AVAILABLE": 0}

            for finding in findings:
                if finding.compliance_status:
                    compliance_counts[finding.compliance_status.value] += 1

            summary[standard_name] = compliance_counts

        return summary

    async def create_automation_rule(
        self, rule_name: str, finding_filters: dict[str, Any], actions: list[dict[str, Any]], description: Optional[str] = None
    ) -> dict[str, Any]:
        """Create an automation rule for automatic finding updates.

        Args:
            rule_name: Name of the automation rule
            finding_filters: Filters to match findings
            actions: Actions to take on matched findings
            description: Description of the rule

        Returns:
            Response from Security Hub
        """
        rule = {
            "RuleName": rule_name,
            "RuleStatus": "ENABLED",
            "Criteria": finding_filters,
            "Actions": actions,
        }

        if description:
            rule["Description"] = description

        try:
            response = await asyncio.to_thread(self.client.create_automation_rule, **rule)
            logger.info(f"Created automation rule: {rule_name}")
            return response
        except ClientError as e:
            logger.error(f"Error creating automation rule: {e}")
            raise

    # Helper methods

    def _get_severities_above_threshold(self, threshold: FindingSeverity) -> list[FindingSeverity]:
        """Get list of severities at or above threshold."""
        severity_order = [
            FindingSeverity.INFORMATIONAL,
            FindingSeverity.LOW,
            FindingSeverity.MEDIUM,
            FindingSeverity.HIGH,
            FindingSeverity.CRITICAL,
        ]

        threshold_index = severity_order.index(threshold)
        return severity_order[threshold_index:]

    async def _async_paginate(self, paginator, **kwargs):
        """Async wrapper for boto3 paginator."""
        page_iterator = paginator.paginate(**kwargs)
        for page in page_iterator:
            yield page

    async def _get_default_product_arn(self) -> str:
        """Get default product ARN for custom findings."""
        account_id = await self._get_account_id()
        return f"arn:aws:securityhub:{self.region}:{account_id}:product/{account_id}/default"

    async def _get_account_id(self) -> str:
        """Get current AWS account ID."""
        sts = boto3.client("sts")
        response = await asyncio.to_thread(sts.get_caller_identity)
        return response["Account"]

    async def _get_insight_results(self, insight_arn: str) -> dict[str, Any]:
        """Get results for a specific insight."""
        try:
            response = await asyncio.to_thread(self.client.get_insight_results, InsightArn=insight_arn)
            return response.get("InsightResults", {})
        except ClientError as e:
            logger.error(f"Error getting insight results: {e}")
            return {}

    async def _get_enabled_standards(self) -> list[dict[str, Any]]:
        """Get list of enabled security standards."""
        standards = []
        paginator = self.client.get_paginator("get_enabled_standards")

        try:
            async for page in self._async_paginate(paginator):
                standards.extend(page.get("StandardsSubscriptions", []))
        except ClientError as e:
            logger.error(f"Error getting enabled standards: {e}")

        return standards