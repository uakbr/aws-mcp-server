"""AWS GuardDuty integration for threat detection and response.

This module provides integration with AWS GuardDuty to:
- Monitor and detect threats across AWS accounts
- Implement automated threat response workflows
- Generate threat intelligence reports
- Manage threat suppression rules
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class ThreatSeverity(Enum):
    """GuardDuty finding severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ThreatType(Enum):
    """Common GuardDuty threat types."""

    RECON = "Recon"
    INSTANCE_COMPROMISE = "UnauthorizedAccess"
    MALWARE = "Trojan"
    BACKDOOR = "Backdoor"
    CRYPTO_MINING = "CryptoCurrency"
    POLICY_VIOLATION = "Policy"
    STEALTH = "Stealth"
    IMPACT = "Impact"


@dataclass
class ThreatFinding:
    """Represents a threat finding from GuardDuty."""

    id: str
    type: str
    severity: float
    title: str
    description: str
    resource_type: str
    resource_id: str
    region: str
    account_id: str
    created_at: datetime
    updated_at: datetime
    confidence: float
    threat_severity: ThreatSeverity
    service_name: str = "guardduty"
    archived: bool = False
    count: int = 1
    threat_intelligence_details: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    affected_resources: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_guardduty_finding(cls, finding: dict[str, Any]) -> "ThreatFinding":
        """Create ThreatFinding from GuardDuty finding format."""
        severity = finding.get("Severity", 0)
        resource = finding.get("Resource", {})

        # Determine threat severity based on numeric severity
        if severity >= 7.0:
            threat_severity = ThreatSeverity.HIGH
        elif severity >= 4.0:
            threat_severity = ThreatSeverity.MEDIUM
        else:
            threat_severity = ThreatSeverity.LOW

        return cls(
            id=finding.get("Id", ""),
            type=finding.get("Type", ""),
            severity=severity,
            title=finding.get("Title", ""),
            description=finding.get("Description", ""),
            resource_type=resource.get("ResourceType", ""),
            resource_id=self._extract_resource_id(resource),
            region=finding.get("Region", ""),
            account_id=finding.get("AccountId", ""),
            created_at=datetime.fromisoformat(finding.get("CreatedAt", "").replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(finding.get("UpdatedAt", "").replace("Z", "+00:00")),
            confidence=finding.get("Confidence", 0),
            threat_severity=threat_severity,
            service_name=finding.get("Service", {}).get("ServiceName", "guardduty"),
            archived=finding.get("Service", {}).get("Archived", False),
            count=finding.get("Service", {}).get("Count", 1),
            threat_intelligence_details=finding.get("Service", {}).get("ThreatIntelligenceDetails", []),
            evidence=finding.get("Service", {}).get("Evidence", {}),
            affected_resources=[resource] if resource else [],
        )

    @staticmethod
    def _extract_resource_id(resource: dict[str, Any]) -> str:
        """Extract resource ID based on resource type."""
        if resource.get("ResourceType") == "Instance":
            return resource.get("InstanceDetails", {}).get("InstanceId", "")
        elif resource.get("ResourceType") == "AccessKey":
            return resource.get("AccessKeyDetails", {}).get("AccessKeyId", "")
        elif resource.get("ResourceType") == "S3Bucket":
            return resource.get("S3BucketDetails", [{}])[0].get("Name", "") if resource.get("S3BucketDetails") else ""
        elif resource.get("ResourceType") == "Cluster":
            return resource.get("EksClusterDetails", {}).get("Name", "")
        return ""


@dataclass
class ThreatIntelligenceSet:
    """Represents a threat intelligence set in GuardDuty."""

    id: str
    name: str
    format: str
    location: str
    status: str
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class IPSet:
    """Represents an IP set for GuardDuty allow/deny lists."""

    id: str
    name: str
    format: str
    location: str
    status: str
    tags: dict[str, str] = field(default_factory=dict)


class GuardDutyClient:
    """Client for interacting with AWS GuardDuty."""

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """Initialize GuardDuty client.

        Args:
            region: AWS region for GuardDuty
            profile: AWS profile to use for authentication
        """
        self.region = region or "us-east-1"
        self.profile = profile

        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.client = session.client("guardduty", region_name=self.region)
        self._detector_id: Optional[str] = None

    async def create_detector(self, enable: bool = True, finding_publishing_frequency: str = "FIFTEEN_MINUTES") -> str:
        """Create a new GuardDuty detector.

        Args:
            enable: Whether to enable the detector immediately
            finding_publishing_frequency: How often to publish findings

        Returns:
            Detector ID
        """
        try:
            response = await asyncio.to_thread(
                self.client.create_detector, Enable=enable, FindingPublishingFrequency=finding_publishing_frequency
            )
            detector_id = response["DetectorId"]
            logger.info(f"Created GuardDuty detector: {detector_id}")
            return detector_id
        except ClientError as e:
            logger.error(f"Error creating detector: {e}")
            raise

    async def get_detector_id(self) -> str:
        """Get the detector ID for the current account/region."""
        if self._detector_id:
            return self._detector_id

        try:
            response = await asyncio.to_thread(self.client.list_detectors)
            detector_ids = response.get("DetectorIds", [])

            if not detector_ids:
                # Create a new detector if none exists
                self._detector_id = await self.create_detector()
            else:
                self._detector_id = detector_ids[0]

            return self._detector_id
        except ClientError as e:
            logger.error(f"Error getting detector ID: {e}")
            raise

    async def get_findings(
        self,
        severity_threshold: Optional[ThreatSeverity] = None,
        finding_types: Optional[list[str]] = None,
        resource_types: Optional[list[str]] = None,
        max_results: int = 100,
        archived: bool = False,
        updated_after: Optional[datetime] = None,
    ) -> list[ThreatFinding]:
        """Retrieve threat findings from GuardDuty.

        Args:
            severity_threshold: Minimum severity level to include
            finding_types: Specific finding types to filter
            resource_types: Resource types to filter
            max_results: Maximum number of findings to return
            archived: Include archived findings
            updated_after: Only findings updated after this time

        Returns:
            List of threat findings
        """
        detector_id = await self.get_detector_id()

        # Build finding criteria
        criteria = {"Criterion": {}}

        if not archived:
            criteria["Criterion"]["service.archived"] = {"Eq": ["false"]}

        if severity_threshold:
            min_severity = self._get_min_severity_value(severity_threshold)
            criteria["Criterion"]["severity"] = {"Gte": min_severity}

        if finding_types:
            criteria["Criterion"]["type"] = {"Eq": finding_types}

        if resource_types:
            criteria["Criterion"]["resource.resourceType"] = {"Eq": resource_types}

        if updated_after:
            criteria["Criterion"]["updatedAt"] = {"Gte": int(updated_after.timestamp() * 1000)}

        findings = []
        paginator = self.client.get_paginator("list_findings")

        try:
            # First, get finding IDs
            finding_ids = []
            async for page in self._async_paginate(
                paginator, DetectorId=detector_id, FindingCriteria=criteria, MaxResults=min(max_results, 50)
            ):
                finding_ids.extend(page.get("FindingIds", []))
                if len(finding_ids) >= max_results:
                    finding_ids = finding_ids[:max_results]
                    break

            # Then get finding details in batches
            for i in range(0, len(finding_ids), 50):
                batch_ids = finding_ids[i : i + 50]
                response = await asyncio.to_thread(self.client.get_findings, DetectorId=detector_id, FindingIds=batch_ids)

                for finding in response.get("Findings", []):
                    findings.append(ThreatFinding.from_guardduty_finding(finding))

        except ClientError as e:
            logger.error(f"Error retrieving findings: {e}")
            raise

        return findings

    async def archive_findings(self, finding_ids: list[str]) -> dict[str, Any]:
        """Archive GuardDuty findings.

        Args:
            finding_ids: List of finding IDs to archive

        Returns:
            Response from GuardDuty
        """
        detector_id = await self.get_detector_id()

        try:
            response = await asyncio.to_thread(self.client.archive_findings, DetectorId=detector_id, FindingIds=finding_ids)
            logger.info(f"Archived {len(finding_ids)} findings")
            return response
        except ClientError as e:
            logger.error(f"Error archiving findings: {e}")
            raise

    async def create_threat_intelligence_set(self, name: str, format: str, location: str, activate: bool = True) -> str:
        """Create a threat intelligence set.

        Args:
            name: Name of the threat intelligence set
            format: Format of the threat list (TXT, STIX, etc.)
            location: S3 location of the threat list
            activate: Whether to activate immediately

        Returns:
            Threat intelligence set ID
        """
        detector_id = await self.get_detector_id()

        try:
            response = await asyncio.to_thread(
                self.client.create_threat_intel_set,
                DetectorId=detector_id,
                Name=name,
                Format=format,
                Location=location,
                Activate=activate,
            )
            threat_intel_set_id = response["ThreatIntelSetId"]
            logger.info(f"Created threat intelligence set: {threat_intel_set_id}")
            return threat_intel_set_id
        except ClientError as e:
            logger.error(f"Error creating threat intelligence set: {e}")
            raise

    async def create_ip_set(self, name: str, format: str, location: str, activate: bool = True) -> str:
        """Create an IP set for allow/deny listing.

        Args:
            name: Name of the IP set
            format: Format of the IP list (TXT, STIX, etc.)
            location: S3 location of the IP list
            activate: Whether to activate immediately

        Returns:
            IP set ID
        """
        detector_id = await self.get_detector_id()

        try:
            response = await asyncio.to_thread(
                self.client.create_ip_set, DetectorId=detector_id, Name=name, Format=format, Location=location, Activate=activate
            )
            ip_set_id = response["IpSetId"]
            logger.info(f"Created IP set: {ip_set_id}")
            return ip_set_id
        except ClientError as e:
            logger.error(f"Error creating IP set: {e}")
            raise

    async def create_suppression_rule(self, name: str, description: str, finding_criteria: dict[str, Any]) -> dict[str, Any]:
        """Create a suppression rule to auto-archive certain findings.

        Args:
            name: Name of the suppression rule
            description: Description of the rule
            finding_criteria: Criteria for findings to suppress

        Returns:
            Response from GuardDuty
        """
        detector_id = await self.get_detector_id()

        filter_dict = {"Name": name, "Description": description, "FindingCriteria": finding_criteria}

        try:
            response = await asyncio.to_thread(self.client.create_filter, DetectorId=detector_id, **filter_dict)
            logger.info(f"Created suppression rule: {name}")
            return response
        except ClientError as e:
            logger.error(f"Error creating suppression rule: {e}")
            raise

    async def get_threat_statistics(self, time_range: timedelta = timedelta(days=7)) -> dict[str, Any]:
        """Get threat statistics for the specified time range.

        Args:
            time_range: Time range for statistics

        Returns:
            Dictionary with threat statistics
        """
        detector_id = await self.get_detector_id()
        updated_after = datetime.utcnow() - time_range

        criteria = {"Criterion": {"updatedAt": {"Gte": int(updated_after.timestamp() * 1000)}}}

        try:
            response = await asyncio.to_thread(self.client.get_findings_statistics, DetectorId=detector_id, FindingCriteria=criteria)

            statistics = response.get("FindingStatistics", {})
            return {
                "severity_counts": statistics.get("CountBySeverity", {}),
                "total_findings": sum(statistics.get("CountBySeverity", {}).values()),
                "time_range_days": time_range.days,
                "updated_after": updated_after.isoformat(),
            }
        except ClientError as e:
            logger.error(f"Error getting threat statistics: {e}")
            raise

    async def enable_s3_protection(self) -> dict[str, Any]:
        """Enable S3 protection for GuardDuty.

        Returns:
            Response from GuardDuty
        """
        detector_id = await self.get_detector_id()

        try:
            response = await asyncio.to_thread(
                self.client.update_detector, DetectorId=detector_id, DataSources={"S3Logs": {"Enable": True}}
            )
            logger.info("Enabled S3 protection for GuardDuty")
            return response
        except ClientError as e:
            logger.error(f"Error enabling S3 protection: {e}")
            raise

    async def enable_kubernetes_protection(self) -> dict[str, Any]:
        """Enable Kubernetes (EKS) protection for GuardDuty.

        Returns:
            Response from GuardDuty
        """
        detector_id = await self.get_detector_id()

        try:
            response = await asyncio.to_thread(
                self.client.update_detector,
                DetectorId=detector_id,
                DataSources={"Kubernetes": {"AuditLogs": {"Enable": True}}},
            )
            logger.info("Enabled Kubernetes protection for GuardDuty")
            return response
        except ClientError as e:
            logger.error(f"Error enabling Kubernetes protection: {e}")
            raise

    # Helper methods

    def _get_min_severity_value(self, severity: ThreatSeverity) -> float:
        """Get minimum numeric severity value for threshold."""
        severity_values = {ThreatSeverity.LOW: 1.0, ThreatSeverity.MEDIUM: 4.0, ThreatSeverity.HIGH: 7.0}
        return severity_values.get(severity, 1.0)

    async def _async_paginate(self, paginator, **kwargs):
        """Async wrapper for boto3 paginator."""
        page_iterator = paginator.paginate(**kwargs)
        for page in page_iterator:
            yield page


class ThreatDetector:
    """High-level threat detection and response orchestrator."""

    def __init__(self, guardduty_client: GuardDutyClient):
        """Initialize threat detector with GuardDuty client."""
        self.guardduty = guardduty_client
        self.response_handlers: dict[str, Any] = {}

    def register_response_handler(self, threat_type: str, handler):
        """Register a response handler for specific threat types.

        Args:
            threat_type: Type of threat to handle
            handler: Async function to handle the threat
        """
        self.response_handlers[threat_type] = handler

    async def monitor_threats(self, interval: int = 300, severity_threshold: ThreatSeverity = ThreatSeverity.MEDIUM):
        """Continuously monitor for threats and trigger responses.

        Args:
            interval: Check interval in seconds
            severity_threshold: Minimum severity to respond to
        """
        logger.info(f"Starting threat monitoring with {interval}s interval")

        last_check = datetime.utcnow()

        while True:
            try:
                # Get new findings since last check
                findings = await self.guardduty.get_findings(severity_threshold=severity_threshold, updated_after=last_check)

                # Process each finding
                for finding in findings:
                    await self._process_threat(finding)

                last_check = datetime.utcnow()

            except Exception as e:
                logger.error(f"Error in threat monitoring: {e}")

            await asyncio.sleep(interval)

    async def _process_threat(self, finding: ThreatFinding):
        """Process a single threat finding."""
        logger.info(f"Processing threat: {finding.type} - {finding.title}")

        # Find matching handler
        for threat_pattern, handler in self.response_handlers.items():
            if threat_pattern in finding.type:
                try:
                    await handler(finding)
                    logger.info(f"Successfully handled threat: {finding.id}")
                except Exception as e:
                    logger.error(f"Error handling threat {finding.id}: {e}")
                break

    async def generate_threat_report(self, time_range: timedelta = timedelta(days=7)) -> dict[str, Any]:
        """Generate a comprehensive threat report.

        Args:
            time_range: Time range for the report

        Returns:
            Threat report with statistics and top threats
        """
        # Get all findings in time range
        updated_after = datetime.utcnow() - time_range
        findings = await self.guardduty.get_findings(updated_after=updated_after, max_results=1000)

        # Get statistics
        stats = await self.guardduty.get_threat_statistics(time_range)

        # Analyze top threats
        threat_counts = {}
        affected_resources = {}
        severity_breakdown = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

        for finding in findings:
            # Count by threat type
            threat_counts[finding.type] = threat_counts.get(finding.type, 0) + 1

            # Track affected resources
            resource_key = f"{finding.resource_type}:{finding.resource_id}"
            affected_resources[resource_key] = affected_resources.get(resource_key, 0) + 1

            # Severity breakdown
            severity_breakdown[finding.threat_severity.value] += 1

        # Sort top threats
        top_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_resources = sorted(affected_resources.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "summary": stats,
            "total_findings": len(findings),
            "severity_breakdown": severity_breakdown,
            "top_threats": top_threats,
            "most_affected_resources": top_resources,
            "time_range": {"days": time_range.days, "start": updated_after.isoformat(), "end": datetime.utcnow().isoformat()},
        }