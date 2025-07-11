"""AWS Compliance scanning for various security frameworks.

This module provides automated compliance checking for:
- PCI DSS (Payment Card Industry Data Security Standard)
- HIPAA (Health Insurance Portability and Accountability Act)
- SOC2 (Service Organization Control 2)
- CIS (Center for Internet Security) Benchmarks
- Custom compliance frameworks
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Union

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""

    PCI_DSS = "PCI_DSS"
    HIPAA = "HIPAA"
    SOC2 = "SOC2"
    CIS = "CIS"
    ISO_27001 = "ISO_27001"
    NIST = "NIST"
    CUSTOM = "CUSTOM"


class ComplianceStatus(Enum):
    """Compliance check status."""

    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"
    WARNING = "WARNING"


class ControlSeverity(Enum):
    """Severity of compliance control."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class ComplianceControl:
    """Represents a compliance control check."""

    control_id: str
    title: str
    description: str
    framework: ComplianceFramework
    severity: ControlSeverity
    category: str
    automated: bool = True
    remediation_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    check_function: Optional[str] = None


@dataclass
class ComplianceResult:
    """Result of a compliance check."""

    control: ComplianceControl
    status: ComplianceStatus
    resource_arn: Optional[str] = None
    details: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.utcnow())
    remediation_available: bool = False
    auto_remediation_function: Optional[str] = None


@dataclass
class ComplianceReport:
    """Comprehensive compliance report."""

    framework: ComplianceFramework
    account_id: str
    region: str
    scan_date: datetime
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    not_applicable_controls: int
    error_controls: int
    compliance_score: float
    results: list[ComplianceResult]
    summary: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


class ComplianceScanner:
    """Scanner for automated compliance checks."""

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """Initialize compliance scanner.

        Args:
            region: AWS region
            profile: AWS profile to use for authentication
        """
        self.region = region or "us-east-1"
        self.profile = profile

        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.config_client = session.client("config", region_name=self.region)
        self.ec2_client = session.client("ec2", region_name=self.region)
        self.s3_client = session.client("s3")
        self.iam_client = session.client("iam")
        self.cloudtrail_client = session.client("cloudtrail", region_name=self.region)
        self.kms_client = session.client("kms", region_name=self.region)
        self.rds_client = session.client("rds", region_name=self.region)
        self.sts_client = session.client("sts")

        # Initialize control definitions
        self._init_compliance_controls()

    def _init_compliance_controls(self):
        """Initialize compliance control definitions."""
        self.controls = {
            ComplianceFramework.PCI_DSS: self._get_pci_dss_controls(),
            ComplianceFramework.HIPAA: self._get_hipaa_controls(),
            ComplianceFramework.SOC2: self._get_soc2_controls(),
            ComplianceFramework.CIS: self._get_cis_controls(),
        }

    def _get_pci_dss_controls(self) -> list[ComplianceControl]:
        """Get PCI DSS compliance controls."""
        return [
            ComplianceControl(
                control_id="PCI-DSS-1.1",
                title="Firewall Configuration Standards",
                description="Ensure firewalls are configured to protect cardholder data",
                framework=ComplianceFramework.PCI_DSS,
                severity=ControlSeverity.CRITICAL,
                category="Network Security",
                check_function="check_firewall_configuration",
                remediation_steps=[
                    "Review security group rules",
                    "Remove overly permissive rules (0.0.0.0/0)",
                    "Implement least privilege access",
                ],
            ),
            ComplianceControl(
                control_id="PCI-DSS-2.1",
                title="Default Passwords Changed",
                description="Change vendor-supplied defaults before installing on network",
                framework=ComplianceFramework.PCI_DSS,
                severity=ControlSeverity.HIGH,
                category="Access Control",
                check_function="check_default_passwords",
            ),
            ComplianceControl(
                control_id="PCI-DSS-3.4",
                title="Encryption of Cardholder Data",
                description="Render PAN unreadable anywhere it is stored",
                framework=ComplianceFramework.PCI_DSS,
                severity=ControlSeverity.CRITICAL,
                category="Data Protection",
                check_function="check_data_encryption",
            ),
            ComplianceControl(
                control_id="PCI-DSS-8.1",
                title="Unique User IDs",
                description="Assign unique ID to each person with computer access",
                framework=ComplianceFramework.PCI_DSS,
                severity=ControlSeverity.HIGH,
                category="Access Control",
                check_function="check_unique_user_ids",
            ),
            ComplianceControl(
                control_id="PCI-DSS-10.1",
                title="Audit Trail Implementation",
                description="Implement audit trails to link access to individual users",
                framework=ComplianceFramework.PCI_DSS,
                severity=ControlSeverity.HIGH,
                category="Logging and Monitoring",
                check_function="check_audit_trails",
            ),
        ]

    def _get_hipaa_controls(self) -> list[ComplianceControl]:
        """Get HIPAA compliance controls."""
        return [
            ComplianceControl(
                control_id="HIPAA-164.308(a)(1)",
                title="Security Management Process",
                description="Implement policies and procedures to prevent, detect, contain, and correct security violations",
                framework=ComplianceFramework.HIPAA,
                severity=ControlSeverity.HIGH,
                category="Administrative Safeguards",
                check_function="check_security_management",
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(a)(1)",
                title="Access Control",
                description="Implement technical policies for electronic information systems",
                framework=ComplianceFramework.HIPAA,
                severity=ControlSeverity.CRITICAL,
                category="Technical Safeguards",
                check_function="check_access_control",
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(a)(2)(iv)",
                title="Encryption and Decryption",
                description="Implement mechanism to encrypt and decrypt ePHI",
                framework=ComplianceFramework.HIPAA,
                severity=ControlSeverity.CRITICAL,
                category="Technical Safeguards",
                check_function="check_encryption_at_rest",
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(b)",
                title="Audit Controls",
                description="Implement hardware, software, and procedural mechanisms for audit controls",
                framework=ComplianceFramework.HIPAA,
                severity=ControlSeverity.HIGH,
                category="Technical Safeguards",
                check_function="check_audit_controls",
            ),
        ]

    def _get_soc2_controls(self) -> list[ComplianceControl]:
        """Get SOC2 compliance controls."""
        return [
            ComplianceControl(
                control_id="SOC2-CC6.1",
                title="Logical Access Controls",
                description="Logical access to systems is restricted through access control software",
                framework=ComplianceFramework.SOC2,
                severity=ControlSeverity.HIGH,
                category="Security",
                check_function="check_logical_access",
            ),
            ComplianceControl(
                control_id="SOC2-CC6.7",
                title="Transmission Security",
                description="Data transmitted over public networks is encrypted",
                framework=ComplianceFramework.SOC2,
                severity=ControlSeverity.HIGH,
                category="Security",
                check_function="check_transmission_security",
            ),
            ComplianceControl(
                control_id="SOC2-CC7.2",
                title="System Monitoring",
                description="System performance is monitored to identify anomalies",
                framework=ComplianceFramework.SOC2,
                severity=ControlSeverity.MEDIUM,
                category="Availability",
                check_function="check_system_monitoring",
            ),
        ]

    def _get_cis_controls(self) -> list[ComplianceControl]:
        """Get CIS benchmark controls."""
        return [
            ComplianceControl(
                control_id="CIS-1.1",
                title="Root Account Usage",
                description="Avoid the use of root account",
                framework=ComplianceFramework.CIS,
                severity=ControlSeverity.CRITICAL,
                category="Identity and Access Management",
                check_function="check_root_account_usage",
            ),
            ComplianceControl(
                control_id="CIS-2.1",
                title="CloudTrail Enabled",
                description="Ensure CloudTrail is enabled in all regions",
                framework=ComplianceFramework.CIS,
                severity=ControlSeverity.HIGH,
                category="Logging",
                check_function="check_cloudtrail_enabled",
            ),
            ComplianceControl(
                control_id="CIS-2.7",
                title="CloudTrail Log Encryption",
                description="Ensure CloudTrail logs are encrypted at rest",
                framework=ComplianceFramework.CIS,
                severity=ControlSeverity.MEDIUM,
                category="Logging",
                check_function="check_cloudtrail_encryption",
            ),
            ComplianceControl(
                control_id="CIS-3.1",
                title="Log Metric Filters",
                description="Ensure log metric filter for unauthorized API calls",
                framework=ComplianceFramework.CIS,
                severity=ControlSeverity.MEDIUM,
                category="Monitoring",
                check_function="check_log_metric_filters",
            ),
        ]

    async def scan_compliance(
        self, framework: ComplianceFramework, resources: Optional[list[str]] = None, auto_remediate: bool = False
    ) -> ComplianceReport:
        """Perform compliance scan for specified framework.

        Args:
            framework: Compliance framework to scan
            resources: Specific resources to scan (None for all)
            auto_remediate: Whether to auto-remediate findings

        Returns:
            Comprehensive compliance report
        """
        logger.info(f"Starting {framework.value} compliance scan")

        # Get account info
        account_info = await asyncio.to_thread(self.sts_client.get_caller_identity)
        account_id = account_info["Account"]

        # Get controls for framework
        controls = self.controls.get(framework, [])
        if not controls:
            raise ValueError(f"Unsupported framework: {framework}")

        # Run compliance checks
        results = []
        for control in controls:
            try:
                result = await self._check_control(control, resources)
                results.append(result)

                # Auto-remediate if enabled and available
                if auto_remediate and result.status == ComplianceStatus.NON_COMPLIANT and result.remediation_available:
                    await self._auto_remediate(result)

            except Exception as e:
                logger.error(f"Error checking control {control.control_id}: {e}")
                results.append(
                    ComplianceResult(
                        control=control,
                        status=ComplianceStatus.ERROR,
                        details=str(e),
                    )
                )

        # Generate report
        report = self._generate_report(framework, account_id, results)

        logger.info(f"Compliance scan completed. Score: {report.compliance_score:.1f}%")
        return report

    async def _check_control(self, control: ComplianceControl, resources: Optional[list[str]] = None) -> ComplianceResult:
        """Check a single compliance control."""
        check_function = getattr(self, control.check_function, None)
        if not check_function:
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.ERROR,
                details=f"Check function {control.check_function} not implemented",
            )

        return await check_function(control, resources)

    # Compliance check implementations

    async def check_firewall_configuration(self, control: ComplianceControl, resources: Optional[list[str]] = None) -> ComplianceResult:
        """Check firewall (security group) configuration."""
        try:
            # Get all security groups
            response = await asyncio.to_thread(self.ec2_client.describe_security_groups)
            security_groups = response["SecurityGroups"]

            non_compliant_sgs = []
            for sg in security_groups:
                # Check for overly permissive rules
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            # Check if it's not port 80 or 443 (common exceptions)
                            from_port = rule.get("FromPort", 0)
                            if from_port not in [80, 443]:
                                non_compliant_sgs.append(
                                    {
                                        "SecurityGroupId": sg["GroupId"],
                                        "Rule": f"Port {from_port} open to 0.0.0.0/0",
                                    }
                                )

            if non_compliant_sgs:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details=f"Found {len(non_compliant_sgs)} security groups with overly permissive rules",
                    evidence={"non_compliant_security_groups": non_compliant_sgs},
                    remediation_available=True,
                    auto_remediation_function="remediate_security_groups",
                )

            return ComplianceResult(
                control=control,
                status=ComplianceStatus.COMPLIANT,
                details="All security groups follow least privilege principle",
            )

        except ClientError as e:
            return ComplianceResult(control=control, status=ComplianceStatus.ERROR, details=str(e))

    async def check_data_encryption(self, control: ComplianceControl, resources: Optional[list[str]] = None) -> ComplianceResult:
        """Check data encryption at rest."""
        try:
            non_compliant_resources = []

            # Check S3 bucket encryption
            s3_response = await asyncio.to_thread(self.s3_client.list_buckets)
            for bucket in s3_response.get("Buckets", []):
                try:
                    encryption = await asyncio.to_thread(self.s3_client.get_bucket_encryption, Bucket=bucket["Name"])
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                        non_compliant_resources.append({"Type": "S3Bucket", "Name": bucket["Name"], "Issue": "No encryption"})

            # Check RDS instance encryption
            rds_response = await asyncio.to_thread(self.rds_client.describe_db_instances)
            for db in rds_response.get("DBInstances", []):
                if not db.get("StorageEncrypted", False):
                    non_compliant_resources.append(
                        {"Type": "RDSInstance", "Name": db["DBInstanceIdentifier"], "Issue": "Storage not encrypted"}
                    )

            # Check EBS volume encryption
            ec2_response = await asyncio.to_thread(self.ec2_client.describe_volumes)
            for volume in ec2_response.get("Volumes", []):
                if not volume.get("Encrypted", False):
                    non_compliant_resources.append({"Type": "EBSVolume", "Id": volume["VolumeId"], "Issue": "Not encrypted"})

            if non_compliant_resources:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details=f"Found {len(non_compliant_resources)} unencrypted resources",
                    evidence={"unencrypted_resources": non_compliant_resources},
                )

            return ComplianceResult(control=control, status=ComplianceStatus.COMPLIANT, details="All data at rest is encrypted")

        except ClientError as e:
            return ComplianceResult(control=control, status=ComplianceStatus.ERROR, details=str(e))

    async def check_audit_trails(self, control: ComplianceControl, resources: Optional[list[str]] = None) -> ComplianceResult:
        """Check audit trail implementation."""
        try:
            # Check CloudTrail configuration
            trails = await asyncio.to_thread(self.cloudtrail_client.describe_trails)
            
            if not trails.get("trailList"):
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details="No CloudTrail trails configured",
                    remediation_available=True,
                    auto_remediation_function="create_cloudtrail",
                )

            # Check if at least one trail is multi-region and logging
            compliant_trail_found = False
            for trail in trails["trailList"]:
                trail_status = await asyncio.to_thread(self.cloudtrail_client.get_trail_status, Name=trail["TrailARN"])
                
                if trail.get("IsMultiRegionTrail") and trail_status.get("IsLogging"):
                    compliant_trail_found = True
                    break

            if not compliant_trail_found:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details="No multi-region trail with logging enabled found",
                    remediation_available=True,
                )

            # Check S3 bucket access logging
            s3_buckets = await asyncio.to_thread(self.s3_client.list_buckets)
            buckets_without_logging = []
            
            for bucket in s3_buckets.get("Buckets", []):
                try:
                    logging_config = await asyncio.to_thread(self.s3_client.get_bucket_logging, Bucket=bucket["Name"])
                    if not logging_config.get("LoggingEnabled"):
                        buckets_without_logging.append(bucket["Name"])
                except ClientError:
                    buckets_without_logging.append(bucket["Name"])

            if buckets_without_logging:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.WARNING,
                    details=f"CloudTrail configured but {len(buckets_without_logging)} S3 buckets lack access logging",
                    evidence={"buckets_without_logging": buckets_without_logging},
                )

            return ComplianceResult(
                control=control,
                status=ComplianceStatus.COMPLIANT,
                details="Comprehensive audit trails are implemented",
            )

        except ClientError as e:
            return ComplianceResult(control=control, status=ComplianceStatus.ERROR, details=str(e))

    async def check_access_control(self, control: ComplianceControl, resources: Optional[list[str]] = None) -> ComplianceResult:
        """Check access control implementation."""
        try:
            issues = []

            # Check for MFA on root account
            account_summary = await asyncio.to_thread(self.iam_client.get_account_summary)
            if account_summary["SummaryMap"].get("AccountMFAEnabled", 0) == 0:
                issues.append("Root account does not have MFA enabled")

            # Check password policy
            try:
                password_policy = await asyncio.to_thread(self.iam_client.get_account_password_policy)
                policy = password_policy["PasswordPolicy"]
                
                # Check minimum requirements
                if policy.get("MinimumPasswordLength", 0) < 14:
                    issues.append("Password minimum length is less than 14 characters")
                if not policy.get("RequireUppercaseCharacters", False):
                    issues.append("Password policy does not require uppercase characters")
                if not policy.get("RequireLowercaseCharacters", False):
                    issues.append("Password policy does not require lowercase characters")
                if not policy.get("RequireNumbers", False):
                    issues.append("Password policy does not require numbers")
                if not policy.get("RequireSymbols", False):
                    issues.append("Password policy does not require symbols")
                if policy.get("MaxPasswordAge", 0) == 0 or policy.get("MaxPasswordAge", 0) > 90:
                    issues.append("Password expiration is not set or exceeds 90 days")

            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    issues.append("No password policy configured")

            # Check for users without MFA
            users = await asyncio.to_thread(self.iam_client.list_users)
            users_without_mfa = []
            
            for user in users.get("Users", []):
                mfa_devices = await asyncio.to_thread(self.iam_client.list_mfa_devices, UserName=user["UserName"])
                if not mfa_devices.get("MFADevices"):
                    # Check if user has console access
                    try:
                        await asyncio.to_thread(self.iam_client.get_login_profile, UserName=user["UserName"])
                        users_without_mfa.append(user["UserName"])
                    except ClientError:
                        # No console access, MFA not required
                        pass

            if users_without_mfa:
                issues.append(f"{len(users_without_mfa)} users with console access lack MFA")

            if issues:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details=f"Found {len(issues)} access control issues",
                    evidence={"issues": issues, "users_without_mfa": users_without_mfa},
                    remediation_available=True,
                    auto_remediation_function="improve_access_control",
                )

            return ComplianceResult(
                control=control,
                status=ComplianceStatus.COMPLIANT,
                details="Access control policies meet requirements",
            )

        except ClientError as e:
            return ComplianceResult(control=control, status=ComplianceStatus.ERROR, details=str(e))

    async def check_root_account_usage(self, control: ComplianceControl, resources: Optional[list[str]] = None) -> ComplianceResult:
        """Check root account usage."""
        try:
            # Get credential report
            await asyncio.to_thread(self.iam_client.generate_credential_report)
            
            # Wait for report generation
            await asyncio.sleep(2)
            
            report_response = await asyncio.to_thread(self.iam_client.get_credential_report)
            report_content = report_response["Content"].decode("utf-8")
            
            # Parse CSV report
            import csv
            import io
            
            reader = csv.DictReader(io.StringIO(report_content))
            root_user = None
            
            for row in reader:
                if row["user"] == "<root_account>":
                    root_user = row
                    break
            
            if not root_user:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.ERROR,
                    details="Could not find root account in credential report",
                )
            
            issues = []
            
            # Check last use of root account
            if root_user.get("password_last_used") and root_user["password_last_used"] != "N/A":
                last_used = datetime.strptime(root_user["password_last_used"], "%Y-%m-%dT%H:%M:%S+00:00")
                days_since_use = (datetime.utcnow() - last_used).days
                
                if days_since_use < 90:
                    issues.append(f"Root account was used {days_since_use} days ago")
            
            # Check for access keys
            if root_user.get("access_key_1_active") == "true":
                issues.append("Root account has active access key 1")
            if root_user.get("access_key_2_active") == "true":
                issues.append("Root account has active access key 2")
            
            # Check MFA
            if root_user.get("mfa_active") != "true":
                issues.append("Root account does not have MFA enabled")
            
            if issues:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details=f"Root account has {len(issues)} issues",
                    evidence={"issues": issues},
                    remediation_available=True,
                )
            
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.COMPLIANT,
                details="Root account follows best practices",
            )
            
        except ClientError as e:
            return ComplianceResult(control=control, status=ComplianceStatus.ERROR, details=str(e))

    async def check_cloudtrail_enabled(self, control: ComplianceControl, resources: Optional[list[str]] = None) -> ComplianceResult:
        """Check if CloudTrail is enabled in all regions."""
        try:
            trails = await asyncio.to_thread(self.cloudtrail_client.describe_trails)
            
            if not trails.get("trailList"):
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details="No CloudTrail trails configured",
                    remediation_available=True,
                    auto_remediation_function="create_cloudtrail",
                )
            
            # Check for multi-region trail
            multi_region_trail = None
            for trail in trails["trailList"]:
                if trail.get("IsMultiRegionTrail"):
                    multi_region_trail = trail
                    break
            
            if not multi_region_trail:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details="No multi-region CloudTrail trail found",
                    remediation_available=True,
                )
            
            # Check if trail is logging
            trail_status = await asyncio.to_thread(
                self.cloudtrail_client.get_trail_status,
                Name=multi_region_trail["TrailARN"]
            )
            
            if not trail_status.get("IsLogging"):
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details="Multi-region trail exists but is not logging",
                    remediation_available=True,
                )
            
            # Check event selectors
            event_selectors = await asyncio.to_thread(
                self.cloudtrail_client.get_event_selectors,
                TrailName=multi_region_trail["TrailARN"]
            )
            
            has_all_s3_events = False
            has_all_lambda_events = False
            
            for selector in event_selectors.get("EventSelectors", []):
                if selector.get("IncludeManagementEvents") and selector.get("ReadWriteType") == "All":
                    if any(resource["Type"] == "AWS::S3::Object" and resource["Values"] == ["arn:aws:s3:::*/*"] 
                          for resource in selector.get("DataResources", [])):
                        has_all_s3_events = True
                    if any(resource["Type"] == "AWS::Lambda::Function" and resource["Values"] == ["arn:aws:lambda:*:*:function/*"] 
                          for resource in selector.get("DataResources", [])):
                        has_all_lambda_events = True
            
            if not has_all_s3_events or not has_all_lambda_events:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.WARNING,
                    details="CloudTrail enabled but not capturing all S3/Lambda events",
                    evidence={
                        "captures_all_s3_events": has_all_s3_events,
                        "captures_all_lambda_events": has_all_lambda_events
                    },
                )
            
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.COMPLIANT,
                details="CloudTrail is properly configured in all regions",
                evidence={"trail_name": multi_region_trail["Name"]},
            )
            
        except ClientError as e:
            return ComplianceResult(control=control, status=ComplianceStatus.ERROR, details=str(e))

    async def check_cloudtrail_encryption(self, control: ComplianceControl, resources: Optional[list[str]] = None) -> ComplianceResult:
        """Check CloudTrail log encryption."""
        try:
            trails = await asyncio.to_thread(self.cloudtrail_client.describe_trails)
            
            if not trails.get("trailList"):
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NOT_APPLICABLE,
                    details="No CloudTrail trails to check",
                )
            
            unencrypted_trails = []
            for trail in trails["trailList"]:
                if not trail.get("KmsKeyId"):
                    unencrypted_trails.append(trail["Name"])
            
            if unencrypted_trails:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details=f"{len(unencrypted_trails)} trails are not encrypted with KMS",
                    evidence={"unencrypted_trails": unencrypted_trails},
                    remediation_available=True,
                )
            
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.COMPLIANT,
                details="All CloudTrail trails are encrypted with KMS",
            )
            
        except ClientError as e:
            return ComplianceResult(control=control, status=ComplianceStatus.ERROR, details=str(e))

    # Auto-remediation functions

    async def _auto_remediate(self, result: ComplianceResult):
        """Execute auto-remediation for a non-compliant finding."""
        if not result.auto_remediation_function:
            return
        
        remediation_function = getattr(self, result.auto_remediation_function, None)
        if remediation_function:
            try:
                await remediation_function(result)
                logger.info(f"Auto-remediated control {result.control.control_id}")
            except Exception as e:
                logger.error(f"Failed to auto-remediate {result.control.control_id}: {e}")

    async def remediate_security_groups(self, result: ComplianceResult):
        """Remediate overly permissive security groups."""
        for sg_info in result.evidence.get("non_compliant_security_groups", []):
            sg_id = sg_info["SecurityGroupId"]
            
            # Get current rules
            response = await asyncio.to_thread(
                self.ec2_client.describe_security_groups,
                GroupIds=[sg_id]
            )
            
            sg = response["SecurityGroups"][0]
            
            # Remove overly permissive rules
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        from_port = rule.get("FromPort", 0)
                        if from_port not in [80, 443]:  # Keep common web ports
                            await asyncio.to_thread(
                                self.ec2_client.revoke_security_group_ingress,
                                GroupId=sg_id,
                                IpPermissions=[{
                                    "IpProtocol": rule["IpProtocol"],
                                    "FromPort": from_port,
                                    "ToPort": rule.get("ToPort", from_port),
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                                }]
                            )
                            logger.info(f"Removed 0.0.0.0/0 rule from {sg_id} port {from_port}")

    async def create_cloudtrail(self, result: ComplianceResult):
        """Create a multi-region CloudTrail."""
        trail_name = "aws-mcp-compliance-trail"
        bucket_name = f"aws-mcp-cloudtrail-{self.region}-{await self._get_account_id()}"
        
        # Create S3 bucket for CloudTrail
        try:
            if self.region == "us-east-1":
                await asyncio.to_thread(self.s3_client.create_bucket, Bucket=bucket_name)
            else:
                await asyncio.to_thread(
                    self.s3_client.create_bucket,
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": self.region}
                )
            
            # Set bucket policy for CloudTrail
            bucket_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AWSCloudTrailAclCheck",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket_name}"
                    },
                    {
                        "Sid": "AWSCloudTrailWrite",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/*",
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-acl": "bucket-owner-full-control"
                            }
                        }
                    }
                ]
            }
            
            await asyncio.to_thread(
                self.s3_client.put_bucket_policy,
                Bucket=bucket_name,
                Policy=json.dumps(bucket_policy)
            )
            
            # Create CloudTrail
            await asyncio.to_thread(
                self.cloudtrail_client.create_trail,
                Name=trail_name,
                S3BucketName=bucket_name,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True
            )
            
            # Start logging
            await asyncio.to_thread(
                self.cloudtrail_client.start_logging,
                Name=trail_name
            )
            
            logger.info(f"Created multi-region CloudTrail: {trail_name}")
            
        except ClientError as e:
            logger.error(f"Failed to create CloudTrail: {e}")
            raise

    async def improve_access_control(self, result: ComplianceResult):
        """Improve access control policies."""
        # Update password policy
        try:
            await asyncio.to_thread(
                self.iam_client.update_account_password_policy,
                MinimumPasswordLength=14,
                RequireSymbols=True,
                RequireNumbers=True,
                RequireUppercaseCharacters=True,
                RequireLowercaseCharacters=True,
                AllowUsersToChangePassword=True,
                MaxPasswordAge=90,
                PasswordReusePrevention=24
            )
            logger.info("Updated password policy to meet compliance requirements")
        except ClientError as e:
            logger.error(f"Failed to update password policy: {e}")

    # Report generation

    def _generate_report(self, framework: ComplianceFramework, account_id: str, results: list[ComplianceResult]) -> ComplianceReport:
        """Generate compliance report from results."""
        # Count results by status
        status_counts = {
            ComplianceStatus.COMPLIANT: 0,
            ComplianceStatus.NON_COMPLIANT: 0,
            ComplianceStatus.NOT_APPLICABLE: 0,
            ComplianceStatus.ERROR: 0,
            ComplianceStatus.WARNING: 0,
        }
        
        for result in results:
            status_counts[result.status] += 1
        
        # Calculate compliance score
        total_applicable = len(results) - status_counts[ComplianceStatus.NOT_APPLICABLE] - status_counts[ComplianceStatus.ERROR]
        compliant_count = status_counts[ComplianceStatus.COMPLIANT]
        compliance_score = (compliant_count / total_applicable * 100) if total_applicable > 0 else 0
        
        # Generate summary by category
        category_summary = {}
        for result in results:
            category = result.control.category
            if category not in category_summary:
                category_summary[category] = {
                    "total": 0,
                    "compliant": 0,
                    "non_compliant": 0,
                    "warnings": 0,
                }
            
            category_summary[category]["total"] += 1
            if result.status == ComplianceStatus.COMPLIANT:
                category_summary[category]["compliant"] += 1
            elif result.status == ComplianceStatus.NON_COMPLIANT:
                category_summary[category]["non_compliant"] += 1
            elif result.status == ComplianceStatus.WARNING:
                category_summary[category]["warnings"] += 1
        
        # Generate recommendations
        recommendations = []
        critical_findings = [r for r in results if r.status == ComplianceStatus.NON_COMPLIANT and r.control.severity == ControlSeverity.CRITICAL]
        
        if critical_findings:
            recommendations.append(f"Address {len(critical_findings)} critical non-compliant controls immediately")
        
        if status_counts[ComplianceStatus.NON_COMPLIANT] > 0:
            recommendations.append("Implement auto-remediation for common compliance violations")
        
        if compliance_score < 80:
            recommendations.append("Schedule regular compliance scans to track improvement")
        
        return ComplianceReport(
            framework=framework,
            account_id=account_id,
            region=self.region,
            scan_date=datetime.utcnow(),
            total_controls=len(results),
            compliant_controls=status_counts[ComplianceStatus.COMPLIANT],
            non_compliant_controls=status_counts[ComplianceStatus.NON_COMPLIANT],
            not_applicable_controls=status_counts[ComplianceStatus.NOT_APPLICABLE],
            error_controls=status_counts[ComplianceStatus.ERROR],
            compliance_score=compliance_score,
            results=results,
            summary={"by_category": category_summary, "by_status": status_counts},
            recommendations=recommendations,
        )

    async def _get_account_id(self) -> str:
        """Get current AWS account ID."""
        response = await asyncio.to_thread(self.sts_client.get_caller_identity)
        return response["Account"]

    async def export_report(self, report: ComplianceReport, format: str = "json") -> str:
        """Export compliance report in various formats.

        Args:
            report: Compliance report to export
            format: Export format (json, csv, html)

        Returns:
            Exported report as string
        """
        if format == "json":
            return json.dumps(
                {
                    "framework": report.framework.value,
                    "account_id": report.account_id,
                    "region": report.region,
                    "scan_date": report.scan_date.isoformat(),
                    "compliance_score": report.compliance_score,
                    "summary": report.summary,
                    "recommendations": report.recommendations,
                    "results": [
                        {
                            "control_id": r.control.control_id,
                            "title": r.control.title,
                            "status": r.status.value,
                            "severity": r.control.severity.value,
                            "details": r.details,
                            "evidence": r.evidence,
                        }
                        for r in report.results
                    ],
                },
                indent=2,
            )
        
        elif format == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                "Control ID",
                "Title",
                "Category",
                "Severity",
                "Status",
                "Details",
                "Remediation Available"
            ])
            
            # Write results
            for result in report.results:
                writer.writerow([
                    result.control.control_id,
                    result.control.title,
                    result.control.category,
                    result.control.severity.value,
                    result.status.value,
                    result.details,
                    "Yes" if result.remediation_available else "No"
                ])
            
            return output.getvalue()
        
        elif format == "html":
            html_template = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>{report.framework.value} Compliance Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ background-color: #f0f0f0; padding: 20px; }}
                    .score {{ font-size: 48px; font-weight: bold; color: {'#4CAF50' if report.compliance_score >= 80 else '#FF9800' if report.compliance_score >= 60 else '#F44336'}; }}
                    table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #4CAF50; color: white; }}
                    .compliant {{ color: #4CAF50; }}
                    .non-compliant {{ color: #F44336; }}
                    .warning {{ color: #FF9800; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>{report.framework.value} Compliance Report</h1>
                    <p>Account: {report.account_id} | Region: {report.region}</p>
                    <p>Scan Date: {report.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    <div class="score">{report.compliance_score:.1f}%</div>
                </div>
                
                <h2>Summary</h2>
                <ul>
                    <li>Total Controls: {report.total_controls}</li>
                    <li class="compliant">Compliant: {report.compliant_controls}</li>
                    <li class="non-compliant">Non-Compliant: {report.non_compliant_controls}</li>
                    <li>Not Applicable: {report.not_applicable_controls}</li>
                    <li>Errors: {report.error_controls}</li>
                </ul>
                
                <h2>Recommendations</h2>
                <ul>
                    {"".join(f"<li>{rec}</li>" for rec in report.recommendations)}
                </ul>
                
                <h2>Detailed Results</h2>
                <table>
                    <tr>
                        <th>Control ID</th>
                        <th>Title</th>
                        <th>Category</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Details</th>
                    </tr>
                    {"".join(f'''
                    <tr>
                        <td>{r.control.control_id}</td>
                        <td>{r.control.title}</td>
                        <td>{r.control.category}</td>
                        <td>{r.control.severity.value}</td>
                        <td class="{r.status.value.lower().replace('_', '-')}">{r.status.value}</td>
                        <td>{r.details}</td>
                    </tr>
                    ''' for r in report.results)}
                </table>
            </body>
            </html>
            """
            return html_template
        
        else:
            raise ValueError(f"Unsupported format: {format}")

    async def schedule_compliance_scan(
        self,
        framework: ComplianceFramework,
        schedule: str,
        auto_remediate: bool = False,
        notification_email: Optional[str] = None
    ) -> dict[str, Any]:
        """Schedule regular compliance scans.

        Args:
            framework: Compliance framework to scan
            schedule: Cron expression for scheduling
            auto_remediate: Whether to auto-remediate findings
            notification_email: Email for scan notifications

        Returns:
            Schedule configuration
        """
        # This would integrate with AWS EventBridge or similar scheduling service
        # For now, return configuration that could be used by a scheduler
        return {
            "framework": framework.value,
            "schedule": schedule,
            "auto_remediate": auto_remediate,
            "notification_email": notification_email,
            "next_run": "Scheduled scanning requires external scheduler integration",
        }