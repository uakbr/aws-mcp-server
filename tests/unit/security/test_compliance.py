"""Unit tests for Compliance Scanner."""

import asyncio
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_mcp_server.security.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceReport,
    ComplianceResult,
    ComplianceScanner,
    ComplianceStatus,
    ControlSeverity,
)


@pytest.fixture
def mock_boto3_session():
    """Mock boto3 session."""
    with patch("boto3.Session") as mock:
        yield mock


@pytest.fixture
def compliance_scanner(mock_boto3_session):
    """Create a ComplianceScanner with mocked AWS clients."""
    mock_session = MagicMock()
    mock_boto3_session.return_value = mock_session
    
    # Create mocks for all clients
    mock_config = MagicMock()
    mock_ec2 = MagicMock()
    mock_s3 = MagicMock()
    mock_iam = MagicMock()
    mock_cloudtrail = MagicMock()
    mock_kms = MagicMock()
    mock_rds = MagicMock()
    mock_sts = MagicMock()
    
    def mock_client(service_name, **kwargs):
        clients = {
            "config": mock_config,
            "ec2": mock_ec2,
            "s3": mock_s3,
            "iam": mock_iam,
            "cloudtrail": mock_cloudtrail,
            "kms": mock_kms,
            "rds": mock_rds,
            "sts": mock_sts,
        }
        return clients.get(service_name, MagicMock())
    
    mock_session.client.side_effect = mock_client
    
    scanner = ComplianceScanner(region="us-east-1")
    scanner.config_client = mock_config
    scanner.ec2_client = mock_ec2
    scanner.s3_client = mock_s3
    scanner.iam_client = mock_iam
    scanner.cloudtrail_client = mock_cloudtrail
    scanner.kms_client = mock_kms
    scanner.rds_client = mock_rds
    scanner.sts_client = mock_sts
    
    return scanner


class TestComplianceControl:
    """Test ComplianceControl dataclass."""
    
    def test_control_creation(self):
        """Test creating a compliance control."""
        control = ComplianceControl(
            control_id="TEST-1.1",
            title="Test Control",
            description="Test control description",
            framework=ComplianceFramework.PCI_DSS,
            severity=ControlSeverity.HIGH,
            category="Security",
            automated=True,
            check_function="check_test_control"
        )
        
        assert control.control_id == "TEST-1.1"
        assert control.framework == ComplianceFramework.PCI_DSS
        assert control.severity == ControlSeverity.HIGH
        assert control.automated is True


class TestComplianceScanner:
    """Test ComplianceScanner."""
    
    def test_init_compliance_controls(self, compliance_scanner):
        """Test initialization of compliance controls."""
        # Verify controls are loaded for each framework
        assert ComplianceFramework.PCI_DSS in compliance_scanner.controls
        assert ComplianceFramework.HIPAA in compliance_scanner.controls
        assert ComplianceFramework.SOC2 in compliance_scanner.controls
        assert ComplianceFramework.CIS in compliance_scanner.controls
        
        # Verify some controls exist
        pci_controls = compliance_scanner.controls[ComplianceFramework.PCI_DSS]
        assert len(pci_controls) > 0
        assert all(c.framework == ComplianceFramework.PCI_DSS for c in pci_controls)
    
    @pytest.mark.asyncio
    async def test_scan_compliance(self, compliance_scanner):
        """Test running a compliance scan."""
        # Mock STS for account ID
        compliance_scanner.sts_client.get_caller_identity = MagicMock(
            return_value={"Account": "123456789012"}
        )
        
        # Mock check methods to return compliant results
        async def mock_check_firewall(control, resources):
            return ComplianceResult(
                control=control,
                status=ComplianceStatus.COMPLIANT,
                details="All security groups are properly configured"
            )
        
        compliance_scanner.check_firewall_configuration = mock_check_firewall
        
        with patch("asyncio.to_thread", new=AsyncMock(
            return_value={"Account": "123456789012"}
        )):
            report = await compliance_scanner.scan_compliance(
                framework=ComplianceFramework.PCI_DSS,
                auto_remediate=False
            )
        
        assert isinstance(report, ComplianceReport)
        assert report.framework == ComplianceFramework.PCI_DSS
        assert report.account_id == "123456789012"
        assert report.total_controls > 0
    
    @pytest.mark.asyncio
    async def test_check_firewall_configuration(self, compliance_scanner):
        """Test firewall configuration check."""
        # Mock EC2 describe_security_groups
        mock_response = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-safe",
                    "IpPermissions": [{
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
                    }]
                },
                {
                    "GroupId": "sg-unsafe",
                    "IpPermissions": [{
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }]
                }
            ]
        }
        
        control = ComplianceControl(
            control_id="TEST-FW",
            title="Test Firewall",
            description="Test",
            framework=ComplianceFramework.PCI_DSS,
            severity=ControlSeverity.HIGH,
            category="Network"
        )
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            result = await compliance_scanner.check_firewall_configuration(control, None)
        
        assert result.status == ComplianceStatus.NON_COMPLIANT
        assert "1 security groups with overly permissive rules" in result.details
        assert result.remediation_available is True
        
        # Check evidence
        non_compliant_sgs = result.evidence.get("non_compliant_security_groups", [])
        assert len(non_compliant_sgs) == 1
        assert non_compliant_sgs[0]["SecurityGroupId"] == "sg-unsafe"
    
    @pytest.mark.asyncio
    async def test_check_data_encryption(self, compliance_scanner):
        """Test data encryption check."""
        # Mock S3 list_buckets
        s3_buckets = {"Buckets": [{"Name": "bucket1"}, {"Name": "bucket2"}]}
        
        # Mock RDS instances
        rds_instances = {
            "DBInstances": [
                {"DBInstanceIdentifier": "db1", "StorageEncrypted": True},
                {"DBInstanceIdentifier": "db2", "StorageEncrypted": False}
            ]
        }
        
        # Mock EBS volumes
        ebs_volumes = {
            "Volumes": [
                {"VolumeId": "vol-1", "Encrypted": True},
                {"VolumeId": "vol-2", "Encrypted": False}
            ]
        }
        
        control = ComplianceControl(
            control_id="TEST-ENC",
            title="Test Encryption",
            description="Test",
            framework=ComplianceFramework.PCI_DSS,
            severity=ControlSeverity.CRITICAL,
            category="Data Protection"
        )
        
        # Mock S3 encryption check
        def mock_get_bucket_encryption(Bucket):
            if Bucket == "bucket1":
                return {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
            else:
                raise ClientError(
                    {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}},
                    "GetBucketEncryption"
                )
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            s3_buckets,  # list_buckets
            mock_get_bucket_encryption(Bucket="bucket1"),  # bucket1 encryption
            ClientError(  # bucket2 no encryption
                {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}},
                "GetBucketEncryption"
            ),
            rds_instances,  # describe_db_instances
            ebs_volumes  # describe_volumes
        ])):
            result = await compliance_scanner.check_data_encryption(control, None)
        
        assert result.status == ComplianceStatus.NON_COMPLIANT
        assert "3 unencrypted resources" in result.details
        
        unencrypted = result.evidence.get("unencrypted_resources", [])
        assert len(unencrypted) == 3
        
        # Check resource types
        resource_types = {r["Type"] for r in unencrypted}
        assert "S3Bucket" in resource_types
        assert "RDSInstance" in resource_types
        assert "EBSVolume" in resource_types
    
    @pytest.mark.asyncio
    async def test_check_audit_trails(self, compliance_scanner):
        """Test audit trail check."""
        # Mock CloudTrail responses
        trails = {
            "trailList": [{
                "Name": "test-trail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
                "IsMultiRegionTrail": True
            }]
        }
        
        trail_status = {"IsLogging": True}
        
        s3_buckets = {"Buckets": [{"Name": "bucket1"}, {"Name": "bucket2"}]}
        
        control = ComplianceControl(
            control_id="TEST-AUDIT",
            title="Test Audit",
            description="Test",
            framework=ComplianceFramework.PCI_DSS,
            severity=ControlSeverity.HIGH,
            category="Logging"
        )
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            trails,  # describe_trails
            trail_status,  # get_trail_status
            s3_buckets,  # list_buckets
            {"LoggingEnabled": {"TargetBucket": "logs"}},  # bucket1 logging
            ClientError({"Error": {"Code": "NoSuchBucketLogging"}}, "GetBucketLogging")  # bucket2 no logging
        ])):
            result = await compliance_scanner.check_audit_trails(control, None)
        
        assert result.status == ComplianceStatus.WARNING
        assert "1 S3 buckets lack access logging" in result.details
    
    @pytest.mark.asyncio
    async def test_check_access_control(self, compliance_scanner):
        """Test access control check."""
        # Mock IAM responses
        account_summary = {
            "SummaryMap": {"AccountMFAEnabled": 0}
        }
        
        password_policy = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 8,
                "RequireUppercaseCharacters": False,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
                "MaxPasswordAge": 0
            }
        }
        
        users = {
            "Users": [
                {"UserName": "user1"},
                {"UserName": "user2"}
            ]
        }
        
        control = ComplianceControl(
            control_id="TEST-ACCESS",
            title="Test Access",
            description="Test",
            framework=ComplianceFramework.HIPAA,
            severity=ControlSeverity.CRITICAL,
            category="Access Control"
        )
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            account_summary,  # get_account_summary
            password_policy,  # get_account_password_policy
            users,  # list_users
            {"MFADevices": []},  # user1 no MFA
            {"LoginProfile": {"UserName": "user1"}},  # user1 has console access
            {"MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/user2"}]},  # user2 has MFA
        ])):
            result = await compliance_scanner.check_access_control(control, None)
        
        assert result.status == ComplianceStatus.NON_COMPLIANT
        
        issues = result.evidence.get("issues", [])
        assert len(issues) > 0
        assert any("Root account does not have MFA" in issue for issue in issues)
        assert any("minimum length" in issue for issue in issues)
        assert result.remediation_available is True
    
    @pytest.mark.asyncio
    async def test_check_root_account_usage(self, compliance_scanner):
        """Test root account usage check."""
        # Mock credential report
        credential_report = """user,password_last_used,access_key_1_active,access_key_2_active,mfa_active
<root_account>,2024-01-01T00:00:00+00:00,false,false,true
user1,N/A,true,false,true"""
        
        control = ComplianceControl(
            control_id="CIS-1.1",
            title="Root Account Usage",
            description="Test",
            framework=ComplianceFramework.CIS,
            severity=ControlSeverity.CRITICAL,
            category="IAM"
        )
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            {},  # generate_credential_report
            {"Content": credential_report.encode("utf-8")}  # get_credential_report
        ])):
            await asyncio.sleep(0)  # Let async context switch
            with patch("asyncio.sleep", new=AsyncMock()):
                result = await compliance_scanner.check_root_account_usage(control, None)
        
        assert result.status == ComplianceStatus.COMPLIANT
        assert "Root account follows best practices" in result.details
    
    @pytest.mark.asyncio
    async def test_check_cloudtrail_enabled(self, compliance_scanner):
        """Test CloudTrail enabled check."""
        trails = {
            "trailList": [{
                "Name": "global-trail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/global-trail",
                "IsMultiRegionTrail": True
            }]
        }
        
        trail_status = {"IsLogging": True}
        
        event_selectors = {
            "EventSelectors": [{
                "IncludeManagementEvents": True,
                "ReadWriteType": "All",
                "DataResources": [
                    {
                        "Type": "AWS::S3::Object",
                        "Values": ["arn:aws:s3:::*/*"]
                    },
                    {
                        "Type": "AWS::Lambda::Function",
                        "Values": ["arn:aws:lambda:*:*:function/*"]
                    }
                ]
            }]
        }
        
        control = ComplianceControl(
            control_id="CIS-2.1",
            title="CloudTrail Enabled",
            description="Test",
            framework=ComplianceFramework.CIS,
            severity=ControlSeverity.HIGH,
            category="Logging"
        )
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            trails,  # describe_trails
            trail_status,  # get_trail_status
            event_selectors  # get_event_selectors
        ])):
            result = await compliance_scanner.check_cloudtrail_enabled(control, None)
        
        assert result.status == ComplianceStatus.COMPLIANT
        assert "CloudTrail is properly configured" in result.details
    
    @pytest.mark.asyncio
    async def test_auto_remediation(self, compliance_scanner):
        """Test auto-remediation functionality."""
        # Create a non-compliant finding with remediation
        control = ComplianceControl(
            control_id="TEST-REMEDIATE",
            title="Test Remediation",
            description="Test",
            framework=ComplianceFramework.PCI_DSS,
            severity=ControlSeverity.HIGH,
            category="Security"
        )
        
        result = ComplianceResult(
            control=control,
            status=ComplianceStatus.NON_COMPLIANT,
            details="Security groups have issues",
            remediation_available=True,
            auto_remediation_function="remediate_security_groups",
            evidence={
                "non_compliant_security_groups": [{
                    "SecurityGroupId": "sg-12345",
                    "Rule": "Port 22 open to 0.0.0.0/0"
                }]
            }
        )
        
        # Mock remediation
        sg_response = {
            "SecurityGroups": [{
                "GroupId": "sg-12345",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            }]
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            sg_response,  # describe_security_groups
            {}  # revoke_security_group_ingress
        ])):
            await compliance_scanner._auto_remediate(result)
    
    def test_generate_report(self, compliance_scanner):
        """Test report generation."""
        results = [
            ComplianceResult(
                control=ComplianceControl(
                    control_id="C1",
                    title="Control 1",
                    description="Test",
                    framework=ComplianceFramework.PCI_DSS,
                    severity=ControlSeverity.CRITICAL,
                    category="Security"
                ),
                status=ComplianceStatus.NON_COMPLIANT
            ),
            ComplianceResult(
                control=ComplianceControl(
                    control_id="C2",
                    title="Control 2",
                    description="Test",
                    framework=ComplianceFramework.PCI_DSS,
                    severity=ControlSeverity.HIGH,
                    category="Security"
                ),
                status=ComplianceStatus.COMPLIANT
            ),
            ComplianceResult(
                control=ComplianceControl(
                    control_id="C3",
                    title="Control 3",
                    description="Test",
                    framework=ComplianceFramework.PCI_DSS,
                    severity=ControlSeverity.MEDIUM,
                    category="Logging"
                ),
                status=ComplianceStatus.NOT_APPLICABLE
            )
        ]
        
        report = compliance_scanner._generate_report(
            ComplianceFramework.PCI_DSS,
            "123456789012",
            results
        )
        
        assert report.framework == ComplianceFramework.PCI_DSS
        assert report.account_id == "123456789012"
        assert report.total_controls == 3
        assert report.compliant_controls == 1
        assert report.non_compliant_controls == 1
        assert report.not_applicable_controls == 1
        assert report.compliance_score == 50.0  # 1 compliant out of 2 applicable
        
        # Check category summary
        assert "Security" in report.summary["by_category"]
        assert report.summary["by_category"]["Security"]["total"] == 2
        assert report.summary["by_category"]["Security"]["compliant"] == 1
        assert report.summary["by_category"]["Security"]["non_compliant"] == 1
    
    @pytest.mark.asyncio
    async def test_export_report_json(self, compliance_scanner):
        """Test exporting report as JSON."""
        report = ComplianceReport(
            framework=ComplianceFramework.PCI_DSS,
            account_id="123456789012",
            region="us-east-1",
            scan_date=datetime.utcnow(),
            total_controls=10,
            compliant_controls=7,
            non_compliant_controls=3,
            not_applicable_controls=0,
            error_controls=0,
            compliance_score=70.0,
            results=[],
            recommendations=["Fix security groups", "Enable MFA"]
        )
        
        json_export = await compliance_scanner.export_report(report, format="json")
        
        # Verify it's valid JSON
        data = json.loads(json_export)
        assert data["framework"] == "PCI_DSS"
        assert data["compliance_score"] == 70.0
        assert len(data["recommendations"]) == 2
    
    @pytest.mark.asyncio
    async def test_export_report_csv(self, compliance_scanner):
        """Test exporting report as CSV."""
        results = [
            ComplianceResult(
                control=ComplianceControl(
                    control_id="C1",
                    title="Control 1",
                    description="Test",
                    framework=ComplianceFramework.PCI_DSS,
                    severity=ControlSeverity.HIGH,
                    category="Security"
                ),
                status=ComplianceStatus.NON_COMPLIANT,
                details="Failed check",
                remediation_available=True
            )
        ]
        
        report = ComplianceReport(
            framework=ComplianceFramework.PCI_DSS,
            account_id="123456789012",
            region="us-east-1",
            scan_date=datetime.utcnow(),
            total_controls=1,
            compliant_controls=0,
            non_compliant_controls=1,
            not_applicable_controls=0,
            error_controls=0,
            compliance_score=0.0,
            results=results,
            recommendations=[]
        )
        
        csv_export = await compliance_scanner.export_report(report, format="csv")
        
        # Verify CSV structure
        lines = csv_export.strip().split("\n")
        assert len(lines) == 2  # Header + 1 result
        assert "Control ID" in lines[0]
        assert "C1" in lines[1]
        assert "NON_COMPLIANT" in lines[1]


class TestIntegration:
    """Test integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_full_compliance_scan_workflow(self, compliance_scanner):
        """Test complete compliance scan workflow."""
        # Mock all AWS service responses for a minimal scan
        compliance_scanner.sts_client.get_caller_identity = MagicMock(
            return_value={"Account": "123456789012"}
        )
        
        # Mock check methods
        async def mock_check(control, resources):
            if "firewall" in control.check_function:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.COMPLIANT,
                    details="Firewall configured correctly"
                )
            elif "encryption" in control.check_function:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NON_COMPLIANT,
                    details="Some resources unencrypted",
                    remediation_available=False
                )
            else:
                return ComplianceResult(
                    control=control,
                    status=ComplianceStatus.NOT_APPLICABLE,
                    details="Not applicable to environment"
                )
        
        compliance_scanner._check_control = mock_check
        
        with patch("asyncio.to_thread", new=AsyncMock(
            return_value={"Account": "123456789012"}
        )):
            report = await compliance_scanner.scan_compliance(
                framework=ComplianceFramework.PCI_DSS,
                auto_remediate=False
            )
        
        assert isinstance(report, ComplianceReport)
        assert report.framework == ComplianceFramework.PCI_DSS
        assert report.total_controls > 0
        assert report.compliance_score >= 0
        assert report.compliance_score <= 100
        
        # Verify recommendations generated
        if report.non_compliant_controls > 0:
            assert len(report.recommendations) > 0