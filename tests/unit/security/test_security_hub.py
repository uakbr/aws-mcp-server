"""Unit tests for Security Hub integration."""

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_mcp_server.security.security_hub import (
    ComplianceStatus,
    FindingSeverity,
    RecordState,
    SecurityFinding,
    SecurityHubClient,
    WorkflowStatus,
)


@pytest.fixture
def mock_boto3_session():
    """Mock boto3 session."""
    with patch("boto3.Session") as mock:
        yield mock


@pytest.fixture
def security_hub_client(mock_boto3_session):
    """Create a SecurityHubClient with mocked AWS clients."""
    mock_session = MagicMock()
    mock_boto3_session.return_value = mock_session
    
    mock_client = MagicMock()
    mock_session.client.return_value = mock_client
    
    return SecurityHubClient(region="us-east-1")


@pytest.fixture
def sample_aws_finding():
    """Sample AWS Security Hub finding."""
    return {
        "Id": "test-finding-123",
        "Title": "Test Security Finding",
        "Description": "This is a test finding",
        "Severity": {"Label": "HIGH"},
        "Compliance": {"Status": "FAILED"},
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/aws/security-hub",
        "Resources": [{
            "Type": "AwsS3Bucket",
            "Id": "arn:aws:s3:::test-bucket",
            "Region": "us-east-1"
        }],
        "AwsAccountId": "123456789012",
        "CreatedAt": "2024-01-01T00:00:00.000Z",
        "UpdatedAt": "2024-01-01T00:00:00.000Z",
        "Types": ["Software and Configuration Checks"],
        "SourceUrl": "https://example.com",
        "UserDefinedFields": {"CustomField": "CustomValue"}
    }


class TestSecurityFinding:
    """Test SecurityFinding dataclass."""
    
    def test_from_aws_finding(self, sample_aws_finding):
        """Test creating SecurityFinding from AWS format."""
        finding = SecurityFinding.from_aws_finding(sample_aws_finding)
        
        assert finding.id == "test-finding-123"
        assert finding.title == "Test Security Finding"
        assert finding.description == "This is a test finding"
        assert finding.severity == FindingSeverity.HIGH
        assert finding.compliance_status == ComplianceStatus.FAILED
        assert finding.workflow_status == WorkflowStatus.NEW
        assert finding.record_state == RecordState.ACTIVE
        assert finding.resource_type == "AwsS3Bucket"
        assert finding.resource_id == "arn:aws:s3:::test-bucket"
        assert finding.region == "us-east-1"
        assert finding.account_id == "123456789012"
    
    def test_from_aws_finding_minimal(self):
        """Test creating SecurityFinding from minimal AWS format."""
        minimal_finding = {
            "Id": "test-123",
            "Title": "Test",
            "Description": "Test description"
        }
        
        finding = SecurityFinding.from_aws_finding(minimal_finding)
        
        assert finding.id == "test-123"
        assert finding.title == "Test"
        assert finding.severity == FindingSeverity.INFORMATIONAL
        assert finding.workflow_status == WorkflowStatus.NEW
        assert finding.record_state == RecordState.ACTIVE


class TestSecurityHubClient:
    """Test SecurityHubClient."""
    
    @pytest.mark.asyncio
    async def test_enable_security_hub(self, security_hub_client):
        """Test enabling Security Hub."""
        mock_response = {"HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default"}
        security_hub_client.client.enable_security_hub = MagicMock(return_value=mock_response)
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            result = await security_hub_client.enable_security_hub()
        
        assert result == mock_response
    
    @pytest.mark.asyncio
    async def test_enable_security_hub_already_enabled(self, security_hub_client):
        """Test enabling Security Hub when already enabled."""
        error = ClientError(
            {"Error": {"Code": "ResourceConflictException", "Message": "Already enabled"}},
            "EnableSecurityHub"
        )
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=error)):
            result = await security_hub_client.enable_security_hub()
        
        assert result == {"message": "Security Hub already enabled"}
    
    @pytest.mark.asyncio
    async def test_get_findings(self, security_hub_client, sample_aws_finding):
        """Test retrieving findings."""
        mock_pages = [{"Findings": [sample_aws_finding]}]
        
        # Mock paginator
        mock_paginator = MagicMock()
        mock_page_iterator = MagicMock()
        mock_page_iterator.__iter__.return_value = iter(mock_pages)
        mock_paginator.paginate.return_value = mock_page_iterator
        security_hub_client.client.get_paginator.return_value = mock_paginator
        
        findings = await security_hub_client.get_findings(
            severity_threshold=FindingSeverity.MEDIUM,
            max_results=10
        )
        
        assert len(findings) == 1
        assert findings[0].id == "test-finding-123"
        assert findings[0].severity == FindingSeverity.HIGH
    
    @pytest.mark.asyncio
    async def test_get_findings_with_filters(self, security_hub_client):
        """Test retrieving findings with custom filters."""
        mock_pages = [{"Findings": []}]
        
        # Mock paginator
        mock_paginator = MagicMock()
        mock_page_iterator = MagicMock()
        mock_page_iterator.__iter__.return_value = iter(mock_pages)
        mock_paginator.paginate.return_value = mock_paginator
        security_hub_client.client.get_paginator.return_value = mock_paginator
        
        custom_filters = {
            "ResourceType": [{
                "Value": "AwsS3Bucket",
                "Comparison": "EQUALS"
            }]
        }
        
        findings = await security_hub_client.get_findings(
            filters=custom_filters,
            compliance_status=ComplianceStatus.FAILED,
            workflow_status=WorkflowStatus.NEW
        )
        
        # Verify paginate was called with expected filters
        call_args = mock_paginator.paginate.call_args
        assert "Filters" in call_args[1]
        filters = call_args[1]["Filters"]
        assert "ComplianceStatus" in filters
        assert "WorkflowStatus" in filters
    
    @pytest.mark.asyncio
    async def test_create_finding(self, security_hub_client):
        """Test creating a security finding."""
        mock_response = {
            "FailedCount": 0,
            "SuccessCount": 1,
            "FailedFindings": []
        }
        
        # Mock methods
        security_hub_client._get_default_product_arn = AsyncMock(
            return_value="arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default"
        )
        security_hub_client._get_account_id = AsyncMock(return_value="123456789012")
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            finding = SecurityFinding(
                id="custom-finding-1",
                title="Custom Security Issue",
                description="A custom security finding",
                severity=FindingSeverity.HIGH,
                resource_type="AwsEc2Instance",
                resource_id="i-1234567890abcdef0"
            )
            
            result = await security_hub_client.create_finding(finding)
        
        assert result == mock_response
    
    @pytest.mark.asyncio
    async def test_create_finding_failed(self, security_hub_client):
        """Test creating a finding that fails."""
        mock_response = {
            "FailedCount": 1,
            "SuccessCount": 0,
            "FailedFindings": [{"Id": "custom-finding-1", "ErrorCode": "InvalidInput"}]
        }
        
        security_hub_client._get_default_product_arn = AsyncMock(
            return_value="arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default"
        )
        security_hub_client._get_account_id = AsyncMock(return_value="123456789012")
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            finding = SecurityFinding(
                id="custom-finding-1",
                title="Custom Security Issue",
                description="A custom security finding",
                severity=FindingSeverity.HIGH
            )
            
            with pytest.raises(Exception) as exc_info:
                await security_hub_client.create_finding(finding)
            
            assert "Failed to import finding" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_update_finding(self, security_hub_client):
        """Test updating a finding."""
        mock_response = {"ProcessedFindings": 1}
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            result = await security_hub_client.update_finding(
                finding_id="test-finding-123",
                workflow_status=WorkflowStatus.RESOLVED,
                note="Issue has been resolved"
            )
        
        assert result == mock_response
    
    @pytest.mark.asyncio
    async def test_get_compliance_summary(self, security_hub_client, sample_aws_finding):
        """Test getting compliance summary."""
        # Mock enabled standards
        mock_standards = [{
            "StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
        }]
        
        security_hub_client._get_enabled_standards = AsyncMock(return_value=mock_standards)
        
        # Mock findings
        mock_findings = [
            SecurityFinding.from_aws_finding({
                **sample_aws_finding,
                "Compliance": {"Status": "PASSED"}
            }),
            SecurityFinding.from_aws_finding({
                **sample_aws_finding,
                "Compliance": {"Status": "FAILED"}
            })
        ]
        
        security_hub_client.get_findings = AsyncMock(return_value=mock_findings)
        
        summary = await security_hub_client.get_compliance_summary()
        
        assert "aws-foundational-security-best-practices" in summary
        compliance_counts = summary["aws-foundational-security-best-practices"]
        assert compliance_counts["PASSED"] == 1
        assert compliance_counts["FAILED"] == 1
    
    @pytest.mark.asyncio
    async def test_create_automation_rule(self, security_hub_client):
        """Test creating an automation rule."""
        mock_response = {
            "RuleArn": "arn:aws:securityhub:us-east-1:123456789012:automation-rule/test-rule"
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            finding_filters = {
                "SeverityLabel": [{
                    "Value": "HIGH",
                    "Comparison": "EQUALS"
                }]
            }
            
            actions = [{
                "Type": "FINDING_FIELDS_UPDATE",
                "FindingFieldsUpdate": {
                    "Workflow": {"Status": "SUPPRESSED"}
                }
            }]
            
            result = await security_hub_client.create_automation_rule(
                rule_name="test-rule",
                finding_filters=finding_filters,
                actions=actions,
                description="Test automation rule"
            )
        
        assert result == mock_response
    
    def test_get_severities_above_threshold(self, security_hub_client):
        """Test getting severities above threshold."""
        severities = security_hub_client._get_severities_above_threshold(FindingSeverity.MEDIUM)
        
        assert FindingSeverity.MEDIUM in severities
        assert FindingSeverity.HIGH in severities
        assert FindingSeverity.CRITICAL in severities
        assert FindingSeverity.LOW not in severities
        assert FindingSeverity.INFORMATIONAL not in severities


class TestIntegration:
    """Test integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_full_finding_lifecycle(self, security_hub_client, sample_aws_finding):
        """Test full lifecycle of finding: create, retrieve, update."""
        # Setup mocks
        security_hub_client._get_default_product_arn = AsyncMock(
            return_value="arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default"
        )
        security_hub_client._get_account_id = AsyncMock(return_value="123456789012")
        
        # Mock create response
        create_response = {
            "FailedCount": 0,
            "SuccessCount": 1,
            "FailedFindings": []
        }
        
        # Mock get response
        mock_paginator = MagicMock()
        mock_page_iterator = MagicMock()
        mock_page_iterator.__iter__.return_value = iter([{"Findings": [sample_aws_finding]}])
        mock_paginator.paginate.return_value = mock_page_iterator
        security_hub_client.client.get_paginator.return_value = mock_paginator
        
        # Mock update response
        update_response = {"ProcessedFindings": 1}
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            create_response,  # For create
            update_response   # For update
        ])):
            # Create finding
            finding = SecurityFinding(
                id="test-finding-123",
                title="Test Security Finding",
                description="This is a test finding",
                severity=FindingSeverity.HIGH
            )
            
            create_result = await security_hub_client.create_finding(finding)
            assert create_result["SuccessCount"] == 1
            
            # Retrieve findings
            findings = await security_hub_client.get_findings(
                severity_threshold=FindingSeverity.HIGH
            )
            assert len(findings) == 1
            assert findings[0].id == "test-finding-123"
            
            # Update finding
            update_result = await security_hub_client.update_finding(
                finding_id="test-finding-123",
                workflow_status=WorkflowStatus.RESOLVED,
                note="Issue resolved"
            )
            assert update_result["ProcessedFindings"] == 1