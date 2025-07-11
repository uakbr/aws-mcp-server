"""Unit tests for GuardDuty integration."""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_mcp_server.security.guardduty import (
    GuardDutyClient,
    ThreatDetector,
    ThreatFinding,
    ThreatSeverity,
    ThreatType,
)


@pytest.fixture
def mock_boto3_session():
    """Mock boto3 session."""
    with patch("boto3.Session") as mock:
        yield mock


@pytest.fixture
def guardduty_client(mock_boto3_session):
    """Create a GuardDutyClient with mocked AWS clients."""
    mock_session = MagicMock()
    mock_boto3_session.return_value = mock_session
    
    mock_client = MagicMock()
    mock_session.client.return_value = mock_client
    
    return GuardDutyClient(region="us-east-1")


@pytest.fixture
def sample_guardduty_finding():
    """Sample GuardDuty finding."""
    return {
        "Id": "threat-finding-123",
        "Type": "Recon:EC2/PortProbeUnprotectedPort",
        "Severity": 5.0,
        "Title": "Unprotected port on EC2 instance i-99999999",
        "Description": "EC2 instance has an unprotected port which is being probed",
        "Resource": {
            "ResourceType": "Instance",
            "InstanceDetails": {
                "InstanceId": "i-99999999",
                "InstanceType": "t2.micro",
                "LaunchTime": "2024-01-01T00:00:00.000Z"
            }
        },
        "Region": "us-east-1",
        "AccountId": "123456789012",
        "CreatedAt": "2024-01-01T00:00:00.000Z",
        "UpdatedAt": "2024-01-01T00:00:00.000Z",
        "Confidence": 8.0,
        "Service": {
            "ServiceName": "guardduty",
            "Archived": False,
            "Count": 1,
            "Evidence": {
                "ThreatIntelligenceDetails": []
            }
        }
    }


class TestThreatFinding:
    """Test ThreatFinding dataclass."""
    
    def test_from_guardduty_finding(self, sample_guardduty_finding):
        """Test creating ThreatFinding from GuardDuty format."""
        finding = ThreatFinding.from_guardduty_finding(sample_guardduty_finding)
        
        assert finding.id == "threat-finding-123"
        assert finding.type == "Recon:EC2/PortProbeUnprotectedPort"
        assert finding.severity == 5.0
        assert finding.threat_severity == ThreatSeverity.MEDIUM
        assert finding.title == "Unprotected port on EC2 instance i-99999999"
        assert finding.resource_type == "Instance"
        assert finding.resource_id == "i-99999999"
        assert finding.confidence == 8.0
        assert finding.archived is False
        assert finding.count == 1
    
    def test_threat_severity_calculation(self):
        """Test threat severity calculation based on numeric value."""
        # Low severity
        low_finding = {"Severity": 2.0}
        finding = ThreatFinding.from_guardduty_finding(low_finding)
        assert finding.threat_severity == ThreatSeverity.LOW
        
        # Medium severity
        medium_finding = {"Severity": 5.0}
        finding = ThreatFinding.from_guardduty_finding(medium_finding)
        assert finding.threat_severity == ThreatSeverity.MEDIUM
        
        # High severity
        high_finding = {"Severity": 8.0}
        finding = ThreatFinding.from_guardduty_finding(high_finding)
        assert finding.threat_severity == ThreatSeverity.HIGH
    
    def test_extract_resource_id_various_types(self):
        """Test resource ID extraction for different resource types."""
        # S3 bucket
        s3_resource = {
            "ResourceType": "S3Bucket",
            "S3BucketDetails": [{"Name": "my-bucket"}]
        }
        assert ThreatFinding._extract_resource_id(s3_resource) == "my-bucket"
        
        # Access key
        key_resource = {
            "ResourceType": "AccessKey",
            "AccessKeyDetails": {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}
        }
        assert ThreatFinding._extract_resource_id(key_resource) == "AKIAIOSFODNN7EXAMPLE"
        
        # EKS cluster
        cluster_resource = {
            "ResourceType": "Cluster",
            "EksClusterDetails": {"Name": "my-cluster"}
        }
        assert ThreatFinding._extract_resource_id(cluster_resource) == "my-cluster"
        
        # Unknown type
        unknown_resource = {"ResourceType": "Unknown"}
        assert ThreatFinding._extract_resource_id(unknown_resource) == ""


class TestGuardDutyClient:
    """Test GuardDutyClient."""
    
    @pytest.mark.asyncio
    async def test_create_detector(self, guardduty_client):
        """Test creating a detector."""
        mock_response = {"DetectorId": "detector-123"}
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            detector_id = await guardduty_client.create_detector()
        
        assert detector_id == "detector-123"
    
    @pytest.mark.asyncio
    async def test_get_detector_id_existing(self, guardduty_client):
        """Test getting existing detector ID."""
        mock_response = {"DetectorIds": ["detector-123"]}
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            detector_id = await guardduty_client.get_detector_id()
        
        assert detector_id == "detector-123"
        assert guardduty_client._detector_id == "detector-123"
    
    @pytest.mark.asyncio
    async def test_get_detector_id_create_new(self, guardduty_client):
        """Test creating new detector when none exists."""
        # Mock list response with no detectors
        list_response = {"DetectorIds": []}
        # Mock create response
        create_response = {"DetectorId": "new-detector-123"}
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            list_response,
            create_response
        ])):
            detector_id = await guardduty_client.get_detector_id()
        
        assert detector_id == "new-detector-123"
    
    @pytest.mark.asyncio
    async def test_get_findings(self, guardduty_client, sample_guardduty_finding):
        """Test retrieving findings."""
        # Mock detector ID
        guardduty_client._detector_id = "detector-123"
        
        # Mock paginator for list_findings
        mock_paginator = MagicMock()
        mock_page_iterator = MagicMock()
        mock_page_iterator.__iter__.return_value = iter([
            {"FindingIds": ["threat-finding-123"]}
        ])
        mock_paginator.paginate.return_value = mock_page_iterator
        guardduty_client.client.get_paginator.return_value = mock_paginator
        
        # Mock get_findings response
        get_findings_response = {"Findings": [sample_guardduty_finding]}
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=get_findings_response)):
            findings = await guardduty_client.get_findings(
                severity_threshold=ThreatSeverity.MEDIUM,
                max_results=10
            )
        
        assert len(findings) == 1
        assert findings[0].id == "threat-finding-123"
        assert findings[0].threat_severity == ThreatSeverity.MEDIUM
    
    @pytest.mark.asyncio
    async def test_get_findings_with_filters(self, guardduty_client):
        """Test retrieving findings with various filters."""
        guardduty_client._detector_id = "detector-123"
        
        # Mock empty response
        mock_paginator = MagicMock()
        mock_page_iterator = MagicMock()
        mock_page_iterator.__iter__.return_value = iter([{"FindingIds": []}])
        mock_paginator.paginate.return_value = mock_page_iterator
        guardduty_client.client.get_paginator.return_value = mock_paginator
        
        # Test with all filters
        findings = await guardduty_client.get_findings(
            severity_threshold=ThreatSeverity.HIGH,
            finding_types=["Recon:*"],
            resource_types=["Instance"],
            archived=False,
            updated_after=datetime.utcnow() - timedelta(days=7)
        )
        
        # Verify paginate was called with expected criteria
        call_args = mock_paginator.paginate.call_args
        criteria = call_args[1]["FindingCriteria"]["Criterion"]
        
        assert "severity" in criteria
        assert criteria["severity"]["Gte"] == 7.0
        assert "type" in criteria
        assert "resource.resourceType" in criteria
        assert "service.archived" in criteria
        assert "updatedAt" in criteria
    
    @pytest.mark.asyncio
    async def test_archive_findings(self, guardduty_client):
        """Test archiving findings."""
        guardduty_client._detector_id = "detector-123"
        mock_response = {}
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            result = await guardduty_client.archive_findings(
                ["finding-1", "finding-2"]
            )
        
        assert result == mock_response
    
    @pytest.mark.asyncio
    async def test_create_threat_intelligence_set(self, guardduty_client):
        """Test creating threat intelligence set."""
        guardduty_client._detector_id = "detector-123"
        mock_response = {"ThreatIntelSetId": "threat-intel-123"}
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            set_id = await guardduty_client.create_threat_intelligence_set(
                name="malicious-ips",
                format="TXT",
                location="s3://my-bucket/threat-intel.txt"
            )
        
        assert set_id == "threat-intel-123"
    
    @pytest.mark.asyncio
    async def test_create_suppression_rule(self, guardduty_client):
        """Test creating suppression rule."""
        guardduty_client._detector_id = "detector-123"
        mock_response = {"Name": "test-rule"}
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            finding_criteria = {
                "Criterion": {
                    "type": {
                        "Eq": ["Recon:EC2/PortProbeUnprotectedPort"]
                    }
                }
            }
            
            result = await guardduty_client.create_suppression_rule(
                name="test-rule",
                description="Suppress port probe findings",
                finding_criteria=finding_criteria
            )
        
        assert result == mock_response
    
    @pytest.mark.asyncio
    async def test_get_threat_statistics(self, guardduty_client):
        """Test getting threat statistics."""
        guardduty_client._detector_id = "detector-123"
        mock_response = {
            "FindingStatistics": {
                "CountBySeverity": {
                    "0.0": 10,
                    "2.0": 20,
                    "5.0": 15,
                    "8.0": 5
                }
            }
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            stats = await guardduty_client.get_threat_statistics(
                time_range=timedelta(days=7)
            )
        
        assert stats["total_findings"] == 50
        assert stats["severity_counts"]["0.0"] == 10
        assert stats["time_range_days"] == 7
    
    @pytest.mark.asyncio
    async def test_enable_s3_protection(self, guardduty_client):
        """Test enabling S3 protection."""
        guardduty_client._detector_id = "detector-123"
        mock_response = {}
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=mock_response)):
            result = await guardduty_client.enable_s3_protection()
        
        assert result == mock_response
    
    def test_get_min_severity_value(self, guardduty_client):
        """Test getting minimum severity value."""
        assert guardduty_client._get_min_severity_value(ThreatSeverity.LOW) == 1.0
        assert guardduty_client._get_min_severity_value(ThreatSeverity.MEDIUM) == 4.0
        assert guardduty_client._get_min_severity_value(ThreatSeverity.HIGH) == 7.0


class TestThreatDetector:
    """Test ThreatDetector."""
    
    @pytest.fixture
    def threat_detector(self, guardduty_client):
        """Create ThreatDetector instance."""
        return ThreatDetector(guardduty_client)
    
    def test_register_response_handler(self, threat_detector):
        """Test registering response handler."""
        async def test_handler(finding):
            pass
        
        threat_detector.register_response_handler("Recon:*", test_handler)
        
        assert "Recon:*" in threat_detector.response_handlers
        assert threat_detector.response_handlers["Recon:*"] == test_handler
    
    @pytest.mark.asyncio
    async def test_process_threat_with_handler(self, threat_detector, sample_guardduty_finding):
        """Test processing threat with matching handler."""
        # Track if handler was called
        handler_called = False
        
        async def test_handler(finding):
            nonlocal handler_called
            handler_called = True
            assert finding.type == "Recon:EC2/PortProbeUnprotectedPort"
        
        threat_detector.register_response_handler("Recon:", test_handler)
        
        finding = ThreatFinding.from_guardduty_finding(sample_guardduty_finding)
        await threat_detector._process_threat(finding)
        
        assert handler_called
    
    @pytest.mark.asyncio
    async def test_process_threat_handler_error(self, threat_detector, sample_guardduty_finding):
        """Test processing threat when handler raises error."""
        async def failing_handler(finding):
            raise Exception("Handler error")
        
        threat_detector.register_response_handler("Recon:", failing_handler)
        
        finding = ThreatFinding.from_guardduty_finding(sample_guardduty_finding)
        
        # Should not raise, just log error
        await threat_detector._process_threat(finding)
    
    @pytest.mark.asyncio
    async def test_generate_threat_report(self, threat_detector, sample_guardduty_finding):
        """Test generating threat report."""
        # Mock GuardDuty client methods
        findings = [
            ThreatFinding.from_guardduty_finding(sample_guardduty_finding),
            ThreatFinding.from_guardduty_finding({
                **sample_guardduty_finding,
                "Id": "threat-finding-124",
                "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
                "Severity": 8.0
            })
        ]
        
        threat_detector.guardduty.get_findings = AsyncMock(return_value=findings)
        threat_detector.guardduty.get_threat_statistics = AsyncMock(return_value={
            "severity_counts": {"0.0": 0, "2.0": 0, "5.0": 1, "8.0": 1},
            "total_findings": 2
        })
        
        report = await threat_detector.generate_threat_report(timedelta(days=7))
        
        assert report["total_findings"] == 2
        assert report["severity_breakdown"]["MEDIUM"] == 1
        assert report["severity_breakdown"]["HIGH"] == 1
        assert len(report["top_threats"]) == 2
        assert report["time_range"]["days"] == 7


class TestIntegration:
    """Test integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_threat_monitoring_workflow(self, guardduty_client):
        """Test complete threat monitoring workflow."""
        # Create detector
        guardduty_client._detector_id = None
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            {"DetectorIds": []},  # No existing detector
            {"DetectorId": "new-detector-123"}  # Create new
        ])):
            detector_id = await guardduty_client.get_detector_id()
            assert detector_id == "new-detector-123"
        
        # Enable protections
        with patch("asyncio.to_thread", new=AsyncMock(return_value={})):
            await guardduty_client.enable_s3_protection()
            await guardduty_client.enable_kubernetes_protection()
        
        # Create threat detector
        detector = ThreatDetector(guardduty_client)
        
        # Register handler
        handled_findings = []
        
        async def security_handler(finding):
            handled_findings.append(finding)
        
        detector.register_response_handler("UnauthorizedAccess:", security_handler)
        
        # Process finding
        finding = ThreatFinding(
            id="test-123",
            type="UnauthorizedAccess:EC2/SSHBruteForce",
            severity=8.0,
            threat_severity=ThreatSeverity.HIGH,
            title="SSH brute force attempt",
            description="Multiple failed SSH login attempts",
            resource_type="Instance",
            resource_id="i-12345",
            region="us-east-1",
            account_id="123456789012",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            confidence=9.0
        )
        
        await detector._process_threat(finding)
        
        assert len(handled_findings) == 1
        assert handled_findings[0].id == "test-123"