"""Unit tests for IAM Policy Analyzer."""

import asyncio
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_mcp_server.security.iam_analyzer import (
    FindingType,
    IAMAnalyzer,
    LeastPrivilegeRecommendation,
    PolicyAnalysisResult,
    PolicyFinding,
    RiskLevel,
)


@pytest.fixture
def mock_boto3_session():
    """Mock boto3 session."""
    with patch("boto3.Session") as mock:
        yield mock


@pytest.fixture
def iam_analyzer(mock_boto3_session):
    """Create an IAMAnalyzer with mocked AWS clients."""
    mock_session = MagicMock()
    mock_boto3_session.return_value = mock_session
    
    # Mock all required clients
    mock_iam = MagicMock()
    mock_access_analyzer = MagicMock()
    mock_sts = MagicMock()
    
    def mock_client(service_name, **kwargs):
        if service_name == "iam":
            return mock_iam
        elif service_name == "accessanalyzer":
            return mock_access_analyzer
        elif service_name == "sts":
            return mock_sts
        return MagicMock()
    
    mock_session.client.side_effect = mock_client
    
    analyzer = IAMAnalyzer(region="us-east-1")
    analyzer.iam_client = mock_iam
    analyzer.access_analyzer_client = mock_access_analyzer
    analyzer.sts_client = mock_sts
    
    return analyzer


@pytest.fixture
def sample_policy_document():
    """Sample IAM policy document."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }


@pytest.fixture
def sample_policy_document_complex():
    """Complex IAM policy document with various issues."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:*",
                    "ec2:TerminateInstances"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::123456789012:role/MyRole"
            },
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": "*",
                "Condition": {
                    "IpAddress": {
                        "aws:SourceIp": "192.168.1.0/24"
                    }
                }
            }
        ]
    }


class TestPolicyFinding:
    """Test PolicyFinding dataclass."""
    
    def test_policy_finding_creation(self):
        """Test creating a policy finding."""
        finding = PolicyFinding(
            finding_type=FindingType.WILDCARD_ACTION,
            risk_level=RiskLevel.HIGH,
            resource_arn="arn:aws:iam::123456789012:policy/TestPolicy",
            policy_name="TestPolicy",
            description="Policy contains wildcard actions",
            recommendation="Replace wildcards with specific actions",
            affected_actions=["s3:*"],
            affected_resources=["*"]
        )
        
        assert finding.finding_type == FindingType.WILDCARD_ACTION
        assert finding.risk_level == RiskLevel.HIGH
        assert "s3:*" in finding.affected_actions
        assert "*" in finding.affected_resources


class TestIAMAnalyzer:
    """Test IAMAnalyzer."""
    
    @pytest.mark.asyncio
    async def test_analyze_policy_admin_access(self, iam_analyzer, sample_policy_document):
        """Test analyzing policy with admin access."""
        policy_arn = "arn:aws:iam::123456789012:policy/AdminPolicy"
        
        # Mock IAM responses
        iam_analyzer.iam_client.get_policy = MagicMock(return_value={
            "Policy": {
                "PolicyName": "AdminPolicy",
                "Arn": policy_arn,
                "DefaultVersionId": "v1"
            }
        })
        
        iam_analyzer.iam_client.get_policy_version = MagicMock(return_value={
            "PolicyVersion": {
                "Document": json.dumps(sample_policy_document)
            }
        })
        
        iam_analyzer._get_attached_entities = AsyncMock(return_value=["AdminRole"])
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            iam_analyzer.iam_client.get_policy(PolicyArn=policy_arn),
            iam_analyzer.iam_client.get_policy_version(PolicyArn=policy_arn, VersionId="v1")
        ])):
            result = await iam_analyzer.analyze_policy(policy_arn)
        
        assert result.policy_name == "AdminPolicy"
        assert result.resource_arn == policy_arn
        assert len(result.findings) > 0
        
        # Check for expected findings
        finding_types = [f.finding_type for f in result.findings]
        assert FindingType.WILDCARD_ACTION in finding_types
        assert FindingType.WILDCARD_RESOURCE in finding_types
        assert FindingType.ADMIN_ACCESS in finding_types
        
        # Check risk score
        assert result.risk_score > 80  # High risk for admin access
    
    @pytest.mark.asyncio
    async def test_analyze_policy_dangerous_actions(self, iam_analyzer, sample_policy_document_complex):
        """Test analyzing policy with dangerous actions."""
        policy_arn = "arn:aws:iam::123456789012:policy/DangerousPolicy"
        
        iam_analyzer.iam_client.get_policy = MagicMock(return_value={
            "Policy": {
                "PolicyName": "DangerousPolicy",
                "Arn": policy_arn,
                "DefaultVersionId": "v1"
            }
        })
        
        iam_analyzer.iam_client.get_policy_version = MagicMock(return_value={
            "PolicyVersion": {
                "Document": json.dumps(sample_policy_document_complex)
            }
        })
        
        iam_analyzer._get_attached_entities = AsyncMock(return_value=[])
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            iam_analyzer.iam_client.get_policy(PolicyArn=policy_arn),
            iam_analyzer.iam_client.get_policy_version(PolicyArn=policy_arn, VersionId="v1")
        ])):
            result = await iam_analyzer.analyze_policy(policy_arn)
        
        # Check for dangerous action findings
        dangerous_findings = [f for f in result.findings if f.finding_type == FindingType.DANGEROUS_ACTION]
        assert len(dangerous_findings) > 0
        
        # Check specific dangerous actions detected
        dangerous_actions = []
        for f in dangerous_findings:
            dangerous_actions.extend(f.affected_actions)
        
        assert "iam:PassRole" in dangerous_actions
    
    @pytest.mark.asyncio
    async def test_analyze_role_trust_policy(self, iam_analyzer):
        """Test analyzing role trust policy."""
        role_name = "TestRole"
        
        # Mock role with overly permissive trust policy
        iam_analyzer.iam_client.get_role = MagicMock(return_value={
            "Role": {
                "RoleName": role_name,
                "Arn": f"arn:aws:iam::123456789012:role/{role_name}",
                "AssumeRolePolicyDocument": json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "sts:AssumeRole"
                    }]
                })
            }
        })
        
        iam_analyzer.iam_client.list_attached_role_policies = MagicMock(return_value={
            "AttachedPolicies": []
        })
        
        iam_analyzer.iam_client.list_role_policies = MagicMock(return_value={
            "PolicyNames": []
        })
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            iam_analyzer.iam_client.get_role(RoleName=role_name),
            iam_analyzer.iam_client.list_attached_role_policies(RoleName=role_name),
            iam_analyzer.iam_client.list_role_policies(RoleName=role_name)
        ])):
            results = await iam_analyzer.analyze_role(role_name)
        
        # Should have trust policy findings
        trust_policy_results = [r for r in results if r.resource_type == "AWS::IAM::Role::TrustPolicy"]
        assert len(trust_policy_results) == 1
        
        trust_result = trust_policy_results[0]
        public_access_findings = [f for f in trust_result.findings if f.finding_type == FindingType.PUBLIC_ACCESS]
        assert len(public_access_findings) > 0
        assert public_access_findings[0].risk_level == RiskLevel.CRITICAL
    
    @pytest.mark.asyncio
    async def test_analyze_cross_account_trust(self, iam_analyzer):
        """Test analyzing cross-account trust without external ID."""
        role_name = "CrossAccountRole"
        
        iam_analyzer._get_account_id = AsyncMock(return_value="123456789012")
        
        iam_analyzer.iam_client.get_role = MagicMock(return_value={
            "Role": {
                "RoleName": role_name,
                "Arn": f"arn:aws:iam::123456789012:role/{role_name}",
                "AssumeRolePolicyDocument": json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": ["arn:aws:iam::987654321098:root"]
                        },
                        "Action": "sts:AssumeRole"
                    }]
                })
            }
        })
        
        iam_analyzer.iam_client.list_attached_role_policies = MagicMock(return_value={
            "AttachedPolicies": []
        })
        
        iam_analyzer.iam_client.list_role_policies = MagicMock(return_value={
            "PolicyNames": []
        })
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=[
            iam_analyzer.iam_client.get_role(RoleName=role_name),
            iam_analyzer.iam_client.list_attached_role_policies(RoleName=role_name),
            iam_analyzer.iam_client.list_role_policies(RoleName=role_name)
        ])):
            results = await iam_analyzer.analyze_role(role_name)
        
        # Check for cross-account findings
        trust_result = results[0]
        cross_account_findings = [f for f in trust_result.findings if f.finding_type == FindingType.CROSS_ACCOUNT_ACCESS]
        assert len(cross_account_findings) > 0
        assert "external ID" in cross_account_findings[0].recommendation.lower()
    
    @pytest.mark.asyncio
    async def test_generate_least_privilege_policy(self, iam_analyzer, sample_policy_document_complex):
        """Test generating least-privilege policy recommendations."""
        recommendation = await iam_analyzer.generate_least_privilege_policy(
            sample_policy_document_complex
        )
        
        assert isinstance(recommendation, LeastPrivilegeRecommendation)
        assert recommendation.original_policy == sample_policy_document_complex
        assert len(recommendation.recommended_policy["Statement"]) > 0
        
        # Check that wildcards were addressed
        for statement in recommendation.recommended_policy["Statement"]:
            if statement.get("Effect") == "Allow":
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                # Should not have service-level wildcards
                assert not any(action == "s3:*" for action in actions)
        
        # Check risk reduction
        assert recommendation.risk_reduction > 0
        assert recommendation.explanation != ""
    
    @pytest.mark.asyncio
    async def test_find_unused_permissions(self, iam_analyzer):
        """Test finding unused permissions."""
        # Mock Access Analyzer responses
        iam_analyzer._get_or_create_analyzer = AsyncMock(
            return_value="arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test"
        )
        
        iam_analyzer.access_analyzer_client.list_findings = MagicMock(return_value={
            "findings": [
                {
                    "resource": "arn:aws:iam::123456789012:role/UnusedRole",
                    "findingType": "UnusedAccess",
                    "action": ["s3:GetObject", "s3:PutObject"],
                    "analyzedAt": datetime.utcnow().isoformat()
                }
            ]
        })
        
        with patch("asyncio.to_thread", new=AsyncMock(
            return_value=iam_analyzer.access_analyzer_client.list_findings(
                analyzerArn="arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test"
            )
        )):
            unused = await iam_analyzer.find_unused_permissions(days=90)
        
        assert len(unused) == 1
        assert unused[0]["resource_arn"] == "arn:aws:iam::123456789012:role/UnusedRole"
        assert "s3:GetObject" in unused[0]["unused_permissions"]
    
    @pytest.mark.asyncio
    async def test_validate_policy_syntax(self, iam_analyzer):
        """Test policy syntax validation."""
        # Valid policy
        valid_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*"
            }]
        }
        
        with patch("asyncio.to_thread", new=AsyncMock(return_value=None)):
            is_valid, errors = await iam_analyzer.validate_policy_syntax(valid_policy)
        
        assert is_valid
        assert len(errors) == 0
        
        # Invalid policy
        iam_analyzer.iam_client.simulate_custom_policy.side_effect = ClientError(
            {"Error": {"Code": "MalformedPolicyDocument", "Message": "Invalid JSON"}},
            "SimulateCustomPolicy"
        )
        
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=ClientError(
            {"Error": {"Code": "MalformedPolicyDocument", "Message": "Invalid JSON"}},
            "SimulateCustomPolicy"
        ))):
            is_valid, errors = await iam_analyzer.validate_policy_syntax("{invalid json}")
        
        assert not is_valid
        assert len(errors) > 0
    
    def test_calculate_risk_score(self, iam_analyzer):
        """Test risk score calculation."""
        findings = [
            PolicyFinding(
                finding_type=FindingType.ADMIN_ACCESS,
                risk_level=RiskLevel.CRITICAL,
                resource_arn="test",
                policy_name="test",
                description="test",
                recommendation="test"
            ),
            PolicyFinding(
                finding_type=FindingType.WILDCARD_RESOURCE,
                risk_level=RiskLevel.HIGH,
                resource_arn="test",
                policy_name="test",
                description="test",
                recommendation="test"
            ),
            PolicyFinding(
                finding_type=FindingType.MISSING_CONDITION,
                risk_level=RiskLevel.MEDIUM,
                resource_arn="test",
                policy_name="test",
                description="test",
                recommendation="test"
            )
        ]
        
        score = iam_analyzer._calculate_risk_score(findings)
        
        # With 1 critical, 1 high, 1 medium finding
        # (10 + 7 + 3) / 30 * 100 = 66.67
        assert 65 < score < 70
    
    def test_suggest_scoped_resources(self, iam_analyzer):
        """Test resource scoping suggestions."""
        # S3 actions
        s3_suggestions = iam_analyzer._suggest_scoped_resources(["s3:GetObject", "s3:PutObject"])
        assert any("s3:::" in s for s in s3_suggestions)
        
        # DynamoDB actions  
        dynamo_suggestions = iam_analyzer._suggest_scoped_resources(["dynamodb:GetItem"])
        assert any("dynamodb:" in s for s in dynamo_suggestions)
        
        # Mixed services
        mixed_suggestions = iam_analyzer._suggest_scoped_resources(["s3:GetObject", "ec2:DescribeInstances"])
        assert any("s3:::" in s for s in mixed_suggestions)
        assert any("ec2:" in s for s in mixed_suggestions)
    
    def test_should_have_conditions(self, iam_analyzer):
        """Test condition requirement detection."""
        # Dangerous actions should have conditions
        assert iam_analyzer._should_have_conditions(["ec2:TerminateInstances"])
        assert iam_analyzer._should_have_conditions(["s3:DeleteBucket"])
        assert iam_analyzer._should_have_conditions(["iam:CreateUser"])
        
        # Read-only actions typically don't need conditions
        assert not iam_analyzer._should_have_conditions(["s3:ListBucket"])
        assert not iam_analyzer._should_have_conditions(["ec2:DescribeInstances"])


class TestIntegration:
    """Test integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_full_policy_analysis_workflow(self, iam_analyzer):
        """Test complete policy analysis workflow."""
        # Mock list of policies
        iam_analyzer._list_policies = AsyncMock(return_value=[
            {"Arn": "arn:aws:iam::123456789012:policy/Policy1", "PolicyName": "Policy1"},
            {"Arn": "arn:aws:iam::123456789012:policy/Policy2", "PolicyName": "Policy2"}
        ])
        
        # Mock analyze_policy to return different risk levels
        async def mock_analyze(arn):
            if "Policy1" in arn:
                return PolicyAnalysisResult(
                    resource_arn=arn,
                    resource_type="AWS::IAM::Policy",
                    policy_name="Policy1",
                    findings=[
                        PolicyFinding(
                            finding_type=FindingType.WILDCARD_ACTION,
                            risk_level=RiskLevel.HIGH,
                            resource_arn=arn,
                            policy_name="Policy1",
                            description="Wildcard actions",
                            recommendation="Remove wildcards"
                        )
                    ],
                    risk_score=75.0
                )
            else:
                return PolicyAnalysisResult(
                    resource_arn=arn,
                    resource_type="AWS::IAM::Policy",
                    policy_name="Policy2",
                    findings=[],
                    risk_score=0.0
                )
        
        iam_analyzer.analyze_policy = mock_analyze
        iam_analyzer._analyze_inline_policies = AsyncMock(return_value=[])
        
        results = await iam_analyzer.analyze_all_policies()
        
        # Should only return policies with findings
        assert len(results) == 1
        assert results[0].policy_name == "Policy1"
        assert results[0].risk_score == 75.0