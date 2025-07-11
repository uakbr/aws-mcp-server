"""AWS IAM Policy Analyzer for permission analysis and security recommendations.

This module provides tools to:
- Analyze IAM policies for overly permissive access
- Generate least-privilege policy recommendations
- Detect policy anomalies and security risks
- Provide policy optimization suggestions
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Union

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk levels for IAM policy findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingType(Enum):
    """Types of IAM policy findings."""

    OVERLY_PERMISSIVE = "OVERLY_PERMISSIVE"
    WILDCARD_RESOURCE = "WILDCARD_RESOURCE"
    WILDCARD_ACTION = "WILDCARD_ACTION"
    ADMIN_ACCESS = "ADMIN_ACCESS"
    UNUSED_PERMISSION = "UNUSED_PERMISSION"
    CROSS_ACCOUNT_ACCESS = "CROSS_ACCOUNT_ACCESS"
    PUBLIC_ACCESS = "PUBLIC_ACCESS"
    DANGEROUS_ACTION = "DANGEROUS_ACTION"
    MISSING_CONDITION = "MISSING_CONDITION"
    WEAK_CONDITION = "WEAK_CONDITION"


@dataclass
class PolicyFinding:
    """Represents a finding from IAM policy analysis."""

    finding_type: FindingType
    risk_level: RiskLevel
    resource_arn: str
    policy_name: str
    description: str
    recommendation: str
    affected_actions: list[str] = field(default_factory=list)
    affected_resources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation_steps: list[str] = field(default_factory=list)


@dataclass
class PolicyAnalysisResult:
    """Result of IAM policy analysis."""

    resource_arn: str
    resource_type: str
    policy_name: str
    findings: list[PolicyFinding]
    risk_score: float
    last_used: Optional[datetime] = None
    attached_entities: list[str] = field(default_factory=list)
    policy_document: Optional[dict[str, Any]] = None


@dataclass
class LeastPrivilegeRecommendation:
    """Recommendation for least-privilege policy."""

    original_policy: dict[str, Any]
    recommended_policy: dict[str, Any]
    removed_permissions: list[str]
    risk_reduction: float
    explanation: str


class IAMAnalyzer:
    """Analyzer for IAM policies and permissions."""

    # Dangerous actions that pose high security risk
    DANGEROUS_ACTIONS = {
        "*",
        "iam:*",
        "iam:PassRole",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutGroupPolicy",
        "iam:PutRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "lambda:UpdateFunctionCode",
        "glue:CreateDevEndpoint",
        "glue:UpdateDevEndpoint",
        "cloudformation:CreateStack",
        "datapipeline:CreatePipeline",
        "datapipeline:PutPipelineDefinition",
    }

    # Services that should rarely have wildcard access
    SENSITIVE_SERVICES = {
        "iam",
        "sts",
        "kms",
        "cloudtrail",
        "config",
        "guardduty",
        "securityhub",
        "organizations",
        "account",
    }

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """Initialize IAM Analyzer.

        Args:
            region: AWS region
            profile: AWS profile to use for authentication
        """
        self.region = region or "us-east-1"
        self.profile = profile

        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.iam_client = session.client("iam")
        self.access_analyzer_client = session.client("accessanalyzer", region_name=self.region)
        self.sts_client = session.client("sts")

    async def analyze_all_policies(self, include_aws_managed: bool = False) -> list[PolicyAnalysisResult]:
        """Analyze all IAM policies in the account.

        Args:
            include_aws_managed: Whether to include AWS managed policies

        Returns:
            List of policy analysis results
        """
        results = []

        # Analyze customer managed policies
        policies = await self._list_policies(scope="Local")
        for policy in policies:
            result = await self.analyze_policy(policy["Arn"])
            if result.findings:  # Only include policies with findings
                results.append(result)

        # Analyze AWS managed policies if requested
        if include_aws_managed:
            aws_policies = await self._list_policies(scope="AWS")
            for policy in aws_policies[:50]:  # Limit to prevent overwhelming results
                result = await self.analyze_policy(policy["Arn"])
                if result.findings:
                    results.append(result)

        # Analyze inline policies
        inline_results = await self._analyze_inline_policies()
        results.extend(inline_results)

        return sorted(results, key=lambda x: x.risk_score, reverse=True)

    async def analyze_policy(self, policy_arn: str) -> PolicyAnalysisResult:
        """Analyze a specific IAM policy.

        Args:
            policy_arn: ARN of the policy to analyze

        Returns:
            Policy analysis result
        """
        try:
            # Get policy details
            policy_response = await asyncio.to_thread(self.iam_client.get_policy, PolicyArn=policy_arn)
            policy = policy_response["Policy"]

            # Get policy document
            version_response = await asyncio.to_thread(
                self.iam_client.get_policy_version, PolicyArn=policy_arn, VersionId=policy["DefaultVersionId"]
            )
            policy_document = json.loads(version_response["PolicyVersion"]["Document"])

            # Get attached entities
            attached_entities = await self._get_attached_entities(policy_arn)

            # Analyze the policy
            findings = await self._analyze_policy_document(policy_document, policy["PolicyName"], policy_arn)

            # Calculate risk score
            risk_score = self._calculate_risk_score(findings)

            return PolicyAnalysisResult(
                resource_arn=policy_arn,
                resource_type="AWS::IAM::Policy",
                policy_name=policy["PolicyName"],
                findings=findings,
                risk_score=risk_score,
                attached_entities=attached_entities,
                policy_document=policy_document,
            )

        except ClientError as e:
            logger.error(f"Error analyzing policy {policy_arn}: {e}")
            raise

    async def analyze_role(self, role_name: str) -> list[PolicyAnalysisResult]:
        """Analyze all policies attached to a role.

        Args:
            role_name: Name of the IAM role

        Returns:
            List of policy analysis results
        """
        results = []

        try:
            # Get role details
            role_response = await asyncio.to_thread(self.iam_client.get_role, RoleName=role_name)
            role = role_response["Role"]

            # Analyze trust policy
            trust_policy = json.loads(role["AssumeRolePolicyDocument"])
            trust_findings = await self._analyze_trust_policy(trust_policy, role_name)
            if trust_findings:
                results.append(
                    PolicyAnalysisResult(
                        resource_arn=role["Arn"],
                        resource_type="AWS::IAM::Role::TrustPolicy",
                        policy_name=f"{role_name}-TrustPolicy",
                        findings=trust_findings,
                        risk_score=self._calculate_risk_score(trust_findings),
                        policy_document=trust_policy,
                    )
                )

            # Analyze attached managed policies
            attached_policies = await asyncio.to_thread(self.iam_client.list_attached_role_policies, RoleName=role_name)
            for policy in attached_policies.get("AttachedPolicies", []):
                result = await self.analyze_policy(policy["PolicyArn"])
                results.append(result)

            # Analyze inline policies
            inline_policies = await asyncio.to_thread(self.iam_client.list_role_policies, RoleName=role_name)
            for policy_name in inline_policies.get("PolicyNames", []):
                policy_response = await asyncio.to_thread(self.iam_client.get_role_policy, RoleName=role_name, PolicyName=policy_name)
                policy_document = json.loads(policy_response["PolicyDocument"])

                findings = await self._analyze_policy_document(policy_document, policy_name, f"inline-policy-{role_name}-{policy_name}")

                if findings:
                    results.append(
                        PolicyAnalysisResult(
                            resource_arn=f"{role['Arn']}/inline-policy/{policy_name}",
                            resource_type="AWS::IAM::Role::InlinePolicy",
                            policy_name=policy_name,
                            findings=findings,
                            risk_score=self._calculate_risk_score(findings),
                            attached_entities=[role["Arn"]],
                            policy_document=policy_document,
                        )
                    )

        except ClientError as e:
            logger.error(f"Error analyzing role {role_name}: {e}")
            raise

        return results

    async def generate_least_privilege_policy(
        self, current_policy: dict[str, Any], usage_data: Optional[dict[str, Any]] = None
    ) -> LeastPrivilegeRecommendation:
        """Generate a least-privilege version of a policy.

        Args:
            current_policy: Current policy document
            usage_data: Optional usage data to inform recommendations

        Returns:
            Least-privilege policy recommendation
        """
        recommended_policy = {"Version": "2012-10-17", "Statement": []}
        removed_permissions = []
        
        for statement in current_policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                recommended_policy["Statement"].append(statement)
                continue

            # Analyze actions
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # Filter out wildcard actions
            filtered_actions = []
            for action in actions:
                if "*" in action and action != "*":
                    # Keep partial wildcards but log them
                    filtered_actions.append(action)
                elif action == "*":
                    # Replace with specific actions based on usage
                    if usage_data:
                        used_actions = usage_data.get("used_actions", [])
                        filtered_actions.extend(used_actions)
                        removed_permissions.append("*")
                    else:
                        # If no usage data, suggest removing
                        removed_permissions.append("*")
                else:
                    filtered_actions.append(action)

            # Filter out wildcard resources where possible
            filtered_resources = []
            for resource in resources:
                if resource == "*":
                    # Try to scope down based on actions
                    scoped_resources = self._suggest_scoped_resources(filtered_actions)
                    if scoped_resources:
                        filtered_resources.extend(scoped_resources)
                        removed_permissions.append("Resource: *")
                    else:
                        filtered_resources.append(resource)
                else:
                    filtered_resources.append(resource)

            # Add conditions where appropriate
            conditions = statement.get("Condition", {})
            if not conditions and self._should_have_conditions(filtered_actions):
                conditions = self._suggest_conditions(filtered_actions)

            # Build new statement
            if filtered_actions and filtered_resources:
                new_statement = {
                    "Effect": "Allow",
                    "Action": filtered_actions,
                    "Resource": filtered_resources,
                }
                if conditions:
                    new_statement["Condition"] = conditions

                recommended_policy["Statement"].append(new_statement)

        # Calculate risk reduction
        original_risk = self._calculate_policy_risk(current_policy)
        recommended_risk = self._calculate_policy_risk(recommended_policy)
        risk_reduction = max(0, (original_risk - recommended_risk) / original_risk) if original_risk > 0 else 0

        explanation = self._generate_recommendation_explanation(current_policy, recommended_policy, removed_permissions)

        return LeastPrivilegeRecommendation(
            original_policy=current_policy,
            recommended_policy=recommended_policy,
            removed_permissions=removed_permissions,
            risk_reduction=risk_reduction,
            explanation=explanation,
        )

    async def find_unused_permissions(self, days: int = 90) -> list[dict[str, Any]]:
        """Find permissions that haven't been used in the specified number of days.

        Args:
            days: Number of days to look back

        Returns:
            List of unused permissions by entity
        """
        unused_permissions = []

        try:
            # Use Access Analyzer to find unused access
            analyzer_arn = await self._get_or_create_analyzer()

            # List all findings
            findings_response = await asyncio.to_thread(self.access_analyzer_client.list_findings, analyzerArn=analyzer_arn)

            for finding in findings_response.get("findings", []):
                if finding.get("findingType") == "UnusedAccess":
                    unused_permissions.append(
                        {
                            "resource_arn": finding.get("resource"),
                            "unused_permissions": finding.get("action", []),
                            "last_accessed": finding.get("analyzedAt"),
                            "recommendation": "Consider removing these unused permissions",
                        }
                    )

        except ClientError as e:
            logger.error(f"Error finding unused permissions: {e}")

        return unused_permissions

    async def validate_policy_syntax(self, policy_document: Union[str, dict]) -> tuple[bool, list[str]]:
        """Validate IAM policy syntax.

        Args:
            policy_document: Policy document as string or dict

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        if isinstance(policy_document, dict):
            policy_json = json.dumps(policy_document)
        else:
            policy_json = policy_document

        try:
            # Use IAM policy simulator to validate
            await asyncio.to_thread(self.iam_client.simulate_custom_policy, PolicyInputList=[policy_json], ActionNames=["iam:CreateRole"])
            return True, []
        except ClientError as e:
            error_message = e.response.get("Error", {}).get("Message", str(e))
            return False, [error_message]

    # Helper methods

    async def _analyze_policy_document(self, policy_document: dict[str, Any], policy_name: str, resource_arn: str) -> list[PolicyFinding]:
        """Analyze a policy document for security issues."""
        findings = []

        for statement in policy_document.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # Check for wildcard actions
            if "*" in actions or any("*" in action for action in actions):
                findings.append(
                    PolicyFinding(
                        finding_type=FindingType.WILDCARD_ACTION,
                        risk_level=RiskLevel.HIGH if "*" in actions else RiskLevel.MEDIUM,
                        resource_arn=resource_arn,
                        policy_name=policy_name,
                        description="Policy contains wildcard actions",
                        recommendation="Replace wildcards with specific actions",
                        affected_actions=actions,
                        affected_resources=resources,
                        remediation_steps=[
                            "Identify the specific actions needed",
                            "Replace wildcard with explicit action list",
                            "Test the policy with reduced permissions",
                        ],
                    )
                )

            # Check for wildcard resources
            if "*" in resources:
                findings.append(
                    PolicyFinding(
                        finding_type=FindingType.WILDCARD_RESOURCE,
                        risk_level=RiskLevel.HIGH,
                        resource_arn=resource_arn,
                        policy_name=policy_name,
                        description="Policy grants access to all resources",
                        recommendation="Scope resources to specific ARNs",
                        affected_actions=actions,
                        affected_resources=resources,
                        remediation_steps=[
                            "Identify the specific resources that need access",
                            "Replace * with specific resource ARNs",
                            "Use resource tags or prefixes where appropriate",
                        ],
                    )
                )

            # Check for dangerous actions
            dangerous_actions_found = [action for action in actions if action in self.DANGEROUS_ACTIONS]
            if dangerous_actions_found:
                findings.append(
                    PolicyFinding(
                        finding_type=FindingType.DANGEROUS_ACTION,
                        risk_level=RiskLevel.CRITICAL,
                        resource_arn=resource_arn,
                        policy_name=policy_name,
                        description=f"Policy contains dangerous actions: {', '.join(dangerous_actions_found)}",
                        recommendation="Remove or restrict dangerous actions",
                        affected_actions=dangerous_actions_found,
                        affected_resources=resources,
                        evidence={"dangerous_actions": dangerous_actions_found},
                        remediation_steps=[
                            "Review if these permissions are absolutely necessary",
                            "Implement additional conditions to restrict usage",
                            "Consider using AWS Organizations SCPs for additional protection",
                        ],
                    )
                )

            # Check for admin access
            if ("*" in actions or "iam:*" in actions) and "*" in resources:
                findings.append(
                    PolicyFinding(
                        finding_type=FindingType.ADMIN_ACCESS,
                        risk_level=RiskLevel.CRITICAL,
                        resource_arn=resource_arn,
                        policy_name=policy_name,
                        description="Policy grants full administrative access",
                        recommendation="Implement least-privilege access",
                        affected_actions=actions,
                        affected_resources=resources,
                        remediation_steps=[
                            "Identify specific permissions needed",
                            "Create role-specific policies",
                            "Implement break-glass procedures for emergency access",
                        ],
                    )
                )

            # Check for missing conditions on sensitive actions
            if any(action.startswith(service + ":") for service in self.SENSITIVE_SERVICES for action in actions):
                if not statement.get("Condition"):
                    findings.append(
                        PolicyFinding(
                            finding_type=FindingType.MISSING_CONDITION,
                            risk_level=RiskLevel.MEDIUM,
                            resource_arn=resource_arn,
                            policy_name=policy_name,
                            description="Sensitive actions lack conditional restrictions",
                            recommendation="Add conditions to restrict access",
                            affected_actions=actions,
                            affected_resources=resources,
                            remediation_steps=[
                                "Add IP address restrictions",
                                "Require MFA for sensitive actions",
                                "Add time-based restrictions",
                            ],
                        )
                    )

        return findings

    async def _analyze_trust_policy(self, trust_policy: dict[str, Any], role_name: str) -> list[PolicyFinding]:
        """Analyze a role's trust policy for security issues."""
        findings = []

        for statement in trust_policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal", {})

            # Check for overly permissive principal
            if principal == "*" or principal.get("AWS") == "*":
                findings.append(
                    PolicyFinding(
                        finding_type=FindingType.PUBLIC_ACCESS,
                        risk_level=RiskLevel.CRITICAL,
                        resource_arn=f"arn:aws:iam:::role/{role_name}",
                        policy_name=f"{role_name}-TrustPolicy",
                        description="Role can be assumed by anyone",
                        recommendation="Restrict principal to specific accounts or services",
                        evidence={"principal": principal},
                        remediation_steps=[
                            "Specify exact AWS account IDs or service principals",
                            "Add external ID condition for cross-account access",
                            "Review if public access is truly needed",
                        ],
                    )
                )

            # Check for cross-account access without external ID
            if isinstance(principal.get("AWS"), list):
                external_accounts = [arn for arn in principal["AWS"] if not arn.startswith(f"arn:aws:iam::{await self._get_account_id()}")]
                if external_accounts and not statement.get("Condition", {}).get("StringEquals", {}).get("sts:ExternalId"):
                    findings.append(
                        PolicyFinding(
                            finding_type=FindingType.CROSS_ACCOUNT_ACCESS,
                            risk_level=RiskLevel.HIGH,
                            resource_arn=f"arn:aws:iam:::role/{role_name}",
                            policy_name=f"{role_name}-TrustPolicy",
                            description="Cross-account access lacks external ID",
                            recommendation="Add external ID condition for security",
                            evidence={"external_accounts": external_accounts},
                            remediation_steps=[
                                "Generate a unique external ID",
                                "Add StringEquals condition for sts:ExternalId",
                                "Share external ID securely with trusted party",
                            ],
                        )
                    )

        return findings

    async def _get_attached_entities(self, policy_arn: str) -> list[str]:
        """Get entities attached to a policy."""
        entities = []

        try:
            # Get attached users
            users_response = await asyncio.to_thread(self.iam_client.list_entities_for_policy, PolicyArn=policy_arn, EntityFilter="User")
            entities.extend([user["UserName"] for user in users_response.get("PolicyUsers", [])])

            # Get attached groups
            groups_response = await asyncio.to_thread(self.iam_client.list_entities_for_policy, PolicyArn=policy_arn, EntityFilter="Group")
            entities.extend([group["GroupName"] for group in groups_response.get("PolicyGroups", [])])

            # Get attached roles
            roles_response = await asyncio.to_thread(self.iam_client.list_entities_for_policy, PolicyArn=policy_arn, EntityFilter="Role")
            entities.extend([role["RoleName"] for role in roles_response.get("PolicyRoles", [])])

        except ClientError as e:
            logger.error(f"Error getting attached entities: {e}")

        return entities

    async def _list_policies(self, scope: str = "Local") -> list[dict[str, Any]]:
        """List IAM policies."""
        policies = []
        paginator = self.iam_client.get_paginator("list_policies")

        try:
            for page in paginator.paginate(Scope=scope):
                policies.extend(page.get("Policies", []))
        except ClientError as e:
            logger.error(f"Error listing policies: {e}")

        return policies

    async def _analyze_inline_policies(self) -> list[PolicyAnalysisResult]:
        """Analyze all inline policies in the account."""
        results = []

        # Analyze user inline policies
        try:
            users_response = await asyncio.to_thread(self.iam_client.list_users)
            for user in users_response.get("Users", []):
                user_policies = await asyncio.to_thread(self.iam_client.list_user_policies, UserName=user["UserName"])
                for policy_name in user_policies.get("PolicyNames", []):
                    policy_response = await asyncio.to_thread(
                        self.iam_client.get_user_policy, UserName=user["UserName"], PolicyName=policy_name
                    )
                    policy_document = json.loads(policy_response["PolicyDocument"])

                    findings = await self._analyze_policy_document(
                        policy_document, policy_name, f"inline-policy-user-{user['UserName']}-{policy_name}"
                    )

                    if findings:
                        results.append(
                            PolicyAnalysisResult(
                                resource_arn=f"{user['Arn']}/inline-policy/{policy_name}",
                                resource_type="AWS::IAM::User::InlinePolicy",
                                policy_name=policy_name,
                                findings=findings,
                                risk_score=self._calculate_risk_score(findings),
                                attached_entities=[user["Arn"]],
                                policy_document=policy_document,
                            )
                        )
        except ClientError as e:
            logger.error(f"Error analyzing user inline policies: {e}")

        return results

    def _calculate_risk_score(self, findings: list[PolicyFinding]) -> float:
        """Calculate overall risk score based on findings."""
        if not findings:
            return 0.0

        risk_weights = {RiskLevel.LOW: 1.0, RiskLevel.MEDIUM: 3.0, RiskLevel.HIGH: 7.0, RiskLevel.CRITICAL: 10.0}

        total_score = sum(risk_weights[finding.risk_level] for finding in findings)
        max_score = len(findings) * risk_weights[RiskLevel.CRITICAL]

        return min(100.0, (total_score / max_score) * 100) if max_score > 0 else 0.0

    def _calculate_policy_risk(self, policy: dict[str, Any]) -> float:
        """Calculate risk score for a policy document."""
        risk_score = 0.0

        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # Score based on wildcards
            if "*" in actions:
                risk_score += 30
            elif any("*" in action for action in actions):
                risk_score += 20

            if "*" in resources:
                risk_score += 30

            # Score based on dangerous actions
            dangerous_count = sum(1 for action in actions if action in self.DANGEROUS_ACTIONS)
            risk_score += dangerous_count * 15

            # Reduce score for conditions
            if statement.get("Condition"):
                risk_score *= 0.7

        return min(100.0, risk_score)

    def _suggest_scoped_resources(self, actions: list[str]) -> list[str]:
        """Suggest scoped resources based on actions."""
        suggestions = []

        # Extract service from actions
        services = set()
        for action in actions:
            if ":" in action:
                services.add(action.split(":")[0])

        # Suggest resource patterns based on service
        for service in services:
            if service == "s3":
                suggestions.extend(["arn:aws:s3:::bucket-name/*", "arn:aws:s3:::bucket-name"])
            elif service == "dynamodb":
                suggestions.append("arn:aws:dynamodb:*:*:table/table-name")
            elif service == "lambda":
                suggestions.append("arn:aws:lambda:*:*:function:function-name")
            elif service == "ec2":
                suggestions.append("arn:aws:ec2:*:*:instance/*")

        return suggestions if suggestions else ["arn:aws:service:region:account:resource"]

    def _should_have_conditions(self, actions: list[str]) -> bool:
        """Determine if actions should have conditions."""
        sensitive_patterns = ["Delete", "Terminate", "Modify", "Update", "Put", "Create"]
        return any(any(pattern in action for pattern in sensitive_patterns) for action in actions)

    def _suggest_conditions(self, actions: list[str]) -> dict[str, Any]:
        """Suggest appropriate conditions for actions."""
        conditions = {}

        # Suggest MFA for sensitive actions
        if any("iam:" in action or "Delete" in action for action in actions):
            conditions["Bool"] = {"aws:MultiFactorAuthPresent": "true"}

        # Suggest IP restrictions
        conditions["IpAddress"] = {"aws:SourceIp": ["10.0.0.0/8", "172.16.0.0/12"]}

        return conditions

    def _generate_recommendation_explanation(
        self, original: dict[str, Any], recommended: dict[str, Any], removed: list[str]
    ) -> str:
        """Generate explanation for policy recommendations."""
        explanation_parts = []

        if removed:
            explanation_parts.append(f"Removed {len(removed)} overly permissive permissions including: {', '.join(removed[:3])}")

        original_statements = len(original.get("Statement", []))
        recommended_statements = len(recommended.get("Statement", []))
        if recommended_statements < original_statements:
            explanation_parts.append(f"Consolidated {original_statements} statements into {recommended_statements}")

        # Check for added conditions
        original_conditions = sum(1 for s in original.get("Statement", []) if s.get("Condition"))
        recommended_conditions = sum(1 for s in recommended.get("Statement", []) if s.get("Condition"))
        if recommended_conditions > original_conditions:
            explanation_parts.append(f"Added {recommended_conditions - original_conditions} security conditions")

        return ". ".join(explanation_parts) if explanation_parts else "Policy follows security best practices"

    async def _get_or_create_analyzer(self) -> str:
        """Get or create an Access Analyzer."""
        try:
            analyzers = await asyncio.to_thread(self.access_analyzer_client.list_analyzers)
            if analyzers.get("analyzers"):
                return analyzers["analyzers"][0]["arn"]

            # Create new analyzer
            response = await asyncio.to_thread(
                self.access_analyzer_client.create_analyzer, analyzerName="aws-mcp-analyzer", type="ACCOUNT"
            )
            return response["arn"]
        except ClientError as e:
            logger.error(f"Error with Access Analyzer: {e}")
            raise

    async def _get_account_id(self) -> str:
        """Get current AWS account ID."""
        response = await asyncio.to_thread(self.sts_client.get_caller_identity)
        return response["Account"]