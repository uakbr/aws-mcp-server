"""Security module for AWS MCP Server.

This module provides integrations with AWS security services including:
- Security Hub for centralized security findings
- GuardDuty for threat detection
- IAM Policy Analyzer for permission analysis
- Secrets Manager and KMS for secure credential management
- Automated compliance scanning
"""

from .security_hub import SecurityHubClient, SecurityFinding, FindingSeverity
from .guardduty import GuardDutyClient, ThreatDetector
from .iam_analyzer import IAMAnalyzer, PolicyAnalysisResult
from .secrets_manager import SecretsManagerClient, KMSClient
from .compliance import ComplianceScanner, ComplianceFramework, ComplianceStatus

__all__ = [
    "SecurityHubClient",
    "SecurityFinding",
    "FindingSeverity",
    "GuardDutyClient",
    "ThreatDetector",
    "IAMAnalyzer",
    "PolicyAnalysisResult",
    "SecretsManagerClient",
    "KMSClient",
    "ComplianceScanner",
    "ComplianceFramework",
    "ComplianceStatus",
]