"""
MCP Sampling capabilities for AI-powered AWS analysis.

This module implements sampling features that allow the MCP server to request
LLM completions for intelligent error analysis, architecture recommendations,
and other advanced insights.
"""

from typing import Dict, Any, Optional, List
from mcp.server.fastmcp import Context
import json
import logging

logger = logging.getLogger(__name__)


class AWSAnalyzer:
    """Provides AI-powered analysis of AWS resources and issues."""
    
    @staticmethod
    async def analyze_error(ctx: Context, command: str, error_output: str) -> Dict[str, Any]:
        """
        Analyze AWS CLI errors using LLM sampling and suggest solutions.
        
        Args:
            ctx: MCP context for sampling
            command: The AWS CLI command that failed
            error_output: The error message from AWS
            
        Returns:
            Dictionary containing analysis and recommendations
        """
        prompt = f"""Analyze this AWS CLI error and provide actionable solutions.

Command: {command}
Error Output: {error_output}

Please provide:
1. Root Cause Analysis: What specifically went wrong
2. Solution Steps: Clear, numbered steps to fix the issue
3. Prevention Tips: How to avoid this error in the future
4. Related Commands: Other AWS CLI commands that might help

Format your response as a structured analysis."""

        try:
            result = await ctx.sample(prompt)
            
            return {
                "status": "success",
                "command": command,
                "error": error_output,
                "analysis": result.text,
                "timestamp": None  # Will be added by the caller
            }
        except Exception as e:
            logger.error(f"Error during LLM sampling: {e}")
            return {
                "status": "error",
                "command": command,
                "error": error_output,
                "analysis": f"Failed to analyze error: {str(e)}",
                "timestamp": None
            }
    
    @staticmethod
    async def generate_architecture_recommendation(
        ctx: Context,
        current_resources: Dict[str, Any],
        requirements: str
    ) -> Dict[str, Any]:
        """
        Generate AWS architecture recommendations based on current resources.
        
        Args:
            ctx: MCP context for sampling
            current_resources: Dictionary of current AWS resources
            requirements: User's requirements or goals
            
        Returns:
            Architecture recommendations
        """
        resources_summary = json.dumps(current_resources, indent=2)
        
        prompt = f"""Based on the current AWS resources and requirements, provide architecture recommendations.

Current Resources:
{resources_summary}

Requirements:
{requirements}

Please provide:
1. Architecture Assessment: Analysis of current setup
2. Recommended Changes: Specific improvements with AWS services
3. Implementation Steps: How to implement the recommendations
4. Cost Impact: Estimated cost changes
5. Security Considerations: Security improvements needed

Format as a clear, actionable recommendation."""

        try:
            result = await ctx.sample(prompt)
            
            return {
                "status": "success",
                "requirements": requirements,
                "recommendations": result.text,
                "current_resources_count": len(current_resources),
                "timestamp": None
            }
        except Exception as e:
            logger.error(f"Error generating architecture recommendation: {e}")
            return {
                "status": "error",
                "requirements": requirements,
                "recommendations": f"Failed to generate recommendations: {str(e)}",
                "timestamp": None
            }
    
    @staticmethod
    async def analyze_costs(
        ctx: Context,
        cost_data: Dict[str, Any],
        optimization_goal: str = "reduce monthly spend by 20%"
    ) -> Dict[str, Any]:
        """
        Analyze AWS costs and suggest optimizations.
        
        Args:
            ctx: MCP context for sampling
            cost_data: Cost and usage data
            optimization_goal: Specific optimization target
            
        Returns:
            Cost optimization recommendations
        """
        cost_summary = json.dumps(cost_data, indent=2)
        
        prompt = f"""Analyze AWS costs and provide optimization recommendations.

Cost Data:
{cost_summary}

Optimization Goal: {optimization_goal}

Please provide:
1. Cost Analysis: Breakdown of major cost drivers
2. Quick Wins: Immediate actions for cost reduction
3. Long-term Optimizations: Strategic changes for sustained savings
4. Resource Right-sizing: Specific instances/services to resize
5. Reserved Instances/Savings Plans: Recommendations for commitments
6. Estimated Savings: Projected monthly/annual savings

Be specific with instance types, service configurations, and estimated savings."""

        try:
            result = await ctx.sample(prompt)
            
            return {
                "status": "success",
                "optimization_goal": optimization_goal,
                "analysis": result.text,
                "total_monthly_cost": cost_data.get("total_monthly_cost", "Unknown"),
                "timestamp": None
            }
        except Exception as e:
            logger.error(f"Error analyzing costs: {e}")
            return {
                "status": "error",
                "optimization_goal": optimization_goal,
                "analysis": f"Failed to analyze costs: {str(e)}",
                "timestamp": None
            }
    
    @staticmethod
    async def generate_security_report(
        ctx: Context,
        security_findings: List[Dict[str, Any]],
        compliance_framework: str = "AWS Well-Architected"
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive security report from raw findings.
        
        Args:
            ctx: MCP context for sampling
            security_findings: List of security issues/findings
            compliance_framework: Framework to evaluate against
            
        Returns:
            Human-readable security report
        """
        findings_summary = json.dumps(security_findings, indent=2)
        
        prompt = f"""Generate a comprehensive security report based on these findings.

Security Findings:
{findings_summary}

Compliance Framework: {compliance_framework}

Please provide:
1. Executive Summary: High-level security posture assessment
2. Critical Issues: Issues requiring immediate attention
3. Risk Assessment: Categorized by severity (Critical/High/Medium/Low)
4. Remediation Plan: Prioritized list of fixes with steps
5. Compliance Gaps: Specific {compliance_framework} requirements not met
6. Best Practices: Additional security hardening recommendations

Format as a professional security report."""

        try:
            result = await ctx.sample(prompt)
            
            return {
                "status": "success",
                "compliance_framework": compliance_framework,
                "findings_count": len(security_findings),
                "report": result.text,
                "timestamp": None
            }
        except Exception as e:
            logger.error(f"Error generating security report: {e}")
            return {
                "status": "error",
                "compliance_framework": compliance_framework,
                "report": f"Failed to generate report: {str(e)}",
                "timestamp": None
            }
    
    @staticmethod
    async def suggest_automation(
        ctx: Context,
        manual_tasks: List[str],
        current_tools: List[str] = None
    ) -> Dict[str, Any]:
        """
        Suggest automation opportunities for manual AWS tasks.
        
        Args:
            ctx: MCP context for sampling
            manual_tasks: List of tasks currently done manually
            current_tools: Tools already in use
            
        Returns:
            Automation recommendations
        """
        if current_tools is None:
            current_tools = []
            
        tasks_list = "\n".join(f"- {task}" for task in manual_tasks)
        tools_list = "\n".join(f"- {tool}" for tool in current_tools) if current_tools else "None specified"
        
        prompt = f"""Suggest AWS automation solutions for these manual tasks.

Manual Tasks:
{tasks_list}

Current Tools:
{tools_list}

Please provide:
1. Automation Opportunities: Map each task to AWS automation services
2. Implementation Approach: Step-by-step for each automation
3. Tool Recommendations: Specific AWS services/features to use
4. Integration Points: How to connect with existing tools
5. ROI Estimation: Time savings and efficiency gains
6. Quick Start: Which automation to implement first

Focus on practical, AWS-native solutions."""

        try:
            result = await ctx.sample(prompt)
            
            return {
                "status": "success",
                "manual_tasks_count": len(manual_tasks),
                "suggestions": result.text,
                "timestamp": None
            }
        except Exception as e:
            logger.error(f"Error suggesting automation: {e}")
            return {
                "status": "error",
                "suggestions": f"Failed to generate suggestions: {str(e)}",
                "timestamp": None
            }
    
    @staticmethod
    async def troubleshoot_performance(
        ctx: Context,
        service_metrics: Dict[str, Any],
        issue_description: str
    ) -> Dict[str, Any]:
        """
        Troubleshoot AWS service performance issues.
        
        Args:
            ctx: MCP context for sampling
            service_metrics: Performance metrics data
            issue_description: Description of the performance problem
            
        Returns:
            Troubleshooting steps and recommendations
        """
        metrics_summary = json.dumps(service_metrics, indent=2)
        
        prompt = f"""Troubleshoot this AWS performance issue and provide solutions.

Issue Description: {issue_description}

Service Metrics:
{metrics_summary}

Please provide:
1. Issue Analysis: What the metrics indicate
2. Root Causes: Likely causes ranked by probability
3. Diagnostic Steps: Additional checks to perform
4. Solutions: Specific fixes for each potential cause
5. Performance Tuning: Configuration changes to improve performance
6. Monitoring Setup: Alerts to prevent future issues

Be specific with AWS service configurations and CloudWatch metrics."""

        try:
            result = await ctx.sample(prompt)
            
            return {
                "status": "success",
                "issue": issue_description,
                "troubleshooting": result.text,
                "metrics_analyzed": len(service_metrics),
                "timestamp": None
            }
        except Exception as e:
            logger.error(f"Error troubleshooting performance: {e}")
            return {
                "status": "error",
                "issue": issue_description,
                "troubleshooting": f"Failed to troubleshoot: {str(e)}",
                "timestamp": None
            }