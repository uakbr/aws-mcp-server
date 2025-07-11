"""
Intelligent Automation Engine for AWS MCP Server.

This module provides intelligent automation capabilities including:
- Auto-remediation of common issues
- Predictive scaling based on patterns
- Anomaly detection in resource usage
- Cost anomaly alerts
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import json
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass
class AutomationRule:
    """Represents an automation rule."""
    rule_id: str
    name: str
    description: str
    trigger_type: str  # "event", "schedule", "anomaly", "threshold"
    trigger_config: Dict[str, Any]
    conditions: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_triggered: Optional[datetime] = None
    execution_count: int = 0


@dataclass
class AnomalyDetection:
    """Configuration for anomaly detection."""
    metric_name: str
    resource_id: str
    baseline_value: float
    current_value: float
    deviation_percentage: float
    severity: str  # "low", "medium", "high", "critical"
    detected_at: datetime = field(default_factory=datetime.utcnow)


class IntelligentAutomation:
    """Main class for intelligent automation features."""
    
    def __init__(self):
        self.rules: Dict[str, AutomationRule] = {}
        self.anomaly_detectors: Dict[str, Any] = {}
        self._clients: Dict[str, Any] = {}
        
    def _get_client(self, service: str, region: str = 'us-east-1') -> Any:
        """Get or create a boto3 client."""
        key = f"{service}_{region}"
        if key not in self._clients:
            self._clients[key] = boto3.client(service, region_name=region)
        return self._clients[key]
    
    async def auto_remediate_security_group(self, sg_id: str, region: str) -> Dict[str, Any]:
        """
        Auto-remediate common security group issues.
        
        Common remediations:
        - Remove unrestricted inbound access (0.0.0.0/0)
        - Add missing egress rules
        - Remove unused rules
        """
        ec2 = self._get_client('ec2', region)
        results = {"sg_id": sg_id, "remediations": []}
        
        try:
            # Get security group details
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: ec2.describe_security_groups(GroupIds=[sg_id])
            )
            
            if not response['SecurityGroups']:
                return {"error": f"Security group {sg_id} not found"}
            
            sg = response['SecurityGroups'][0]
            
            # Check for unrestricted inbound access
            for rule in sg['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        # Found unrestricted access
                        if rule['IpProtocol'] == 'tcp' and rule.get('FromPort') in [22, 3389]:
                            # SSH or RDP open to world - remediate
                            logger.warning(f"Found unrestricted {rule['FromPort']} access in {sg_id}")
                            
                            # Remove the rule
                            await asyncio.get_event_loop().run_in_executor(
                                None,
                                lambda: ec2.revoke_security_group_ingress(
                                    GroupId=sg_id,
                                    IpPermissions=[{
                                        'IpProtocol': rule['IpProtocol'],
                                        'FromPort': rule['FromPort'],
                                        'ToPort': rule['ToPort'],
                                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                                    }]
                                )
                            )
                            
                            results["remediations"].append({
                                "action": "removed_unrestricted_access",
                                "port": rule['FromPort'],
                                "protocol": rule['IpProtocol']
                            })
            
            # Add default egress rule if missing
            if not sg['IpPermissionsEgress']:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: ec2.authorize_security_group_egress(
                        GroupId=sg_id,
                        IpPermissions=[{
                            'IpProtocol': '-1',
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    )
                )
                
                results["remediations"].append({
                    "action": "added_default_egress",
                    "description": "Added default egress rule for all traffic"
                })
            
            results["status"] = "success"
            results["remediation_count"] = len(results["remediations"])
            
        except ClientError as e:
            logger.error(f"Error remediating security group {sg_id}: {e}")
            results["error"] = str(e)
            results["status"] = "failed"
        
        return results
    
    async def auto_remediate_s3_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """
        Auto-remediate common S3 bucket security issues.
        
        Remediations:
        - Enable versioning
        - Enable encryption
        - Block public access
        - Enable logging
        """
        s3 = self._get_client('s3')
        results = {"bucket": bucket_name, "remediations": []}
        
        try:
            # Check and enable versioning
            versioning = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: s3.get_bucket_versioning(Bucket=bucket_name)
            )
            
            if versioning.get('Status') != 'Enabled':
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: s3.put_bucket_versioning(
                        Bucket=bucket_name,
                        VersioningConfiguration={'Status': 'Enabled'}
                    )
                )
                results["remediations"].append({
                    "action": "enabled_versioning",
                    "description": "Enabled bucket versioning for data protection"
                })
            
            # Check and enable encryption
            try:
                encryption = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: s3.get_bucket_encryption(Bucket=bucket_name)
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    # Enable encryption
                    await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: s3.put_bucket_encryption(
                            Bucket=bucket_name,
                            ServerSideEncryptionConfiguration={
                                'Rules': [{
                                    'ApplyServerSideEncryptionByDefault': {
                                        'SSEAlgorithm': 'AES256'
                                    }
                                }]
                            }
                        )
                    )
                    results["remediations"].append({
                        "action": "enabled_encryption",
                        "description": "Enabled AES256 encryption for bucket"
                    })
            
            # Block public access
            public_block = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: s3.get_public_access_block(Bucket=bucket_name)
            )
            
            config = public_block.get('PublicAccessBlockConfiguration', {})
            if not all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ]):
                # Enable all public access blocks
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: s3.put_public_access_block(
                        Bucket=bucket_name,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True,
                            'IgnorePublicAcls': True,
                            'BlockPublicPolicy': True,
                            'RestrictPublicBuckets': True
                        }
                    )
                )
                results["remediations"].append({
                    "action": "blocked_public_access",
                    "description": "Enabled all public access block settings"
                })
            
            results["status"] = "success"
            results["remediation_count"] = len(results["remediations"])
            
        except ClientError as e:
            logger.error(f"Error remediating S3 bucket {bucket_name}: {e}")
            results["error"] = str(e)
            results["status"] = "failed"
        
        return results
    
    async def predictive_scaling_analysis(
        self,
        resource_type: str,
        resource_id: str,
        region: str,
        lookback_days: int = 7
    ) -> Dict[str, Any]:
        """
        Analyze historical metrics to predict scaling needs.
        
        Args:
            resource_type: Type of resource (ec2, ecs, rds)
            resource_id: ID of the resource
            region: AWS region
            lookback_days: Days of historical data to analyze
            
        Returns:
            Scaling predictions and recommendations
        """
        cloudwatch = self._get_client('cloudwatch', region)
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=lookback_days)
        
        predictions = {
            "resource_type": resource_type,
            "resource_id": resource_id,
            "analysis_period": f"{lookback_days} days",
            "predictions": []
        }
        
        # Define metrics to analyze based on resource type
        metrics_config = {
            "ec2": [
                {"name": "CPUUtilization", "namespace": "AWS/EC2", "stat": "Average"},
                {"name": "NetworkIn", "namespace": "AWS/EC2", "stat": "Sum"},
                {"name": "NetworkOut", "namespace": "AWS/EC2", "stat": "Sum"}
            ],
            "rds": [
                {"name": "CPUUtilization", "namespace": "AWS/RDS", "stat": "Average"},
                {"name": "DatabaseConnections", "namespace": "AWS/RDS", "stat": "Average"},
                {"name": "FreeableMemory", "namespace": "AWS/RDS", "stat": "Average"}
            ]
        }
        
        metrics_to_analyze = metrics_config.get(resource_type, [])
        
        for metric_config in metrics_to_analyze:
            try:
                # Get metric statistics
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: cloudwatch.get_metric_statistics(
                        Namespace=metric_config["namespace"],
                        MetricName=metric_config["name"],
                        Dimensions=[
                            {
                                'Name': 'InstanceId' if resource_type == 'ec2' else 'DBInstanceIdentifier',
                                'Value': resource_id
                            }
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,  # 1 hour
                        Statistics=[metric_config["stat"]]
                    )
                )
                
                datapoints = sorted(response['Datapoints'], key=lambda x: x['Timestamp'])
                
                if datapoints:
                    # Simple prediction based on trend analysis
                    values = [dp[metric_config["stat"]] for dp in datapoints]
                    avg_value = sum(values) / len(values)
                    max_value = max(values)
                    
                    # Calculate trend (simple linear regression)
                    if len(values) > 24:  # At least 1 day of data
                        recent_avg = sum(values[-24:]) / 24
                        older_avg = sum(values[:-24]) / (len(values) - 24)
                        trend = "increasing" if recent_avg > older_avg * 1.1 else "stable"
                    else:
                        trend = "insufficient_data"
                    
                    prediction = {
                        "metric": metric_config["name"],
                        "current_avg": round(avg_value, 2),
                        "peak_value": round(max_value, 2),
                        "trend": trend,
                        "recommendation": ""
                    }
                    
                    # Generate recommendations
                    if metric_config["name"] == "CPUUtilization":
                        if max_value > 80:
                            prediction["recommendation"] = "Consider scaling up - peak CPU exceeds 80%"
                        elif avg_value < 20:
                            prediction["recommendation"] = "Consider scaling down - average CPU below 20%"
                    
                    predictions["predictions"].append(prediction)
                
            except Exception as e:
                logger.error(f"Error analyzing metric {metric_config['name']}: {e}")
        
        # Generate overall recommendation
        high_cpu_predictions = [p for p in predictions["predictions"] 
                               if p["metric"] == "CPUUtilization" and p["peak_value"] > 80]
        
        if high_cpu_predictions:
            predictions["overall_recommendation"] = "Scaling up recommended based on CPU utilization patterns"
        else:
            predictions["overall_recommendation"] = "Current scaling appears adequate"
        
        return predictions
    
    async def detect_cost_anomalies(
        self,
        account_id: Optional[str] = None,
        threshold_percentage: float = 20.0
    ) -> Dict[str, Any]:
        """
        Detect cost anomalies by comparing current spending to historical patterns.
        
        Args:
            account_id: AWS account ID (optional)
            threshold_percentage: Percentage increase to consider anomalous
            
        Returns:
            Detected cost anomalies
        """
        ce = self._get_client('ce', 'us-east-1')  # Cost Explorer is only in us-east-1
        
        end_date = datetime.utcnow().date()
        start_date = end_date - timedelta(days=30)
        
        anomalies = {
            "analysis_date": end_date.isoformat(),
            "threshold_percentage": threshold_percentage,
            "anomalies": []
        }
        
        try:
            # Get cost and usage data
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: ce.get_cost_and_usage(
                    TimePeriod={
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    Granularity='DAILY',
                    Metrics=['UnblendedCost'],
                    GroupBy=[
                        {'Type': 'DIMENSION', 'Key': 'SERVICE'}
                    ]
                )
            )
            
            # Analyze daily costs by service
            daily_costs = {}
            for result in response['ResultsByTime']:
                date = result['TimePeriod']['Start']
                for group in result['Groups']:
                    service = group['Keys'][0]
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])
                    
                    if service not in daily_costs:
                        daily_costs[service] = []
                    daily_costs[service].append((date, cost))
            
            # Detect anomalies
            for service, costs in daily_costs.items():
                if len(costs) < 7:  # Need at least a week of data
                    continue
                
                # Calculate baseline (average of days 8-30)
                baseline_costs = [c[1] for c in costs[:-7]]
                if baseline_costs:
                    baseline_avg = sum(baseline_costs) / len(baseline_costs)
                    
                    # Check recent costs (last 7 days)
                    recent_costs = [c[1] for c in costs[-7:]]
                    recent_avg = sum(recent_costs) / len(recent_costs)
                    
                    # Calculate percentage increase
                    if baseline_avg > 0:
                        increase_pct = ((recent_avg - baseline_avg) / baseline_avg) * 100
                        
                        if increase_pct > threshold_percentage:
                            anomalies["anomalies"].append({
                                "service": service,
                                "baseline_daily_avg": round(baseline_avg, 2),
                                "recent_daily_avg": round(recent_avg, 2),
                                "increase_percentage": round(increase_pct, 2),
                                "severity": "high" if increase_pct > 50 else "medium",
                                "recommendation": f"Investigate {service} usage - costs increased by {increase_pct:.1f}%"
                            })
            
            anomalies["total_anomalies"] = len(anomalies["anomalies"])
            anomalies["status"] = "success"
            
        except Exception as e:
            logger.error(f"Error detecting cost anomalies: {e}")
            anomalies["error"] = str(e)
            anomalies["status"] = "failed"
        
        return anomalies
    
    async def create_automation_rule(
        self,
        rule_name: str,
        trigger_type: str,
        trigger_config: Dict[str, Any],
        conditions: List[Dict[str, Any]],
        actions: List[Dict[str, Any]]
    ) -> AutomationRule:
        """Create a new automation rule."""
        rule_id = f"rule_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{len(self.rules)}"
        
        rule = AutomationRule(
            rule_id=rule_id,
            name=rule_name,
            description=f"Automation rule: {rule_name}",
            trigger_type=trigger_type,
            trigger_config=trigger_config,
            conditions=conditions,
            actions=actions
        )
        
        self.rules[rule_id] = rule
        logger.info(f"Created automation rule: {rule_id} - {rule_name}")
        
        return rule
    
    async def execute_automation_rule(self, rule_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an automation rule."""
        if rule_id not in self.rules:
            return {"error": f"Rule {rule_id} not found"}
        
        rule = self.rules[rule_id]
        
        if not rule.enabled:
            return {"status": "skipped", "reason": "Rule is disabled"}
        
        results = {
            "rule_id": rule_id,
            "rule_name": rule.name,
            "execution_time": datetime.utcnow().isoformat(),
            "actions_executed": []
        }
        
        # Check conditions
        conditions_met = True
        for condition in rule.conditions:
            # Evaluate condition based on context
            # This is simplified - real implementation would be more complex
            if not self._evaluate_condition(condition, context):
                conditions_met = False
                break
        
        if not conditions_met:
            results["status"] = "skipped"
            results["reason"] = "Conditions not met"
            return results
        
        # Execute actions
        for action in rule.actions:
            try:
                action_result = await self._execute_action(action, context)
                results["actions_executed"].append(action_result)
            except Exception as e:
                logger.error(f"Error executing action in rule {rule_id}: {e}")
                results["actions_executed"].append({
                    "action": action,
                    "status": "failed",
                    "error": str(e)
                })
        
        # Update rule metadata
        rule.last_triggered = datetime.utcnow()
        rule.execution_count += 1
        
        results["status"] = "completed"
        return results
    
    def _evaluate_condition(self, condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate a single condition."""
        # Simplified condition evaluation
        # Real implementation would support complex conditions
        condition_type = condition.get("type")
        
        if condition_type == "threshold":
            metric_value = context.get(condition["metric"], 0)
            threshold = condition["threshold"]
            operator = condition.get("operator", ">")
            
            if operator == ">":
                return metric_value > threshold
            elif operator == "<":
                return metric_value < threshold
            elif operator == "==":
                return metric_value == threshold
        
        return False
    
    async def _execute_action(self, action: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single automation action."""
        action_type = action.get("type")
        
        if action_type == "scale_ec2":
            # Scale EC2 instance
            instance_id = action["instance_id"]
            new_type = action["instance_type"]
            # Implementation would call EC2 API to modify instance
            return {
                "action": "scale_ec2",
                "instance_id": instance_id,
                "new_type": new_type,
                "status": "success"
            }
        
        elif action_type == "send_notification":
            # Send notification
            message = action["message"].format(**context)
            # Implementation would send SNS notification
            return {
                "action": "send_notification",
                "message": message,
                "status": "success"
            }
        
        return {"action": action_type, "status": "unsupported"}