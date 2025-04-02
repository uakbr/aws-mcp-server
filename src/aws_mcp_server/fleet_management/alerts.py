"""
Alerting System for AWS Fleet Management.

This module provides capabilities to define and evaluate alerts based on
metric thresholds, along with routing and delivery mechanisms.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .monitoring import MetricData

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Severity level of an alert."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    """Status of an alert definition."""
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"


class AlertState(Enum):
    """Current state of an alert."""
    OK = "ok"
    ALERTING = "alerting"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class ComparisonOperator(Enum):
    """Comparison operators for alert conditions."""
    GREATER_THAN = ">"
    GREATER_THAN_OR_EQUAL = ">="
    LESS_THAN = "<"
    LESS_THAN_OR_EQUAL = "<="
    EQUAL = "=="
    NOT_EQUAL = "!="


@dataclass
class AlertCondition:
    """Condition that triggers an alert."""
    metric_id: str
    operator: ComparisonOperator
    threshold: float
    evaluation_periods: int = 1  # Number of consecutive periods to evaluate
    datapoints_to_alarm: int = 1  # Number of datapoints that must be breaching
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "metric_id": self.metric_id,
            "operator": self.operator.value,
            "threshold": self.threshold,
            "evaluation_periods": self.evaluation_periods,
            "datapoints_to_alarm": self.datapoints_to_alarm
        }


@dataclass
class AlertTarget:
    """Target for alert notifications."""
    id: str
    type: str  # email, sns, webhook, etc.
    destination: str  # Email address, SNS ARN, URL, etc.
    format: str = "json"  # json, text, html
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "type": self.type,
            "destination": self.destination,
            "format": self.format
        }


@dataclass
class AlertDefinition:
    """Definition of an alert."""
    id: str
    name: str
    description: str
    conditions: List[AlertCondition]
    targets: List[AlertTarget]
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.ACTIVE
    resource_filters: Dict[str, List[str]] = field(default_factory=dict)
    account_filters: List[str] = field(default_factory=list)
    region_filters: List[str] = field(default_factory=list)
    auto_resolve: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "conditions": [condition.to_dict() for condition in self.conditions],
            "targets": [target.to_dict() for target in self.targets],
            "severity": self.severity.value,
            "status": self.status.value,
            "resource_filters": self.resource_filters,
            "account_filters": self.account_filters,
            "region_filters": self.region_filters,
            "auto_resolve": self.auto_resolve,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


@dataclass
class AlertInstance:
    """An instance of an alert that has triggered."""
    id: str
    alert_definition_id: str
    resource_id: str
    account_id: str
    region: str
    triggered_condition: AlertCondition
    metric_value: float
    state: AlertState
    severity: AlertSeverity
    first_triggered_at: datetime
    last_triggered_at: datetime
    last_updated_at: datetime
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    notification_sent: bool = False
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "alert_definition_id": self.alert_definition_id,
            "resource_id": self.resource_id,
            "account_id": self.account_id,
            "region": self.region,
            "triggered_condition": self.triggered_condition.to_dict(),
            "metric_value": self.metric_value,
            "state": self.state.value,
            "severity": self.severity.value,
            "first_triggered_at": self.first_triggered_at.isoformat(),
            "last_triggered_at": self.last_triggered_at.isoformat(),
            "last_updated_at": self.last_updated_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "notification_sent": self.notification_sent,
            "correlation_id": self.correlation_id
        }


class AlertRegistry:
    """Registry for managing alert definitions."""
    
    _alerts: Dict[str, AlertDefinition] = {}
    
    @classmethod
    def register_alert(cls, alert: AlertDefinition) -> None:
        """Register an alert definition."""
        cls._alerts[alert.id] = alert
    
    @classmethod
    def get_alert(cls, alert_id: str) -> Optional[AlertDefinition]:
        """Get an alert definition by ID."""
        return cls._alerts.get(alert_id)
    
    @classmethod
    def get_alerts_by_severity(cls, severity: AlertSeverity) -> List[AlertDefinition]:
        """Get all alert definitions of a specific severity."""
        return [
            alert for alert in cls._alerts.values()
            if alert.severity == severity and alert.status == AlertStatus.ACTIVE
        ]
    
    @classmethod
    def get_alerts_by_metric(cls, metric_id: str) -> List[AlertDefinition]:
        """Get all alert definitions for a specific metric."""
        return [
            alert for alert in cls._alerts.values()
            if any(condition.metric_id == metric_id for condition in alert.conditions)
            and alert.status == AlertStatus.ACTIVE
        ]
    
    @classmethod
    def delete_alert(cls, alert_id: str) -> bool:
        """Mark an alert as archived."""
        alert = cls.get_alert(alert_id)
        if not alert:
            return False
        
        alert.status = AlertStatus.ARCHIVED
        alert.updated_at = datetime.now()
        return True


class AlertInstanceRegistry:
    """Registry for managing alert instances."""
    
    _instances: Dict[str, AlertInstance] = {}
    
    @classmethod
    def register_instance(cls, instance: AlertInstance) -> None:
        """Register an alert instance."""
        cls._instances[instance.id] = instance
    
    @classmethod
    def get_instance(cls, instance_id: str) -> Optional[AlertInstance]:
        """Get an alert instance by ID."""
        return cls._instances.get(instance_id)
    
    @classmethod
    def get_instances_by_alert(cls, alert_id: str) -> List[AlertInstance]:
        """Get all instances for a specific alert definition."""
        return [
            instance for instance in cls._instances.values()
            if instance.alert_definition_id == alert_id
        ]
    
    @classmethod
    def get_instances_by_resource(cls, resource_id: str) -> List[AlertInstance]:
        """Get all instances for a specific resource."""
        return [
            instance for instance in cls._instances.values()
            if instance.resource_id == resource_id
        ]
    
    @classmethod
    def get_active_instances(cls) -> List[AlertInstance]:
        """Get all active alert instances."""
        return [
            instance for instance in cls._instances.values()
            if instance.state == AlertState.ALERTING
        ]
    
    @classmethod
    def get_instance_key(cls, alert_id: str, resource_id: str, account_id: str, region: str) -> Optional[str]:
        """Get the instance ID for a specific alert and resource."""
        for instance_id, instance in cls._instances.items():
            if (instance.alert_definition_id == alert_id and
                instance.resource_id == resource_id and
                instance.account_id == account_id and
                instance.region == region):
                return instance_id
        return None


class NotificationSender:
    """Sender for alert notifications."""
    
    @classmethod
    async def send_notification(cls, instance: AlertInstance, alert: AlertDefinition) -> bool:
        """
        Send a notification for an alert instance.
        
        Args:
            instance: Alert instance
            alert: Alert definition
            
        Returns:
            True if notification was sent successfully
        """
        success = True
        
        for target in alert.targets:
            try:
                if target.type == "email":
                    success = success and await cls._send_email(instance, alert, target)
                elif target.type == "sns":
                    success = success and await cls._send_sns(instance, alert, target)
                elif target.type == "webhook":
                    success = success and await cls._send_webhook(instance, alert, target)
                else:
                    logger.warning(f"Unsupported notification target type: {target.type}")
                    success = False
            except Exception as e:
                logger.error(f"Error sending notification to {target.type} {target.destination}: {e}")
                success = False
        
        return success
    
    @classmethod
    async def _send_email(cls, instance: AlertInstance, alert: AlertDefinition, target: AlertTarget) -> bool:
        """Send an email notification."""
        # In a real implementation, we would use a library like smtplib
        # For now, we'll just log it
        logger.info(f"Sending email to {target.destination} for alert {alert.name} on resource {instance.resource_id}")
        return True
    
    @classmethod
    async def _send_sns(cls, instance: AlertInstance, alert: AlertDefinition, target: AlertTarget) -> bool:
        """Send an SNS notification."""
        # In a real implementation, we would use boto3
        # For now, we'll just log it
        logger.info(f"Sending SNS to {target.destination} for alert {alert.name} on resource {instance.resource_id}")
        return True
    
    @classmethod
    async def _send_webhook(cls, instance: AlertInstance, alert: AlertDefinition, target: AlertTarget) -> bool:
        """Send a webhook notification."""
        # In a real implementation, we would use a library like aiohttp
        # For now, we'll just log it
        logger.info(f"Sending webhook to {target.destination} for alert {alert.name} on resource {instance.resource_id}")
        return True


class AlertCorrelation:
    """Correlator for related alerts."""
    
    _correlation_groups: Dict[str, List[str]] = {}  # Correlation ID -> List of alert instance IDs
    
    @classmethod
    def correlate_alerts(cls, new_instance: AlertInstance) -> None:
        """
        Correlate a new alert instance with existing ones.
        
        Args:
            new_instance: New alert instance
        """
        # Simple correlation strategy: group by resource and time proximity
        # In a real implementation, more sophisticated strategies would be used
        
        # Find active instances for the same resource
        resource_instances = AlertInstanceRegistry.get_instances_by_resource(new_instance.resource_id)
        active_instances = [
            instance for instance in resource_instances
            if instance.state == AlertState.ALERTING and
            instance.id != new_instance.id and
            (datetime.now() - instance.last_triggered_at).total_seconds() < 300  # Within 5 minutes
        ]
        
        if not active_instances:
            # No correlation found, create a new group
            correlation_id = f"corr-{uuid.uuid4()}"
            cls._correlation_groups[correlation_id] = [new_instance.id]
            new_instance.correlation_id = correlation_id
        else:
            # Use the correlation ID of the first correlated alert
            correlated_instance = active_instances[0]
            correlation_id = correlated_instance.correlation_id
            
            if correlation_id:
                # Add to existing correlation group
                if correlation_id in cls._correlation_groups:
                    cls._correlation_groups[correlation_id].append(new_instance.id)
                else:
                    cls._correlation_groups[correlation_id] = [new_instance.id]
                
                new_instance.correlation_id = correlation_id
            else:
                # Create a new correlation group for both
                correlation_id = f"corr-{uuid.uuid4()}"
                cls._correlation_groups[correlation_id] = [new_instance.id, correlated_instance.id]
                new_instance.correlation_id = correlation_id
                correlated_instance.correlation_id = correlation_id
    
    @classmethod
    def get_correlated_alerts(cls, correlation_id: str) -> List[AlertInstance]:
        """
        Get all alert instances in a correlation group.
        
        Args:
            correlation_id: Correlation group ID
            
        Returns:
            List of alert instances in the group
        """
        if correlation_id not in cls._correlation_groups:
            return []
        
        instance_ids = cls._correlation_groups[correlation_id]
        return [
            AlertInstanceRegistry.get_instance(instance_id) 
            for instance_id in instance_ids
            if AlertInstanceRegistry.get_instance(instance_id) is not None
        ]


class AlertEvaluator:
    """Evaluator for alert conditions."""
    
    _evaluation_history: Dict[str, List[Tuple[datetime, bool]]] = {}
    # Key format: alert_id:resource_id:condition_index:account_id:region
    
    @classmethod
    def evaluate_condition(cls, condition: AlertCondition, value: float) -> bool:
        """
        Evaluate if a condition is breached.
        
        Args:
            condition: Alert condition
            value: Current metric value
            
        Returns:
            True if condition is breached
        """
        if condition.operator == ComparisonOperator.GREATER_THAN:
            return value > condition.threshold
        elif condition.operator == ComparisonOperator.GREATER_THAN_OR_EQUAL:
            return value >= condition.threshold
        elif condition.operator == ComparisonOperator.LESS_THAN:
            return value < condition.threshold
        elif condition.operator == ComparisonOperator.LESS_THAN_OR_EQUAL:
            return value <= condition.threshold
        elif condition.operator == ComparisonOperator.EQUAL:
            return value == condition.threshold
        elif condition.operator == ComparisonOperator.NOT_EQUAL:
            return value != condition.threshold
        else:
            logger.warning(f"Unknown operator: {condition.operator}")
            return False
    
    @classmethod
    async def evaluate_alert(
        cls, alert: AlertDefinition, metric_data: MetricData
    ) -> Optional[AlertInstance]:
        """
        Evaluate an alert definition against metric data.
        
        Args:
            alert: Alert definition to evaluate
            metric_data: Metric data to evaluate against
            
        Returns:
            AlertInstance if alert is triggered, None otherwise
        """
        if not metric_data.values:
            return None
        
        # Check if resource matches filters
        resource_type = metric_data.resource_id.split("-")[0]  # Simple extraction of type from ID
        if alert.resource_filters and resource_type in alert.resource_filters:
            if metric_data.resource_id not in alert.resource_filters[resource_type]:
                return None
        
        # Check if account matches filters
        if alert.account_filters and metric_data.account_id not in alert.account_filters:
            return None
        
        # Check if region matches filters
        if alert.region_filters and metric_data.region not in alert.region_filters:
            return None
        
        # Evaluate each condition
        for i, condition in enumerate(alert.conditions):
            if condition.metric_id != metric_data.metric_id:
                continue
            
            # Get most recent value
            current_value = metric_data.values[-1].value
            
            # Check if condition is breached
            is_breached = cls.evaluate_condition(condition, current_value)
            
            # Update evaluation history
            history_key = f"{alert.id}:{metric_data.resource_id}:{i}:{metric_data.account_id}:{metric_data.region}"
            
            if history_key not in cls._evaluation_history:
                cls._evaluation_history[history_key] = []
            
            history = cls._evaluation_history[history_key]
            history.append((datetime.now(), is_breached))
            
            # Trim history to keep only what's needed for evaluation
            max_history = max(condition.evaluation_periods, 10)  # Keep at least 10 for analysis
            if len(history) > max_history:
                cls._evaluation_history[history_key] = history[-max_history:]
            
            # Check if alert should trigger based on evaluation periods
            history = cls._evaluation_history[history_key]
            recent_history = history[-condition.evaluation_periods:]
            
            # Count breaches in recent history
            breach_count = sum(1 for _, breached in recent_history if breached)
            
            if breach_count >= condition.datapoints_to_alarm:
                # Alert is triggered
                instance_id = AlertInstanceRegistry.get_instance_key(
                    alert.id, metric_data.resource_id, metric_data.account_id, metric_data.region
                )
                
                now = datetime.now()
                
                if instance_id:
                    # Update existing instance
                    instance = AlertInstanceRegistry.get_instance(instance_id)
                    if instance and instance.state in [AlertState.ALERTING, AlertState.ACKNOWLEDGED]:
                        instance.last_triggered_at = now
                        instance.last_updated_at = now
                        instance.metric_value = current_value
                        return instance
                
                # Create new instance
                instance_id = f"alert-instance-{uuid.uuid4()}"
                instance = AlertInstance(
                    id=instance_id,
                    alert_definition_id=alert.id,
                    resource_id=metric_data.resource_id,
                    account_id=metric_data.account_id,
                    region=metric_data.region,
                    triggered_condition=condition,
                    metric_value=current_value,
                    state=AlertState.ALERTING,
                    severity=alert.severity,
                    first_triggered_at=now,
                    last_triggered_at=now,
                    last_updated_at=now
                )
                
                # Register the instance
                AlertInstanceRegistry.register_instance(instance)
                
                # Correlate with other alerts
                AlertCorrelation.correlate_alerts(instance)
                
                return instance
        
        # No conditions triggered, check if we need to auto-resolve
        if alert.auto_resolve:
            instance_id = AlertInstanceRegistry.get_instance_key(
                alert.id, metric_data.resource_id, metric_data.account_id, metric_data.region
            )
            
            if instance_id:
                instance = AlertInstanceRegistry.get_instance(instance_id)
                if instance and instance.state == AlertState.ALERTING:
                    # Auto-resolve the alert
                    instance.state = AlertState.RESOLVED
                    instance.resolved_at = datetime.now()
                    instance.last_updated_at = datetime.now()
                    return instance
        
        return None


class AlertManager:
    """Manager for handling alerts across the fleet."""
    
    @classmethod
    def create_alert(
        cls, name: str, description: str, conditions: List[AlertCondition],
        targets: List[AlertTarget], severity: AlertSeverity,
        resource_filters: Optional[Dict[str, List[str]]] = None,
        account_filters: Optional[List[str]] = None,
        region_filters: Optional[List[str]] = None,
        auto_resolve: bool = True
    ) -> AlertDefinition:
        """Create a new alert definition."""
        alert_id = f"alert-{uuid.uuid4()}"
        alert = AlertDefinition(
            id=alert_id,
            name=name,
            description=description,
            conditions=conditions,
            targets=targets,
            severity=severity,
            resource_filters=resource_filters or {},
            account_filters=account_filters or [],
            region_filters=region_filters or [],
            auto_resolve=auto_resolve
        )
        
        AlertRegistry.register_alert(alert)
        return alert
    
    @classmethod
    def create_alert_target(
        cls, type: str, destination: str, format: str = "json"
    ) -> AlertTarget:
        """Create a new alert target."""
        target_id = f"target-{uuid.uuid4()}"
        return AlertTarget(
            id=target_id,
            type=type,
            destination=destination,
            format=format
        )
    
    @classmethod
    def create_alert_condition(
        cls, metric_id: str, operator: ComparisonOperator, threshold: float,
        evaluation_periods: int = 1, datapoints_to_alarm: int = 1
    ) -> AlertCondition:
        """Create a new alert condition."""
        return AlertCondition(
            metric_id=metric_id,
            operator=operator,
            threshold=threshold,
            evaluation_periods=evaluation_periods,
            datapoints_to_alarm=datapoints_to_alarm
        )
    
    @classmethod
    async def process_metric_data(cls, metric_data: MetricData) -> List[AlertInstance]:
        """
        Process metric data and trigger alerts if needed.
        
        Args:
            metric_data: Metric data to evaluate
            
        Returns:
            List of triggered alert instances
        """
        triggered_instances = []
        
        # Get all alerts for this metric
        alerts = AlertRegistry.get_alerts_by_metric(metric_data.metric_id)
        
        for alert in alerts:
            instance = await AlertEvaluator.evaluate_alert(alert, metric_data)
            
            if instance:
                triggered_instances.append(instance)
                
                # Send notification if needed
                if instance.state == AlertState.ALERTING and not instance.notification_sent:
                    success = await NotificationSender.send_notification(instance, alert)
                    instance.notification_sent = success
        
        return triggered_instances
    
    @classmethod
    def acknowledge_alert(cls, instance_id: str, user: str) -> bool:
        """
        Acknowledge an alert instance.
        
        Args:
            instance_id: ID of the alert instance
            user: User acknowledging the alert
            
        Returns:
            True if alert was acknowledged
        """
        instance = AlertInstanceRegistry.get_instance(instance_id)
        if not instance or instance.state != AlertState.ALERTING:
            return False
        
        instance.state = AlertState.ACKNOWLEDGED
        instance.acknowledged_at = datetime.now()
        instance.acknowledged_by = user
        instance.last_updated_at = datetime.now()
        return True
    
    @classmethod
    def resolve_alert(cls, instance_id: str) -> bool:
        """
        Manually resolve an alert instance.
        
        Args:
            instance_id: ID of the alert instance
            
        Returns:
            True if alert was resolved
        """
        instance = AlertInstanceRegistry.get_instance(instance_id)
        if not instance or instance.state == AlertState.RESOLVED:
            return False
        
        instance.state = AlertState.RESOLVED
        instance.resolved_at = datetime.now()
        instance.last_updated_at = datetime.now()
        return True
    
    @classmethod
    def get_active_alerts(cls) -> List[Dict[str, Any]]:
        """
        Get all active alert instances with alert definition details.
        
        Returns:
            List of active alerts with details
        """
        active_instances = AlertInstanceRegistry.get_active_instances()
        result = []
        
        for instance in active_instances:
            alert = AlertRegistry.get_alert(instance.alert_definition_id)
            if not alert:
                continue
            
            # Get correlated alerts
            correlated_alerts = []
            if instance.correlation_id:
                correlated = AlertCorrelation.get_correlated_alerts(instance.correlation_id)
                correlated_alerts = [
                    {
                        "id": corr.id,
                        "alert_name": (AlertRegistry.get_alert(corr.alert_definition_id).name 
                                      if AlertRegistry.get_alert(corr.alert_definition_id) 
                                      else "Unknown"),
                        "resource_id": corr.resource_id,
                        "triggered_at": corr.last_triggered_at.isoformat()
                    }
                    for corr in correlated
                    if corr.id != instance.id
                ]
            
            result.append({
                "instance": instance.to_dict(),
                "alert": {
                    "id": alert.id,
                    "name": alert.name,
                    "description": alert.description,
                    "severity": alert.severity.value
                },
                "correlated_alerts": correlated_alerts
            })
        
        return result


def initialize_alerts(metric_ids: List[str] = None):
    """Initialize the alerting system with default alert definitions."""
    if not metric_ids or len(metric_ids) < 2:
        logger.warning("No metrics provided for alert initialization")
        return []
    
    # Create alert targets
    email_target = AlertManager.create_alert_target(
        type="email",
        destination="admin@example.com"
    )
    
    sns_target = AlertManager.create_alert_target(
        type="sns",
        destination="arn:aws:sns:us-east-1:123456789012:fleet-alerts"
    )
    
    # Create CPU alert
    cpu_condition = AlertManager.create_alert_condition(
        metric_id=metric_ids[0],  # CPU metric
        operator=ComparisonOperator.GREATER_THAN,
        threshold=80.0,
        evaluation_periods=3,
        datapoints_to_alarm=2
    )
    
    cpu_alert = AlertManager.create_alert(
        name="High CPU Utilization",
        description="CPU utilization is above 80% for 2 out of 3 periods",
        conditions=[cpu_condition],
        targets=[email_target, sns_target],
        severity=AlertSeverity.HIGH
    )
    
    # Create memory alert if we have enough metrics
    memory_alert = None
    composite_alert = None
    if len(metric_ids) > 1:
        memory_condition = AlertManager.create_alert_condition(
            metric_id=metric_ids[1],  # Memory metric
            operator=ComparisonOperator.GREATER_THAN,
            threshold=90.0,
            evaluation_periods=3,
            datapoints_to_alarm=2
        )
        
        memory_alert = AlertManager.create_alert(
            name="High Memory Utilization",
            description="Memory utilization is above 90% for 2 out of 3 periods",
            conditions=[memory_condition],
            targets=[email_target, sns_target],
            severity=AlertSeverity.HIGH
        )
        
        # Create composite alert (both CPU and memory)
        composite_alert = AlertManager.create_alert(
            name="System Resource Saturation",
            description="Both CPU and memory utilization are high",
            conditions=[cpu_condition, memory_condition],
            targets=[email_target, sns_target],
            severity=AlertSeverity.CRITICAL
        )
    
    logger.info("Initialized alerting system with default alerts: " +
               f"CPU: {cpu_alert.id}" +
               (f", Memory: {memory_alert.id}" if len(metric_ids) > 1 else "") +
               (f", Composite: {composite_alert.id}" if len(metric_ids) > 1 else ""))
    
    return [cpu_alert.id] + ([memory_alert.id, composite_alert.id] if len(metric_ids) > 1 else []) 