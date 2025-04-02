"""
Monitoring System for AWS Fleet Management.

This module provides capabilities to collect, aggregate, and analyze
metrics across the fleet of AWS resources.
"""

import json
import logging
import asyncio
import uuid
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Union, Set

logger = logging.getLogger(__name__)


class MetricStatus(Enum):
    """Status of a metric collection."""
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"


class MetricType(Enum):
    """Type of metric."""
    CLOUDWATCH = "cloudwatch"
    CUSTOM = "custom"
    COMPOSITE = "composite"


class MetricPriority(Enum):
    """Priority level of a metric."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class MetricDefinition:
    """Definition of a metric to collect."""
    id: str
    name: str
    description: str
    namespace: str
    metric_name: str
    dimensions: Dict[str, str] = field(default_factory=dict)
    statistic: str = "Average"
    period: int = 300  # 5 minutes in seconds
    unit: Optional[str] = None
    metric_type: MetricType = MetricType.CLOUDWATCH
    priority: MetricPriority = MetricPriority.MEDIUM
    status: MetricStatus = MetricStatus.ACTIVE
    retention_days: int = 14
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "namespace": self.namespace,
            "metric_name": self.metric_name,
            "dimensions": self.dimensions,
            "statistic": self.statistic,
            "period": self.period,
            "unit": self.unit,
            "metric_type": self.metric_type.value,
            "priority": self.priority.value,
            "status": self.status.value,
            "retention_days": self.retention_days,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


@dataclass
class MetricValue:
    """A single metric data point."""
    timestamp: datetime
    value: float
    unit: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "value": self.value,
            "unit": self.unit
        }


@dataclass
class MetricData:
    """A collection of metric values for a specific metric."""
    metric_id: str
    resource_id: str
    account_id: str
    region: str
    values: List[MetricValue] = field(default_factory=list)
    
    def add_value(self, value: float, timestamp: Optional[datetime] = None, unit: Optional[str] = None) -> None:
        """Add a metric value."""
        if timestamp is None:
            timestamp = datetime.now()
        
        self.values.append(MetricValue(
            timestamp=timestamp,
            value=value,
            unit=unit
        ))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "metric_id": self.metric_id,
            "resource_id": self.resource_id,
            "account_id": self.account_id,
            "region": self.region,
            "values": [value.to_dict() for value in self.values]
        }


class MetricRegistry:
    """Registry for managing metric definitions."""
    
    _metrics: Dict[str, MetricDefinition] = {}
    
    @classmethod
    def register_metric(cls, metric: MetricDefinition) -> None:
        """Register a metric definition."""
        cls._metrics[metric.id] = metric
    
    @classmethod
    def get_metric(cls, metric_id: str) -> Optional[MetricDefinition]:
        """Get a metric definition by ID."""
        return cls._metrics.get(metric_id)
    
    @classmethod
    def get_metrics_by_type(cls, metric_type: MetricType) -> List[MetricDefinition]:
        """Get all metric definitions of a specific type."""
        return [
            metric for metric in cls._metrics.values()
            if metric.metric_type == metric_type and metric.status == MetricStatus.ACTIVE
        ]
    
    @classmethod
    def get_metrics_by_priority(cls, priority: MetricPriority) -> List[MetricDefinition]:
        """Get all metric definitions of a specific priority."""
        return [
            metric for metric in cls._metrics.values()
            if metric.priority == priority and metric.status == MetricStatus.ACTIVE
        ]
    
    @classmethod
    def delete_metric(cls, metric_id: str) -> bool:
        """Mark a metric as archived."""
        metric = cls.get_metric(metric_id)
        if not metric:
            return False
        
        metric.status = MetricStatus.ARCHIVED
        metric.updated_at = datetime.now()
        return True


class MetricsStore:
    """Store for metric data."""
    
    # In-memory storage for metric data
    # In production, this would use a time-series database
    _data: Dict[str, Dict[str, Dict[str, List[MetricValue]]]] = {}
    # Structure: metric_id -> resource_id -> account_id+region -> values
    
    @classmethod
    def store_metric(cls, metric_data: MetricData) -> None:
        """Store metric data."""
        # Create nested structure if needed
        metric_id = metric_data.metric_id
        resource_id = metric_data.resource_id
        account_region = f"{metric_data.account_id}:{metric_data.region}"
        
        if metric_id not in cls._data:
            cls._data[metric_id] = {}
        
        if resource_id not in cls._data[metric_id]:
            cls._data[metric_id][resource_id] = {}
        
        if account_region not in cls._data[metric_id][resource_id]:
            cls._data[metric_id][resource_id][account_region] = []
        
        # Add values
        cls._data[metric_id][resource_id][account_region].extend(metric_data.values)
        
        # Apply retention policy
        cls._apply_retention(metric_id, resource_id, account_region)
    
    @classmethod
    def _apply_retention(cls, metric_id: str, resource_id: str, account_region: str) -> None:
        """Apply retention policy to stored metric data."""
        metric = MetricRegistry.get_metric(metric_id)
        if not metric:
            return
        
        # Calculate retention threshold
        retention_threshold = datetime.now() - timedelta(days=metric.retention_days)
        
        # Filter values based on retention
        if metric_id in cls._data and resource_id in cls._data[metric_id] and account_region in cls._data[metric_id][resource_id]:
            cls._data[metric_id][resource_id][account_region] = [
                value for value in cls._data[metric_id][resource_id][account_region]
                if value.timestamp >= retention_threshold
            ]
    
    @classmethod
    def get_metric_data(
        cls, metric_id: str, resource_id: Optional[str] = None,
        account_id: Optional[str] = None, region: Optional[str] = None,
        start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> List[MetricData]:
        """Get metric data with optional filtering."""
        result = []
        
        # Check if metric exists
        if metric_id not in cls._data:
            return result
        
        # Filter resources
        resources = [resource_id] if resource_id else list(cls._data[metric_id].keys())
        
        for res_id in resources:
            if res_id not in cls._data[metric_id]:
                continue
            
            # Filter accounts and regions
            account_regions = []
            for ar in cls._data[metric_id][res_id].keys():
                ar_parts = ar.split(":")
                if len(ar_parts) == 2:
                    a_id, reg = ar_parts
                    if (not account_id or a_id == account_id) and (not region or reg == region):
                        account_regions.append(ar)
            
            for ar in account_regions:
                ar_parts = ar.split(":")
                if len(ar_parts) == 2:
                    a_id, reg = ar_parts
                    
                    # Filter values by time range
                    values = cls._data[metric_id][res_id][ar]
                    if start_time or end_time:
                        filtered_values = []
                        for value in values:
                            if (not start_time or value.timestamp >= start_time) and \
                               (not end_time or value.timestamp <= end_time):
                                filtered_values.append(value)
                        values = filtered_values
                    
                    # Create metric data
                    if values:
                        metric_data = MetricData(
                            metric_id=metric_id,
                            resource_id=res_id,
                            account_id=a_id,
                            region=reg,
                            values=values
                        )
                        result.append(metric_data)
        
        return result


class CloudWatchCollector:
    """Collector for CloudWatch metrics."""
    
    @classmethod
    async def collect_metric(cls, metric: MetricDefinition, resource_id: str, 
                          account_id: str, region: str,
                          start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None) -> MetricData:
        """
        Collect metric data from CloudWatch.
        
        Args:
            metric: Metric definition
            resource_id: Resource ID
            account_id: AWS account ID
            region: AWS region
            start_time: Start time for metric data
            end_time: End time for metric data
            
        Returns:
            Collected metric data
        """
        if start_time is None:
            start_time = datetime.now() - timedelta(minutes=15)
        
        if end_time is None:
            end_time = datetime.now()
        
        # Create metric data
        metric_data = MetricData(
            metric_id=metric.id,
            resource_id=resource_id,
            account_id=account_id,
            region=region
        )
        
        try:
            # In a real implementation, we would use boto3 to get the metrics
            # For example:
            # import boto3
            # cloudwatch = boto3.client('cloudwatch', region_name=region)
            # response = cloudwatch.get_metric_data(...)
            
            # For now, simulate some data
            time_points = int((end_time - start_time).total_seconds() / metric.period)
            
            for i in range(time_points):
                # Generate a simulated value (in real implementation, this would come from CloudWatch)
                timestamp = start_time + timedelta(seconds=i * metric.period)
                
                # Simple simulation based on resource ID hash to ensure consistency
                import hashlib
                hash_val = int(hashlib.md5(f"{resource_id}:{timestamp}".encode()).hexdigest(), 16)
                value = (hash_val % 1000) / 100.0  # Generate a value between 0 and 10
                
                metric_data.add_value(value, timestamp, metric.unit)
            
        except Exception as e:
            logger.error(f"Error collecting CloudWatch metric {metric.id} for resource {resource_id}: {e}")
        
        return metric_data


class MetricManager:
    """Manager for handling metrics across the fleet."""
    
    @classmethod
    def create_metric(
        cls, name: str, description: str, namespace: str, metric_name: str,
        dimensions: Optional[Dict[str, str]] = None, statistic: str = "Average",
        period: int = 300, unit: Optional[str] = None, 
        metric_type: MetricType = MetricType.CLOUDWATCH,
        priority: MetricPriority = MetricPriority.MEDIUM,
        retention_days: int = 14
    ) -> MetricDefinition:
        """Create a new metric definition."""
        metric_id = f"metric-{uuid.uuid4()}"
        metric = MetricDefinition(
            id=metric_id,
            name=name,
            description=description,
            namespace=namespace,
            metric_name=metric_name,
            dimensions=dimensions or {},
            statistic=statistic,
            period=period,
            unit=unit,
            metric_type=metric_type,
            priority=priority,
            retention_days=retention_days
        )
        
        MetricRegistry.register_metric(metric)
        return metric
    
    @classmethod
    async def collect_metrics(
        cls, metric_ids: Optional[List[str]] = None,
        resource_ids: Optional[List[str]] = None,
        account_ids: Optional[List[str]] = None,
        regions: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[MetricData]:
        """
        Collect metrics based on filters.
        
        Args:
            metric_ids: List of metric IDs to collect
            resource_ids: List of resource IDs to collect for
            account_ids: List of AWS account IDs to collect from
            regions: List of AWS regions to collect from
            start_time: Start time for metric data
            end_time: End time for metric data
            
        Returns:
            List of collected metric data
        """
        results = []
        
        # Get metrics to collect
        metrics_to_collect = []
        if metric_ids:
            for metric_id in metric_ids:
                metric = MetricRegistry.get_metric(metric_id)
                if metric and metric.status == MetricStatus.ACTIVE:
                    metrics_to_collect.append(metric)
        else:
            # Collect all active metrics
            metrics_to_collect = [
                metric for metric in MetricRegistry._metrics.values()
                if metric.status == MetricStatus.ACTIVE
            ]
        
        # Default to last 15 minutes if not specified
        if start_time is None:
            start_time = datetime.now() - timedelta(minutes=15)
        
        if end_time is None:
            end_time = datetime.now()
        
        # For each metric, collect data for all resources
        for metric in metrics_to_collect:
            # In a real implementation, we would get the resources from a resource registry
            # For simplicity, we'll use the provided resource IDs or defaults
            resources = resource_ids or ["i-123456", "i-789012"]
            
            # For each resource, collect from all accounts/regions
            for resource_id in resources:
                # In a real implementation, we would get the accounts/regions from a resource registry
                # For simplicity, we'll use the provided account IDs/regions or defaults
                accounts = account_ids or ["123456789012"]
                regs = regions or ["us-east-1", "us-west-2"]
                
                for account_id in accounts:
                    for region in regs:
                        if metric.metric_type == MetricType.CLOUDWATCH:
                            # Collect from CloudWatch
                            metric_data = await CloudWatchCollector.collect_metric(
                                metric=metric,
                                resource_id=resource_id,
                                account_id=account_id,
                                region=region,
                                start_time=start_time,
                                end_time=end_time
                            )
                            
                            # Store the data
                            MetricsStore.store_metric(metric_data)
                            results.append(metric_data)
                        
                        elif metric.metric_type == MetricType.CUSTOM:
                            # Custom metrics would be collected differently
                            # Not implemented in this example
                            pass
                        
                        elif metric.metric_type == MetricType.COMPOSITE:
                            # Composite metrics would be calculated from other metrics
                            # Not implemented in this example
                            pass
        
        return results
    
    @classmethod
    def get_metric_data(
        cls, metric_id: str, resource_id: Optional[str] = None,
        account_id: Optional[str] = None, region: Optional[str] = None,
        start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> List[MetricData]:
        """Get stored metric data with optional filtering."""
        return MetricsStore.get_metric_data(
            metric_id=metric_id,
            resource_id=resource_id,
            account_id=account_id,
            region=region,
            start_time=start_time,
            end_time=end_time
        )
    
    @classmethod
    def analyze_metric_trend(
        cls, metric_id: str, resource_id: str,
        account_id: Optional[str] = None, region: Optional[str] = None,
        hours: int = 24
    ) -> Dict[str, Any]:
        """
        Analyze trend for a specific metric and resource.
        
        Args:
            metric_id: Metric ID
            resource_id: Resource ID
            account_id: AWS account ID
            region: AWS region
            hours: Number of hours to analyze
            
        Returns:
            Analysis results
        """
        # Get metric definition
        metric = MetricRegistry.get_metric(metric_id)
        if not metric:
            return {"error": f"Metric not found: {metric_id}"}
        
        # Get data for the specified time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        metric_data_list = cls.get_metric_data(
            metric_id=metric_id,
            resource_id=resource_id,
            account_id=account_id,
            region=region,
            start_time=start_time,
            end_time=end_time
        )
        
        if not metric_data_list:
            return {
                "metric_id": metric_id,
                "resource_id": resource_id,
                "account_id": account_id,
                "region": region,
                "hours": hours,
                "data_points": 0,
                "error": "No data available for analysis"
            }
        
        # Extract values from all data points
        all_values = []
        for metric_data in metric_data_list:
            all_values.extend([v.value for v in metric_data.values])
        
        if not all_values:
            return {
                "metric_id": metric_id,
                "resource_id": resource_id,
                "account_id": account_id,
                "region": region,
                "hours": hours,
                "data_points": 0,
                "error": "No values available for analysis"
            }
        
        # Calculate statistics
        import statistics
        
        result = {
            "metric_id": metric_id,
            "metric_name": metric.name,
            "resource_id": resource_id,
            "account_id": account_id,
            "region": region,
            "hours": hours,
            "data_points": len(all_values),
            "current": all_values[-1] if all_values else None,
            "min": min(all_values),
            "max": max(all_values),
            "avg": statistics.mean(all_values),
            "median": statistics.median(all_values),
            "unit": metric.unit
        }
        
        # Calculate trend
        try:
            import numpy as np
            # If we have numpy, use linear regression for trend
            x = np.array(range(len(all_values)))
            y = np.array(all_values)
            slope, _, _, _, _ = np.polyfit(x, y, 1, full=True)
            result["trend"] = "increasing" if slope > 0.01 else "decreasing" if slope < -0.01 else "stable"
            result["trend_value"] = slope
        except ImportError:
            # Fallback if numpy is not available
            # Simple trend calculation
            if len(all_values) >= 2:
                first_value = all_values[0]
                last_value = all_values[-1]
                diff = last_value - first_value
                result["trend"] = "increasing" if diff > 0 else "decreasing" if diff < 0 else "stable"
                result["trend_value"] = diff
        
        return result


# Initialize with some default metrics
def initialize_monitoring():
    """Initialize the monitoring system with default metric definitions."""
    # CPU Utilization
    cpu_metric = MetricManager.create_metric(
        name="CPU Utilization",
        description="CPU utilization for EC2 instances",
        namespace="AWS/EC2",
        metric_name="CPUUtilization",
        dimensions={"InstanceId": "{resource_id}"},
        unit="Percent",
        priority=MetricPriority.HIGH
    )
    
    # Memory Utilization
    memory_metric = MetricManager.create_metric(
        name="Memory Utilization",
        description="Memory utilization for EC2 instances (requires CloudWatch agent)",
        namespace="CWAgent",
        metric_name="mem_used_percent",
        dimensions={"InstanceId": "{resource_id}"},
        unit="Percent",
        priority=MetricPriority.HIGH
    )
    
    # Disk Utilization
    disk_metric = MetricManager.create_metric(
        name="Disk Utilization",
        description="Disk utilization for EC2 instances (requires CloudWatch agent)",
        namespace="CWAgent",
        metric_name="disk_used_percent",
        dimensions={"InstanceId": "{resource_id}", "path": "/"},
        unit="Percent",
        priority=MetricPriority.MEDIUM
    )
    
    # Network In
    network_in_metric = MetricManager.create_metric(
        name="Network In",
        description="Network bytes in for EC2 instances",
        namespace="AWS/EC2",
        metric_name="NetworkIn",
        dimensions={"InstanceId": "{resource_id}"},
        unit="Bytes",
        priority=MetricPriority.MEDIUM
    )
    
    # Network Out
    network_out_metric = MetricManager.create_metric(
        name="Network Out",
        description="Network bytes out for EC2 instances",
        namespace="AWS/EC2",
        metric_name="NetworkOut",
        dimensions={"InstanceId": "{resource_id}"},
        unit="Bytes",
        priority=MetricPriority.MEDIUM
    )
    
    logger.info("Initialized monitoring with default metrics: " + 
                f"CPU: {cpu_metric.id}, Memory: {memory_metric.id}, " +
                f"Disk: {disk_metric.id}, Network In: {network_in_metric.id}, " +
                f"Network Out: {network_out_metric.id}")
    
    return [cpu_metric.id, memory_metric.id, disk_metric.id, 
            network_in_metric.id, network_out_metric.id] 