"""
Log Management System for AWS Fleet Management.

This module provides capabilities for collecting, searching, and analyzing
logs from AWS resources across the fleet.
"""

import json
import logging
import asyncio
import uuid
import re
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Union, Set, Pattern, Tuple

logger = logging.getLogger(__name__)


class LogSeverity(Enum):
    """Severity level of a log entry."""
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    DEBUG = "debug"
    TRACE = "trace"


class LogSource(Enum):
    """Source of log data."""
    CLOUDWATCH = "cloudwatch"
    AGENT = "agent"
    CUSTOM = "custom"


class LogStatus(Enum):
    """Status of a log collection."""
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"


@dataclass
class LogPattern:
    """Pattern for log parsing."""
    id: str
    name: str
    description: str
    pattern: str
    compiled_pattern: Optional[Pattern] = None
    group_names: List[str] = field(default_factory=list)
    severity_mapping: Dict[str, LogSeverity] = field(default_factory=dict)
    
    def __post_init__(self):
        """Compile the pattern after initialization."""
        if self.pattern:
            try:
                self.compiled_pattern = re.compile(self.pattern)
                # Extract named groups from pattern
                self.group_names = list(self.compiled_pattern.groupindex.keys())
            except re.error as e:
                logger.error(f"Invalid regex pattern '{self.pattern}': {e}")
                self.compiled_pattern = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "pattern": self.pattern,
            "group_names": self.group_names,
            "severity_mapping": {k: v.value for k, v in self.severity_mapping.items()}
        }
    
    def parse(self, log_text: str) -> Optional[Dict[str, str]]:
        """
        Parse a log line with this pattern.
        
        Args:
            log_text: Log line to parse
            
        Returns:
            Dictionary of extracted values, or None if pattern doesn't match
        """
        if not self.compiled_pattern:
            return None
        
        match = self.compiled_pattern.search(log_text)
        if not match:
            return None
        
        # Extract named groups
        result = {}
        for group_name in self.group_names:
            if group_name in match.groupdict():
                result[group_name] = match.group(group_name)
        
        # Add the full message
        result["message"] = log_text
        
        return result


@dataclass
class LogEntry:
    """A single log entry."""
    id: str
    timestamp: datetime
    message: str
    resource_id: str
    account_id: str
    region: str
    log_group: str
    log_stream: str
    severity: LogSeverity = LogSeverity.INFO
    parsed_data: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
            "resource_id": self.resource_id,
            "account_id": self.account_id,
            "region": self.region,
            "log_group": self.log_group,
            "log_stream": self.log_stream,
            "severity": self.severity.value,
            "parsed_data": self.parsed_data
        }


@dataclass
class LogGroup:
    """Configuration for a log group."""
    id: str
    name: str
    source: LogSource
    log_group_name: str
    description: str = ""
    resource_type: str = "*"
    retention_days: int = 30
    patterns: List[str] = field(default_factory=list)  # List of pattern IDs
    status: LogStatus = LogStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "source": self.source.value,
            "log_group_name": self.log_group_name,
            "description": self.description,
            "resource_type": self.resource_type,
            "retention_days": self.retention_days,
            "patterns": self.patterns,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


@dataclass
class LogQuery:
    """Query for searching logs."""
    id: str
    name: str
    query_string: str
    log_groups: List[str]  # List of log group IDs
    start_time: datetime
    end_time: Optional[datetime] = None
    limit: int = 100
    account_ids: List[str] = field(default_factory=list)
    regions: List[str] = field(default_factory=list)
    resource_ids: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "query_string": self.query_string,
            "log_groups": self.log_groups,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "limit": self.limit,
            "account_ids": self.account_ids,
            "regions": self.regions,
            "resource_ids": self.resource_ids,
            "created_at": self.created_at.isoformat()
        }


@dataclass
class LogQueryResult:
    """Result of a log query."""
    query_id: str
    entries: List[LogEntry] = field(default_factory=list)
    status: str = "complete"
    execution_time_ms: int = 0
    scanned_bytes: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "query_id": self.query_id,
            "entries": [entry.to_dict() for entry in self.entries],
            "status": self.status,
            "count": len(self.entries),
            "execution_time_ms": self.execution_time_ms,
            "scanned_bytes": self.scanned_bytes
        }


class LogPatternRegistry:
    """Registry for managing log patterns."""
    
    _patterns: Dict[str, LogPattern] = {}
    
    @classmethod
    def register_pattern(cls, pattern: LogPattern) -> None:
        """Register a log pattern."""
        cls._patterns[pattern.id] = pattern
    
    @classmethod
    def get_pattern(cls, pattern_id: str) -> Optional[LogPattern]:
        """Get a log pattern by ID."""
        return cls._patterns.get(pattern_id)
    
    @classmethod
    def list_patterns(cls) -> List[LogPattern]:
        """List all registered patterns."""
        return list(cls._patterns.values())
    
    @classmethod
    def delete_pattern(cls, pattern_id: str) -> bool:
        """Delete a log pattern."""
        if pattern_id in cls._patterns:
            del cls._patterns[pattern_id]
            return True
        return False


class LogGroupRegistry:
    """Registry for managing log groups."""
    
    _log_groups: Dict[str, LogGroup] = {}
    
    @classmethod
    def register_log_group(cls, log_group: LogGroup) -> None:
        """Register a log group."""
        cls._log_groups[log_group.id] = log_group
    
    @classmethod
    def get_log_group(cls, log_group_id: str) -> Optional[LogGroup]:
        """Get a log group by ID."""
        return cls._log_groups.get(log_group_id)
    
    @classmethod
    def get_log_groups_by_source(cls, source: LogSource) -> List[LogGroup]:
        """Get all log groups of a specific source."""
        return [
            log_group for log_group in cls._log_groups.values()
            if log_group.source == source and log_group.status == LogStatus.ACTIVE
        ]
    
    @classmethod
    def get_log_groups_by_resource_type(cls, resource_type: str) -> List[LogGroup]:
        """Get all log groups for a specific resource type."""
        return [
            log_group for log_group in cls._log_groups.values()
            if (log_group.resource_type == resource_type or log_group.resource_type == "*")
            and log_group.status == LogStatus.ACTIVE
        ]
    
    @classmethod
    def list_log_groups(cls) -> List[LogGroup]:
        """List all registered log groups."""
        return list(cls._log_groups.values())
    
    @classmethod
    def delete_log_group(cls, log_group_id: str) -> bool:
        """Mark a log group as archived."""
        log_group = cls.get_log_group(log_group_id)
        if not log_group:
            return False
        
        log_group.status = LogStatus.ARCHIVED
        log_group.updated_at = datetime.now()
        return True


class LogStore:
    """Store for log entries."""
    
    # In-memory storage for log data
    # In production, this would use a database or Elasticsearch
    _entries: Dict[str, Dict[str, Dict[str, List[LogEntry]]]] = {}
    # Structure: log_group_id -> account_id+region -> resource_id -> entries
    
    @classmethod
    def store_log_entry(cls, entry: LogEntry, log_group_id: str) -> None:
        """
        Store a log entry.
        
        Args:
            entry: Log entry to store
            log_group_id: ID of the log group
        """
        # Create nested structure if needed
        account_region = f"{entry.account_id}:{entry.region}"
        
        if log_group_id not in cls._entries:
            cls._entries[log_group_id] = {}
        
        if account_region not in cls._entries[log_group_id]:
            cls._entries[log_group_id][account_region] = {}
        
        if entry.resource_id not in cls._entries[log_group_id][account_region]:
            cls._entries[log_group_id][account_region][entry.resource_id] = []
        
        # Add entry
        cls._entries[log_group_id][account_region][entry.resource_id].append(entry)
        
        # Apply retention policy
        cls._apply_retention(log_group_id, account_region, entry.resource_id)
    
    @classmethod
    def _apply_retention(cls, log_group_id: str, account_region: str, resource_id: str) -> None:
        """
        Apply retention policy to stored log entries.
        
        Args:
            log_group_id: Log group ID
            account_region: Account and region key
            resource_id: Resource ID
        """
        log_group = LogGroupRegistry.get_log_group(log_group_id)
        if not log_group:
            return
        
        # Calculate retention threshold
        retention_threshold = datetime.now() - timedelta(days=log_group.retention_days)
        
        # Filter entries based on retention
        if (log_group_id in cls._entries and 
            account_region in cls._entries[log_group_id] and 
            resource_id in cls._entries[log_group_id][account_region]):
            
            cls._entries[log_group_id][account_region][resource_id] = [
                entry for entry in cls._entries[log_group_id][account_region][resource_id]
                if entry.timestamp >= retention_threshold
            ]
    
    @classmethod
    def search_logs(
        cls, query: LogQuery
    ) -> LogQueryResult:
        """
        Search logs based on a query.
        
        Args:
            query: Log query
            
        Returns:
            Query result
        """
        start_time = datetime.now()
        result = LogQueryResult(query_id=query.id)
        all_entries = []
        scanned_bytes = 0
        
        # For each log group
        for log_group_id in query.log_groups:
            if log_group_id not in cls._entries:
                continue
            
            # Filter by account and region
            account_regions = []
            for ar in cls._entries[log_group_id].keys():
                ar_parts = ar.split(":")
                if len(ar_parts) == 2:
                    a_id, reg = ar_parts
                    if ((not query.account_ids or a_id in query.account_ids) and 
                        (not query.regions or reg in query.regions)):
                        account_regions.append(ar)
            
            # For each account/region
            for ar in account_regions:
                ar_parts = ar.split(":")
                if len(ar_parts) != 2:
                    continue
                
                # Filter by resource
                resources = []
                for res_id in cls._entries[log_group_id][ar].keys():
                    if not query.resource_ids or res_id in query.resource_ids:
                        resources.append(res_id)
                
                # For each resource
                for res_id in resources:
                    # Get entries for this resource
                    entries = cls._entries[log_group_id][ar][res_id]
                    
                    # Filter by time range
                    filtered_entries = [
                        entry for entry in entries
                        if entry.timestamp >= query.start_time and
                        (not query.end_time or entry.timestamp <= query.end_time)
                    ]
                    
                    # Filter by query string
                    if query.query_string:
                        filtered_entries = [
                            entry for entry in filtered_entries
                            if cls._match_query_string(entry, query.query_string)
                        ]
                    
                    # Add to result
                    all_entries.extend(filtered_entries)
                    
                    # Update scanned bytes
                    scanned_bytes += sum(len(entry.message) for entry in filtered_entries)
        
        # Sort by timestamp (newest first)
        all_entries.sort(key=lambda e: e.timestamp, reverse=True)
        
        # Apply limit
        result.entries = all_entries[:query.limit]
        result.scanned_bytes = scanned_bytes
        result.execution_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return result
    
    @classmethod
    def _match_query_string(cls, entry: LogEntry, query_string: str) -> bool:
        """
        Check if an entry matches a query string.
        
        Args:
            entry: Log entry
            query_string: Query string
            
        Returns:
            True if entry matches
        """
        # Simple implementation - check if query string is in message
        if query_string.lower() in entry.message.lower():
            return True
        
        # Check parsed fields
        for field_name, value in entry.parsed_data.items():
            if isinstance(value, str) and query_string.lower() in value.lower():
                return True
        
        return False


class CloudWatchLogCollector:
    """Collector for CloudWatch logs."""
    
    @classmethod
    async def collect_logs(
        cls, log_group: LogGroup, resource_id: str, 
        account_id: str, region: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[LogEntry]:
        """
        Collect logs from CloudWatch.
        
        Args:
            log_group: Log group configuration
            resource_id: Resource ID
            account_id: AWS account ID
            region: AWS region
            start_time: Start time for logs
            end_time: End time for logs
            
        Returns:
            List of collected log entries
        """
        if start_time is None:
            start_time = datetime.now() - timedelta(hours=1)
        
        if end_time is None:
            end_time = datetime.now()
        
        # Get patterns for this log group
        patterns = [
            LogPatternRegistry.get_pattern(pattern_id) 
            for pattern_id in log_group.patterns
            if LogPatternRegistry.get_pattern(pattern_id) is not None
        ]
        
        # List to store collected entries
        entries = []
        
        try:
            # In a real implementation, we would use boto3
            # For example:
            # import boto3
            # logs = boto3.client('logs', region_name=region)
            # response = logs.filter_log_events(...)
            
            # For now, simulate some log entries
            log_types = [
                ("INFO", "Application started"),
                ("INFO", f"Processing resource {resource_id}"),
                ("DEBUG", "Loading configuration"),
                ("INFO", "Authentication successful"),
                ("WARNING", "High memory usage detected"),
                ("ERROR", "Failed to connect to database"),
                ("INFO", "Operation completed successfully"),
                ("DEBUG", "Cache hit ratio: 85%")
            ]
            
            # Generate 5-10 random log entries
            import random
            num_entries = random.randint(5, 10)
            
            for i in range(num_entries):
                # Generate a timestamp within the requested range
                time_range = (end_time - start_time).total_seconds()
                random_seconds = random.randint(0, int(time_range))
                timestamp = start_time + timedelta(seconds=random_seconds)
                
                # Select a log type
                log_type, log_base = random.choice(log_types)
                
                # Create a unique log message
                log_message = f"[{log_type}] {log_base} (instance-{i})"
                
                # Create log entry
                entry_id = f"log-{uuid.uuid4()}"
                entry = LogEntry(
                    id=entry_id,
                    timestamp=timestamp,
                    message=log_message,
                    resource_id=resource_id,
                    account_id=account_id,
                    region=region,
                    log_group=log_group.log_group_name,
                    log_stream=f"{resource_id}/application.log",
                    severity=LogSeverity[log_type] if log_type in LogSeverity.__members__ else LogSeverity.INFO
                )
                
                # Parse with patterns
                for pattern in patterns:
                    parsed_data = pattern.parse(log_message)
                    if parsed_data:
                        entry.parsed_data.update(parsed_data)
                        break
                
                entries.append(entry)
                
                # Store the entry
                LogStore.store_log_entry(entry, log_group.id)
            
        except Exception as e:
            logger.error(f"Error collecting logs for {resource_id} from {log_group.name}: {e}")
        
        return entries


class LogParser:
    """Parser for log entries."""
    
    @classmethod
    def parse_log_entry(cls, entry: LogEntry, patterns: List[LogPattern]) -> Dict[str, str]:
        """
        Parse a log entry with a list of patterns.
        
        Args:
            entry: Log entry to parse
            patterns: List of patterns to try
            
        Returns:
            Dictionary of parsed fields
        """
        for pattern in patterns:
            parsed = pattern.parse(entry.message)
            if parsed:
                return parsed
        
        return {}


class LogManager:
    """Manager for handling logs across the fleet."""
    
    @classmethod
    def create_log_pattern(
        cls, name: str, description: str, pattern: str,
        severity_mapping: Optional[Dict[str, LogSeverity]] = None
    ) -> LogPattern:
        """Create a new log pattern."""
        pattern_id = f"pattern-{uuid.uuid4()}"
        log_pattern = LogPattern(
            id=pattern_id,
            name=name,
            description=description,
            pattern=pattern,
            severity_mapping=severity_mapping or {}
        )
        
        LogPatternRegistry.register_pattern(log_pattern)
        return log_pattern
    
    @classmethod
    def create_log_group(
        cls, name: str, source: LogSource, log_group_name: str,
        description: str = "", resource_type: str = "*",
        retention_days: int = 30, patterns: List[str] = None
    ) -> LogGroup:
        """Create a new log group."""
        log_group_id = f"log-group-{uuid.uuid4()}"
        log_group = LogGroup(
            id=log_group_id,
            name=name,
            source=source,
            log_group_name=log_group_name,
            description=description,
            resource_type=resource_type,
            retention_days=retention_days,
            patterns=patterns or []
        )
        
        LogGroupRegistry.register_log_group(log_group)
        return log_group
    
    @classmethod
    def create_log_query(
        cls, name: str, query_string: str, log_groups: List[str],
        start_time: Optional[datetime] = None, end_time: Optional[datetime] = None,
        limit: int = 100, account_ids: List[str] = None,
        regions: List[str] = None, resource_ids: List[str] = None
    ) -> LogQuery:
        """Create a new log query."""
        if start_time is None:
            start_time = datetime.now() - timedelta(hours=1)
        
        query_id = f"query-{uuid.uuid4()}"
        query = LogQuery(
            id=query_id,
            name=name,
            query_string=query_string,
            log_groups=log_groups,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            account_ids=account_ids or [],
            regions=regions or [],
            resource_ids=resource_ids or []
        )
        
        return query
    
    @classmethod
    async def collect_logs(
        cls, log_group_ids: Optional[List[str]] = None,
        resource_ids: Optional[List[str]] = None,
        account_ids: Optional[List[str]] = None,
        regions: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, List[LogEntry]]:
        """
        Collect logs based on filters.
        
        Args:
            log_group_ids: List of log group IDs to collect from
            resource_ids: List of resource IDs to collect for
            account_ids: List of AWS account IDs to collect from
            regions: List of AWS regions to collect from
            start_time: Start time for logs
            end_time: End time for logs
            
        Returns:
            Dictionary of log group ID to list of collected entries
        """
        results: Dict[str, List[LogEntry]] = {}
        
        # Get log groups to collect
        log_groups_to_collect = []
        if log_group_ids:
            for log_group_id in log_group_ids:
                log_group = LogGroupRegistry.get_log_group(log_group_id)
                if log_group and log_group.status == LogStatus.ACTIVE:
                    log_groups_to_collect.append(log_group)
        else:
            # Collect from all active log groups
            log_groups_to_collect = [
                log_group for log_group in LogGroupRegistry.list_log_groups()
                if log_group.status == LogStatus.ACTIVE
            ]
        
        # Default to last hour if not specified
        if start_time is None:
            start_time = datetime.now() - timedelta(hours=1)
        
        if end_time is None:
            end_time = datetime.now()
        
        # For each log group, collect logs for all resources
        for log_group in log_groups_to_collect:
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
                        if log_group.source == LogSource.CLOUDWATCH:
                            # Collect from CloudWatch
                            entries = await CloudWatchLogCollector.collect_logs(
                                log_group=log_group,
                                resource_id=resource_id,
                                account_id=account_id,
                                region=region,
                                start_time=start_time,
                                end_time=end_time
                            )
                            
                            if log_group.id not in results:
                                results[log_group.id] = []
                            
                            results[log_group.id].extend(entries)
        
        return results
    
    @classmethod
    def search_logs(cls, query: LogQuery) -> LogQueryResult:
        """
        Search logs based on a query.
        
        Args:
            query: Log query
            
        Returns:
            Query result
        """
        return LogStore.search_logs(query)


# Initialize with some default log patterns and groups
def initialize_logs():
    """Initialize the log management system with default patterns and groups."""
    # Create log patterns
    
    # Define commonly used log patterns
    patterns = [
        LogPattern(
            id=f"pattern-{uuid.uuid4()}",
            name="Access Log Pattern",
            description="Pattern for HTTP access logs",
            pattern=(
                r'(?P<client_ip>\S+) - (?P<remote_user>\S+) '
                r'\[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
                r'(?P<status>\d+) (?P<bytes>\d+)'
            )
        ),
    ]
    
    # Apache/NGINX access log pattern
    access_log_pattern = LogManager.create_log_pattern(
        name="Access Log",
        description="Pattern for Apache/NGINX access logs",
        pattern=r'(?P<client_ip>\S+) - (?P<user>\S+) \[(?P<timestamp>\d+/\w+/\d+:\d+:\d+:\d+ [+-]\d+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<bytes>\d+)'
    )
    
    # General log level pattern
    log_level_pattern = LogManager.create_log_pattern(
        name="Log Level",
        description="Pattern for logs with level indicator",
        pattern=r'\[(?P<level>[A-Z]+)\] (?P<message>.*)'
    )
    
    # JSON log pattern
    json_log_pattern = LogManager.create_log_pattern(
        name="JSON Log",
        description="Pattern for JSON-formatted logs",
        pattern=r'{.*}'
    )
    
    # EC2 system log group
    ec2_syslog = LogManager.create_log_group(
        name="EC2 System Logs",
        source=LogSource.CLOUDWATCH,
        log_group_name="/aws/ec2/syslog",
        description="System logs from EC2 instances",
        resource_type="ec2",
        patterns=[log_level_pattern.id]
    )
    
    # EC2 application log group
    ec2_app_log = LogManager.create_log_group(
        name="EC2 Application Logs",
        source=LogSource.CLOUDWATCH,
        log_group_name="/aws/ec2/application",
        description="Application logs from EC2 instances",
        resource_type="ec2",
        patterns=[log_level_pattern.id, json_log_pattern.id]
    )
    
    # Lambda function log group
    lambda_log = LogManager.create_log_group(
        name="Lambda Function Logs",
        source=LogSource.CLOUDWATCH,
        log_group_name="/aws/lambda/fleet-management",
        description="Logs from Lambda functions",
        resource_type="lambda",
        patterns=[log_level_pattern.id, json_log_pattern.id]
    )
    
    # RDS database log group
    rds_log = LogManager.create_log_group(
        name="RDS Database Logs",
        source=LogSource.CLOUDWATCH,
        log_group_name="/aws/rds/instance/error",
        description="Error logs from RDS instances",
        resource_type="rds",
        patterns=[log_level_pattern.id]
    )
    
    logger.info("Initialized log management with default patterns: " +
               f"Access Log: {access_log_pattern.id}, " +
               f"Log Level: {log_level_pattern.id}, " +
               f"JSON Log: {json_log_pattern.id}")
    
    logger.info("Initialized log management with default groups: " +
               f"EC2 System: {ec2_syslog.id}, " +
               f"EC2 Application: {ec2_app_log.id}, " +
               f"Lambda: {lambda_log.id}, " +
               f"RDS: {rds_log.id}")
    
    return {
        "patterns": [access_log_pattern.id, log_level_pattern.id, json_log_pattern.id],
        "groups": [ec2_syslog.id, ec2_app_log.id, lambda_log.id, rds_log.id]
    } 