"""Connection pooling for AWS API clients.

This module provides connection pooling and client reuse to optimize AWS API calls:
- Reusable boto3 clients with connection pooling
- Regional client management
- Connection health monitoring
- Automatic retry and failover
"""

import asyncio
import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, ConnectionError, EndpointConnectionError

logger = logging.getLogger(__name__)


@dataclass
class ConnectionStats:
    """Statistics for a connection pool."""
    
    created_at: datetime = field(default_factory=datetime.utcnow)
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_latency_ms: float = 0.0
    last_used: datetime = field(default_factory=datetime.utcnow)
    health_checks_passed: int = 0
    health_checks_failed: int = 0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_requests == 0:
            return 100.0
        return (self.successful_requests / self.total_requests) * 100
    
    @property
    def average_latency_ms(self) -> float:
        """Calculate average latency."""
        if self.successful_requests == 0:
            return 0.0
        return self.total_latency_ms / self.successful_requests
    
    @property
    def age_seconds(self) -> float:
        """Get age of the pool in seconds."""
        return (datetime.utcnow() - self.created_at).total_seconds()


@dataclass
class PoolConfig:
    """Configuration for connection pools."""
    
    max_pool_connections: int = 50
    connect_timeout: int = 5
    read_timeout: int = 60
    retries: int = 3
    retry_mode: str = "adaptive"
    max_retry_attempts: int = 3
    
    # Pool management
    max_pool_age_seconds: int = 3600  # 1 hour
    max_idle_seconds: int = 300  # 5 minutes
    health_check_interval_seconds: int = 60
    
    # Performance
    enable_endpoint_discovery: bool = True
    tcp_keepalive: bool = True
    
    def to_boto_config(self) -> Config:
        """Convert to boto3 Config object."""
        return Config(
            region_name=None,  # Set per client
            signature_version='v4',
            retries={
                'max_attempts': self.max_retry_attempts,
                'mode': self.retry_mode,
            },
            max_pool_connections=self.max_pool_connections,
            connect_timeout=self.connect_timeout,
            read_timeout=self.read_timeout,
            tcp_keepalive=self.tcp_keepalive,
            parameter_validation=True,
        )


class ClientPool:
    """Pool of AWS clients for a specific service and region."""
    
    def __init__(
        self,
        service_name: str,
        region_name: str,
        config: PoolConfig,
        session: Optional[boto3.Session] = None
    ):
        """Initialize client pool.
        
        Args:
            service_name: AWS service name
            region_name: AWS region
            config: Pool configuration
            session: Boto3 session
        """
        self.service_name = service_name
        self.region_name = region_name
        self.config = config
        self.session = session or boto3.Session()
        
        self._client: Optional[Any] = None
        self._lock = asyncio.Lock()
        self.stats = ConnectionStats()
        self._last_health_check = datetime.utcnow()
        
    async def get_client(self) -> Any:
        """Get a client from the pool.
        
        Returns:
            Boto3 client instance
        """
        async with self._lock:
            # Check if we need to create or recreate client
            if self._should_recreate_client():
                await self._create_client()
            
            self.stats.last_used = datetime.utcnow()
            return self._client
    
    async def _create_client(self):
        """Create a new client instance."""
        try:
            # Create client with custom config
            self._client = await asyncio.to_thread(
                self.session.client,
                self.service_name,
                region_name=self.region_name,
                config=self.config.to_boto_config()
            )
            
            # Reset stats for new client
            self.stats = ConnectionStats()
            logger.info(f"Created new {self.service_name} client for region {self.region_name}")
            
        except Exception as e:
            logger.error(f"Failed to create {self.service_name} client: {e}")
            raise
    
    def _should_recreate_client(self) -> bool:
        """Check if client should be recreated."""
        if self._client is None:
            return True
            
        # Check age
        if self.stats.age_seconds > self.config.max_pool_age_seconds:
            logger.info(f"Client pool for {self.service_name} is too old, recreating")
            return True
            
        # Check idle time
        idle_seconds = (datetime.utcnow() - self.stats.last_used).total_seconds()
        if idle_seconds > self.config.max_idle_seconds:
            logger.info(f"Client pool for {self.service_name} was idle too long, recreating")
            return True
            
        # Check failure rate
        if self.stats.total_requests > 100 and self.stats.success_rate < 50:
            logger.warning(f"Client pool for {self.service_name} has low success rate, recreating")
            return True
            
        return False
    
    async def execute_with_stats(self, operation: str, **kwargs) -> Any:
        """Execute an operation with statistics tracking.
        
        Args:
            operation: Operation name
            **kwargs: Operation parameters
            
        Returns:
            Operation result
        """
        client = await self.get_client()
        start_time = time.time()
        
        try:
            # Get the operation method
            method = getattr(client, operation)
            
            # Execute operation
            result = await asyncio.to_thread(method, **kwargs)
            
            # Update stats
            elapsed_ms = (time.time() - start_time) * 1000
            self.stats.total_requests += 1
            self.stats.successful_requests += 1
            self.stats.total_latency_ms += elapsed_ms
            
            return result
            
        except Exception as e:
            # Update failure stats
            self.stats.total_requests += 1
            self.stats.failed_requests += 1
            
            logger.error(f"Operation {operation} failed: {e}")
            raise
    
    async def health_check(self) -> bool:
        """Perform health check on the client.
        
        Returns:
            True if healthy
        """
        # Skip if recently checked
        since_last_check = (datetime.utcnow() - self._last_health_check).total_seconds()
        if since_last_check < self.config.health_check_interval_seconds:
            return True
            
        self._last_health_check = datetime.utcnow()
        
        try:
            client = await self.get_client()
            
            # Service-specific health checks
            if self.service_name == 's3':
                await asyncio.to_thread(client.list_buckets, MaxBuckets=1)
            elif self.service_name == 'ec2':
                await asyncio.to_thread(client.describe_regions, MaxResults=1)
            elif self.service_name == 'sts':
                await asyncio.to_thread(client.get_caller_identity)
            else:
                # Generic operation for other services
                # Try to get service metadata
                await asyncio.to_thread(client.meta.service_model.service_description)
            
            self.stats.health_checks_passed += 1
            return True
            
        except Exception as e:
            logger.warning(f"Health check failed for {self.service_name}: {e}")
            self.stats.health_checks_failed += 1
            return False
    
    async def close(self):
        """Close the client pool."""
        if self._client:
            # Boto3 clients don't have explicit close, but we can clear reference
            self._client = None
            logger.info(f"Closed client pool for {self.service_name} in {self.region_name}")


class ConnectionPoolManager:
    """Manager for AWS client connection pools."""
    
    def __init__(self, config: Optional[PoolConfig] = None):
        """Initialize connection pool manager.
        
        Args:
            config: Pool configuration
        """
        self.config = config or PoolConfig()
        self._pools: Dict[Tuple[str, str], ClientPool] = {}
        self._lock = asyncio.Lock()
        self._session_cache: Dict[str, boto3.Session] = {}
        
    async def get_client(
        self,
        service_name: str,
        region_name: str = 'us-east-1',
        profile_name: Optional[str] = None
    ) -> Any:
        """Get a client from the appropriate pool.
        
        Args:
            service_name: AWS service name
            region_name: AWS region
            profile_name: AWS profile name
            
        Returns:
            Boto3 client instance
        """
        pool_key = (service_name, region_name)
        
        # Get or create pool
        async with self._lock:
            if pool_key not in self._pools:
                session = self._get_session(profile_name)
                self._pools[pool_key] = ClientPool(
                    service_name,
                    region_name,
                    self.config,
                    session
                )
            
            pool = self._pools[pool_key]
        
        # Get client from pool
        return await pool.get_client()
    
    @asynccontextmanager
    async def client_context(
        self,
        service_name: str,
        region_name: str = 'us-east-1',
        profile_name: Optional[str] = None
    ):
        """Context manager for getting a client.
        
        Args:
            service_name: AWS service name
            region_name: AWS region
            profile_name: AWS profile name
            
        Yields:
            Boto3 client instance
        """
        client = await self.get_client(service_name, region_name, profile_name)
        try:
            yield client
        finally:
            # Client is managed by pool, no cleanup needed
            pass
    
    async def execute(
        self,
        service_name: str,
        operation: str,
        region_name: str = 'us-east-1',
        profile_name: Optional[str] = None,
        **kwargs
    ) -> Any:
        """Execute an AWS operation using pooled client.
        
        Args:
            service_name: AWS service name
            operation: Operation name
            region_name: AWS region
            profile_name: AWS profile name
            **kwargs: Operation parameters
            
        Returns:
            Operation result
        """
        pool_key = (service_name, region_name)
        
        # Get or create pool
        async with self._lock:
            if pool_key not in self._pools:
                session = self._get_session(profile_name)
                self._pools[pool_key] = ClientPool(
                    service_name,
                    region_name,
                    self.config,
                    session
                )
            
            pool = self._pools[pool_key]
        
        # Execute with stats tracking
        return await pool.execute_with_stats(operation, **kwargs)
    
    def _get_session(self, profile_name: Optional[str] = None) -> boto3.Session:
        """Get or create a boto3 session.
        
        Args:
            profile_name: AWS profile name
            
        Returns:
            Boto3 session
        """
        cache_key = profile_name or 'default'
        
        if cache_key not in self._session_cache:
            if profile_name:
                self._session_cache[cache_key] = boto3.Session(profile_name=profile_name)
            else:
                self._session_cache[cache_key] = boto3.Session()
        
        return self._session_cache[cache_key]
    
    async def health_check_all(self) -> Dict[str, bool]:
        """Perform health checks on all pools.
        
        Returns:
            Dictionary of pool keys to health status
        """
        results = {}
        
        for pool_key, pool in self._pools.items():
            service, region = pool_key
            key = f"{service}:{region}"
            results[key] = await pool.health_check()
        
        return results
    
    async def get_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all pools.
        
        Returns:
            Dictionary of pool statistics
        """
        stats = {}
        
        for pool_key, pool in self._pools.items():
            service, region = pool_key
            key = f"{service}:{region}"
            
            pool_stats = pool.stats
            stats[key] = {
                'total_requests': pool_stats.total_requests,
                'successful_requests': pool_stats.successful_requests,
                'failed_requests': pool_stats.failed_requests,
                'success_rate': pool_stats.success_rate,
                'average_latency_ms': pool_stats.average_latency_ms,
                'age_seconds': pool_stats.age_seconds,
                'last_used': pool_stats.last_used.isoformat(),
                'health_checks_passed': pool_stats.health_checks_passed,
                'health_checks_failed': pool_stats.health_checks_failed,
            }
        
        return stats
    
    async def cleanup_idle_pools(self) -> int:
        """Clean up idle connection pools.
        
        Returns:
            Number of pools cleaned up
        """
        cleaned = 0
        
        async with self._lock:
            pools_to_remove = []
            
            for pool_key, pool in self._pools.items():
                idle_seconds = (datetime.utcnow() - pool.stats.last_used).total_seconds()
                
                if idle_seconds > self.config.max_idle_seconds:
                    pools_to_remove.append(pool_key)
            
            for pool_key in pools_to_remove:
                pool = self._pools.pop(pool_key)
                await pool.close()
                cleaned += 1
                
                service, region = pool_key
                logger.info(f"Cleaned up idle pool for {service} in {region}")
        
        return cleaned
    
    async def close_all(self):
        """Close all connection pools."""
        async with self._lock:
            for pool in self._pools.values():
                await pool.close()
            
            self._pools.clear()
            self._session_cache.clear()
            
        logger.info("Closed all connection pools")


# Global connection pool manager instance
_global_pool_manager: Optional[ConnectionPoolManager] = None


def get_connection_pool_manager(config: Optional[PoolConfig] = None) -> ConnectionPoolManager:
    """Get the global connection pool manager.
    
    Args:
        config: Pool configuration (used only on first call)
        
    Returns:
        Connection pool manager instance
    """
    global _global_pool_manager
    
    if _global_pool_manager is None:
        _global_pool_manager = ConnectionPoolManager(config)
    
    return _global_pool_manager


async def cleanup_connection_pools():
    """Clean up all connection pools."""
    global _global_pool_manager
    
    if _global_pool_manager:
        await _global_pool_manager.close_all()
        _global_pool_manager = None