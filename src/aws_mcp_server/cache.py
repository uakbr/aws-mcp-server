"""Redis caching layer for AWS MCP Server.

This module provides caching functionality to improve performance by:
- Caching frequently accessed AWS resource metadata
- Storing API responses with TTL
- Implementing cache invalidation strategies
- Providing distributed caching for horizontal scaling
"""

import asyncio
import hashlib
import json
import logging
import pickle
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Optional, Union

import redis.asyncio as redis
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import ConnectionError, RedisError, TimeoutError

logger = logging.getLogger(__name__)


class CacheConfig:
    """Configuration for Redis cache."""
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        ssl: bool = False,
        max_connections: int = 50,
        socket_timeout: int = 5,
        socket_connect_timeout: int = 5,
        retry_on_timeout: bool = True,
        retry_on_error: Optional[list[type[Exception]]] = None,
        max_retries: int = 3,
        default_ttl: int = 3600,  # 1 hour
        key_prefix: str = "aws_mcp:",
    ):
        """Initialize cache configuration.
        
        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            ssl: Use SSL connection
            max_connections: Maximum connections in pool
            socket_timeout: Socket timeout in seconds
            socket_connect_timeout: Socket connect timeout
            retry_on_timeout: Retry on timeout
            retry_on_error: Exceptions to retry on
            max_retries: Maximum retry attempts
            default_ttl: Default TTL in seconds
            key_prefix: Prefix for all cache keys
        """
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.ssl = ssl
        self.max_connections = max_connections
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        self.retry_on_timeout = retry_on_timeout
        self.retry_on_error = retry_on_error or [ConnectionError, TimeoutError]
        self.max_retries = max_retries
        self.default_ttl = default_ttl
        self.key_prefix = key_prefix


class CacheKey:
    """Helper class for generating consistent cache keys."""
    
    @staticmethod
    def resource(resource_type: str, resource_id: str, region: Optional[str] = None) -> str:
        """Generate cache key for AWS resource.
        
        Args:
            resource_type: Type of resource (e.g., 'ec2_instance')
            resource_id: Resource identifier
            region: AWS region
            
        Returns:
            Cache key string
        """
        parts = ["resource", resource_type, resource_id]
        if region:
            parts.append(region)
        return ":".join(parts)
    
    @staticmethod
    def api_response(service: str, operation: str, params: dict[str, Any]) -> str:
        """Generate cache key for API response.
        
        Args:
            service: AWS service name
            operation: API operation
            params: Request parameters
            
        Returns:
            Cache key string
        """
        # Create deterministic hash of parameters
        params_str = json.dumps(params, sort_keys=True)
        params_hash = hashlib.md5(params_str.encode()).hexdigest()
        
        return f"api:{service}:{operation}:{params_hash}"
    
    @staticmethod
    def list_operation(service: str, operation: str, filters: Optional[dict[str, Any]] = None) -> str:
        """Generate cache key for list operations.
        
        Args:
            service: AWS service name
            operation: List operation name
            filters: Optional filters
            
        Returns:
            Cache key string
        """
        parts = ["list", service, operation]
        if filters:
            filters_str = json.dumps(filters, sort_keys=True)
            filters_hash = hashlib.md5(filters_str.encode()).hexdigest()[:8]
            parts.append(filters_hash)
        return ":".join(parts)


class RedisCache:
    """Redis cache implementation for AWS MCP Server."""
    
    def __init__(self, config: Optional[CacheConfig] = None):
        """Initialize Redis cache.
        
        Args:
            config: Cache configuration
        """
        self.config = config or CacheConfig()
        self._redis: Optional[redis.Redis] = None
        self._connected = False
        
    async def connect(self):
        """Connect to Redis server."""
        if self._connected:
            return
            
        try:
            # Configure retry strategy
            retry = Retry(
                retries=self.config.max_retries,
                backoff=ExponentialBackoff(),
                supported_errors=(ConnectionError, TimeoutError),
            )
            
            # Create Redis connection
            self._redis = redis.Redis(
                host=self.config.host,
                port=self.config.port,
                db=self.config.db,
                password=self.config.password,
                ssl=self.config.ssl,
                max_connections=self.config.max_connections,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.socket_connect_timeout,
                retry_on_timeout=self.config.retry_on_timeout,
                retry_on_error=self.config.retry_on_error,
                retry=retry,
                decode_responses=False,  # We'll handle encoding/decoding
            )
            
            # Test connection
            await self._redis.ping()
            self._connected = True
            logger.info(f"Connected to Redis at {self.config.host}:{self.config.port}")
            
        except RedisError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from Redis server."""
        if self._redis and self._connected:
            await self._redis.aclose()
            self._connected = False
            logger.info("Disconnected from Redis")
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        if not self._connected:
            await self.connect()
            
        full_key = self.config.key_prefix + key
        
        try:
            value = await self._redis.get(full_key)
            if value is None:
                return None
                
            # Try to deserialize
            try:
                return pickle.loads(value)
            except pickle.PickleError:
                # Fallback to JSON
                return json.loads(value.decode('utf-8'))
                
        except RedisError as e:
            logger.warning(f"Cache get error for key {key}: {e}")
            return None
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        condition: Optional[str] = None
    ) -> bool:
        """Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            condition: Set condition ('nx' for not exists, 'xx' for exists)
            
        Returns:
            True if set successfully
        """
        if not self._connected:
            await self.connect()
            
        full_key = self.config.key_prefix + key
        ttl = ttl or self.config.default_ttl
        
        try:
            # Serialize value
            try:
                serialized = pickle.dumps(value)
            except (pickle.PickleError, TypeError):
                # Fallback to JSON
                serialized = json.dumps(value).encode('utf-8')
            
            # Set with optional condition
            kwargs = {"ex": ttl}
            if condition:
                kwargs[condition] = True
                
            result = await self._redis.set(full_key, serialized, **kwargs)
            return bool(result)
            
        except RedisError as e:
            logger.warning(f"Cache set error for key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if deleted
        """
        if not self._connected:
            await self.connect()
            
        full_key = self.config.key_prefix + key
        
        try:
            result = await self._redis.delete(full_key)
            return bool(result)
        except RedisError as e:
            logger.warning(f"Cache delete error for key {key}: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if exists
        """
        if not self._connected:
            await self.connect()
            
        full_key = self.config.key_prefix + key
        
        try:
            return bool(await self._redis.exists(full_key))
        except RedisError as e:
            logger.warning(f"Cache exists error for key {key}: {e}")
            return False
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set expiration on a key.
        
        Args:
            key: Cache key
            ttl: Time to live in seconds
            
        Returns:
            True if expiration set
        """
        if not self._connected:
            await self.connect()
            
        full_key = self.config.key_prefix + key
        
        try:
            return bool(await self._redis.expire(full_key, ttl))
        except RedisError as e:
            logger.warning(f"Cache expire error for key {key}: {e}")
            return False
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching pattern.
        
        Args:
            pattern: Key pattern (supports * wildcard)
            
        Returns:
            Number of keys deleted
        """
        if not self._connected:
            await self.connect()
            
        full_pattern = self.config.key_prefix + pattern
        
        try:
            # Use SCAN to find matching keys
            deleted = 0
            async for key in self._redis.scan_iter(match=full_pattern):
                if await self._redis.delete(key):
                    deleted += 1
            return deleted
            
        except RedisError as e:
            logger.warning(f"Cache invalidate pattern error for {pattern}: {e}")
            return 0
    
    async def get_ttl(self, key: str) -> Optional[int]:
        """Get remaining TTL for a key.
        
        Args:
            key: Cache key
            
        Returns:
            TTL in seconds or None if key doesn't exist
        """
        if not self._connected:
            await self.connect()
            
        full_key = self.config.key_prefix + key
        
        try:
            ttl = await self._redis.ttl(full_key)
            return ttl if ttl >= 0 else None
        except RedisError as e:
            logger.warning(f"Cache TTL error for key {key}: {e}")
            return None
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment a counter in cache.
        
        Args:
            key: Cache key
            amount: Amount to increment
            
        Returns:
            New value or None on error
        """
        if not self._connected:
            await self.connect()
            
        full_key = self.config.key_prefix + key
        
        try:
            return await self._redis.incrby(full_key, amount)
        except RedisError as e:
            logger.warning(f"Cache increment error for key {key}: {e}")
            return None
    
    async def get_many(self, keys: list[str]) -> dict[str, Any]:
        """Get multiple values from cache.
        
        Args:
            keys: List of cache keys
            
        Returns:
            Dictionary of key-value pairs
        """
        if not self._connected:
            await self.connect()
            
        if not keys:
            return {}
            
        full_keys = [self.config.key_prefix + key for key in keys]
        
        try:
            values = await self._redis.mget(full_keys)
            result = {}
            
            for key, value in zip(keys, values):
                if value is not None:
                    try:
                        result[key] = pickle.loads(value)
                    except pickle.PickleError:
                        result[key] = json.loads(value.decode('utf-8'))
                        
            return result
            
        except RedisError as e:
            logger.warning(f"Cache get_many error: {e}")
            return {}
    
    async def set_many(self, items: dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Set multiple values in cache.
        
        Args:
            items: Dictionary of key-value pairs
            ttl: Time to live in seconds
            
        Returns:
            True if all set successfully
        """
        if not self._connected:
            await self.connect()
            
        if not items:
            return True
            
        ttl = ttl or self.config.default_ttl
        
        try:
            # Use pipeline for atomic operation
            async with self._redis.pipeline() as pipe:
                for key, value in items.items():
                    full_key = self.config.key_prefix + key
                    
                    # Serialize value
                    try:
                        serialized = pickle.dumps(value)
                    except (pickle.PickleError, TypeError):
                        serialized = json.dumps(value).encode('utf-8')
                    
                    pipe.setex(full_key, ttl, serialized)
                
                results = await pipe.execute()
                return all(results)
                
        except RedisError as e:
            logger.warning(f"Cache set_many error: {e}")
            return False


def cached(
    ttl: Optional[int] = None,
    key_func: Optional[Callable] = None,
    condition: Optional[Callable] = None,
    cache_none: bool = False,
    cache_errors: bool = False,
):
    """Decorator for caching function results.
    
    Args:
        ttl: Time to live in seconds
        key_func: Function to generate cache key from arguments
        condition: Function to determine if result should be cached
        cache_none: Whether to cache None results
        cache_errors: Whether to cache exceptions
        
    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get cache instance (assume it's available in context)
            cache = getattr(wrapper, '_cache', None)
            if not cache:
                # No cache available, call function directly
                return await func(*args, **kwargs)
            
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default key generation
                func_name = f"{func.__module__}.{func.__name__}"
                args_str = str(args) + str(sorted(kwargs.items()))
                args_hash = hashlib.md5(args_str.encode()).hexdigest()[:8]
                cache_key = f"func:{func_name}:{args_hash}"
            
            # Try to get from cache
            cached_value = await cache.get(cache_key)
            if cached_value is not None:
                if isinstance(cached_value, dict) and cached_value.get('_is_exception'):
                    # Cached exception
                    raise cached_value['exception']
                return cached_value
            
            # Call function
            try:
                result = await func(*args, **kwargs)
                
                # Check if should cache
                should_cache = True
                if result is None and not cache_none:
                    should_cache = False
                if condition and not condition(result):
                    should_cache = False
                
                if should_cache:
                    await cache.set(cache_key, result, ttl=ttl)
                
                return result
                
            except Exception as e:
                if cache_errors:
                    # Cache the exception
                    await cache.set(
                        cache_key,
                        {'_is_exception': True, 'exception': e},
                        ttl=ttl or 300  # Default 5 min for errors
                    )
                raise
        
        return wrapper
    return decorator


class CacheManager:
    """Manager for cache instances and cache warming."""
    
    def __init__(self, cache: RedisCache):
        """Initialize cache manager.
        
        Args:
            cache: Redis cache instance
        """
        self.cache = cache
        self._warm_tasks: set[asyncio.Task] = set()
    
    async def warm_resource_cache(self, resource_type: str, resource_ids: list[str], region: str):
        """Warm cache for specific resources.
        
        Args:
            resource_type: Type of resources
            resource_ids: List of resource IDs
            region: AWS region
        """
        # This would be implemented to fetch and cache resource data
        logger.info(f"Warming cache for {len(resource_ids)} {resource_type} resources in {region}")
    
    async def invalidate_resource(self, resource_type: str, resource_id: str, region: Optional[str] = None):
        """Invalidate cache for a specific resource.
        
        Args:
            resource_type: Type of resource
            resource_id: Resource identifier
            region: AWS region
        """
        key = CacheKey.resource(resource_type, resource_id, region)
        await self.cache.delete(key)
        
        # Also invalidate related list operations
        pattern = f"list:{resource_type}:*"
        await self.cache.invalidate_pattern(pattern)
    
    async def invalidate_service(self, service: str):
        """Invalidate all cache entries for a service.
        
        Args:
            service: AWS service name
        """
        patterns = [
            f"api:{service}:*",
            f"list:{service}:*",
            f"resource:{service}:*",
        ]
        
        total_deleted = 0
        for pattern in patterns:
            deleted = await self.cache.invalidate_pattern(pattern)
            total_deleted += deleted
            
        logger.info(f"Invalidated {total_deleted} cache entries for service {service}")
    
    async def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache stats
        """
        if not self.cache._connected:
            await self.cache.connect()
            
        try:
            info = await self.cache._redis.info("stats")
            memory = await self.cache._redis.info("memory")
            
            return {
                "connected": True,
                "total_connections_received": info.get("total_connections_received", 0),
                "total_commands_processed": info.get("total_commands_processed", 0),
                "instantaneous_ops_per_sec": info.get("instantaneous_ops_per_sec", 0),
                "hit_rate": self._calculate_hit_rate(info),
                "memory_used": memory.get("used_memory_human", "0"),
                "memory_peak": memory.get("used_memory_peak_human", "0"),
                "keys": await self.cache._redis.dbsize(),
            }
        except RedisError as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {"connected": False, "error": str(e)}
    
    def _calculate_hit_rate(self, stats: dict[str, Any]) -> float:
        """Calculate cache hit rate from Redis stats."""
        hits = stats.get("keyspace_hits", 0)
        misses = stats.get("keyspace_misses", 0)
        total = hits + misses
        
        if total == 0:
            return 0.0
        
        return (hits / total) * 100