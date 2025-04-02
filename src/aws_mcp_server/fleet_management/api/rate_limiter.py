"""
Rate Limiter for API Server.

This module provides rate limiting capabilities for the API layer.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

from fastapi import HTTPException, Request, status

from .auth import User

logger = logging.getLogger(__name__)


class RateLimitStrategy(Enum):
    """Rate limiting strategies."""
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    enabled: bool = True
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW
    requests_per_minute: int = 60
    burst_limit: int = 100
    token_refill_rate: float = 1.0  # Tokens per second
    window_size: int = 60  # Window size in seconds
    max_delay: int = 5  # Maximum delay in seconds for retries
    cleanup_interval: int = 300  # Interval in seconds to clean up expired records


@dataclass
class UserRateLimit:
    """Rate limit configuration for a specific user or role."""
    user_id: Optional[str] = None
    role: Optional[str] = None
    requests_per_minute: int = 60
    burst_limit: int = 100


class RateLimiter:
    """
    Rate limiter for API requests.
    
    Implements various rate limiting strategies to prevent abuse
    and ensure fair usage of resources.
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        """Initialize the rate limiter."""
        self.config = config or RateLimitConfig()
        
        # Track request counts by user ID and IP address
        self.user_request_counts: Dict[str, List[float]] = {}
        self.ip_request_counts: Dict[str, List[float]] = {}
        
        # Token bucket state
        self.user_tokens: Dict[str, Tuple[float, float]] = {}  # (tokens, last_refill_time)
        self.ip_tokens: Dict[str, Tuple[float, float]] = {}    # (tokens, last_refill_time)
        
        # Custom rate limits by user ID and role
        self.user_rate_limits: Dict[str, UserRateLimit] = {}
        self.role_rate_limits: Dict[str, UserRateLimit] = {}
        
        # Start cleanup task
        if self.config.enabled:
            asyncio.create_task(self._cleanup_loop())
    
    async def _cleanup_loop(self):
        """Periodically clean up expired rate limit records."""
        while True:
            await asyncio.sleep(self.config.cleanup_interval)
            
            try:
                now = time.time()
                window_start = now - self.config.window_size
                
                # Clean up user request counts
                for user_id, timestamps in list(self.user_request_counts.items()):
                    self.user_request_counts[user_id] = [ts for ts in timestamps if ts >= window_start]
                    if not self.user_request_counts[user_id]:
                        del self.user_request_counts[user_id]
                
                # Clean up IP request counts
                for ip, timestamps in list(self.ip_request_counts.items()):
                    self.ip_request_counts[ip] = [ts for ts in timestamps if ts >= window_start]
                    if not self.ip_request_counts[ip]:
                        del self.ip_request_counts[ip]
                
                # No need to clean up token buckets, they're refilled on demand
                
                logger.debug(f"Rate limiter cleanup completed. {len(self.user_request_counts)} user records, "
                             f"{len(self.ip_request_counts)} IP records remaining.")
            except Exception as e:
                logger.error(f"Error in rate limiter cleanup: {e}")
    
    def _get_rate_limits(self, user: Optional[User]) -> Tuple[int, int]:
        """
        Get rate limits for a user based on user ID and roles.
        
        Args:
            user: User making the request
            
        Returns:
            Tuple of (requests_per_minute, burst_limit)
        """
        if not user:
            return self.config.requests_per_minute, self.config.burst_limit
        
        # Check for user-specific rate limits
        if user.id in self.user_rate_limits:
            user_limit = self.user_rate_limits[user.id]
            return user_limit.requests_per_minute, user_limit.burst_limit
        
        # Check for role-based rate limits
        for role in user.roles:
            if role in self.role_rate_limits:
                role_limit = self.role_rate_limits[role]
                return role_limit.requests_per_minute, role_limit.burst_limit
        
        # Default to global limits
        return self.config.requests_per_minute, self.config.burst_limit
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Get the client IP address from the request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Client IP address as string
        """
        # Check for X-Forwarded-For header
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Return the first IP in the list
            return forwarded_for.split(",")[0].strip()
        
        # Fall back to client.host
        client_host = request.client.host if request.client else "unknown"
        return client_host
    
    async def _check_fixed_window(self, key: str, request_counts: Dict[str, List[float]], 
                                 requests_per_minute: int, burst_limit: int) -> bool:
        """
        Check rate limit using fixed window strategy.
        
        Args:
            key: Identifier for the requester (user ID or IP)
            request_counts: Dictionary of request timestamps
            requests_per_minute: Maximum requests per minute
            burst_limit: Maximum burst of requests
            
        Returns:
            True if request is allowed, False otherwise
        """
        now = time.time()
        minute_start = int(now) - (int(now) % 60)  # Start of the current minute
        
        # Get timestamps in the current window
        if key not in request_counts:
            request_counts[key] = []
            
        # Filter timestamps to current minute
        timestamps = [ts for ts in request_counts[key] if ts >= minute_start]
        request_counts[key] = timestamps
        
        # Check against limits
        count = len(timestamps)
        if count >= requests_per_minute:
            return False
            
        # Record this request
        request_counts[key].append(now)
        return True
    
    async def _check_sliding_window(self, key: str, request_counts: Dict[str, List[float]], 
                                   requests_per_minute: int, burst_limit: int) -> bool:
        """
        Check rate limit using sliding window strategy.
        
        Args:
            key: Identifier for the requester (user ID or IP)
            request_counts: Dictionary of request timestamps
            requests_per_minute: Maximum requests per minute
            burst_limit: Maximum burst of requests
            
        Returns:
            True if request is allowed, False otherwise
        """
        now = time.time()
        window_start = now - self.config.window_size
        
        # Get timestamps in the current window
        if key not in request_counts:
            request_counts[key] = []
            
        # Filter timestamps to current window
        timestamps = [ts for ts in request_counts[key] if ts >= window_start]
        request_counts[key] = timestamps
        
        # Check against limits
        count = len(timestamps)
        if count >= requests_per_minute:
            return False
            
        # Check burst limit
        recent_window = now - 1  # Last second
        recent_count = len([ts for ts in timestamps if ts >= recent_window])
        if recent_count >= burst_limit:
            return False
            
        # Record this request
        request_counts[key].append(now)
        return True
    
    async def _check_token_bucket(self, key: str, token_buckets: Dict[str, Tuple[float, float]], 
                                 requests_per_minute: int, burst_limit: int) -> bool:
        """
        Check rate limit using token bucket strategy.
        
        Args:
            key: Identifier for the requester (user ID or IP)
            token_buckets: Dictionary of token bucket states
            requests_per_minute: Maximum requests per minute
            burst_limit: Maximum burst of requests
            
        Returns:
            True if request is allowed, False otherwise
        """
        now = time.time()
        
        # Initialize token bucket if needed
        if key not in token_buckets:
            token_buckets[key] = (burst_limit, now)
            
        tokens, last_refill = token_buckets[key]
        
        # Calculate tokens to add based on time since last refill
        refill_rate = self.config.token_refill_rate
        tokens_to_add = (now - last_refill) * refill_rate
        
        # Refill tokens (capped at burst limit)
        tokens = min(tokens + tokens_to_add, burst_limit)
        
        # Check if enough tokens available
        if tokens < 1:
            return False
            
        # Consume one token
        tokens -= 1
        
        # Update token bucket state
        token_buckets[key] = (tokens, now)
        return True
    
    async def _check_leaky_bucket(self, key: str, request_counts: Dict[str, List[float]], 
                                 requests_per_minute: int, burst_limit: int) -> bool:
        """
        Check rate limit using leaky bucket strategy.
        
        Args:
            key: Identifier for the requester (user ID or IP)
            request_counts: Dictionary of request timestamps
            requests_per_minute: Maximum requests per minute
            burst_limit: Maximum burst of requests
            
        Returns:
            True if request is allowed, False otherwise
        """
        now = time.time()
        
        # Get timestamps in the current window
        if key not in request_counts:
            request_counts[key] = []
            
        # Calculate leak rate (requests per second)
        leak_rate = requests_per_minute / 60.0
        
        # Calculate the theoretical number of leaked requests since the oldest timestamp
        timestamps = sorted(request_counts[key])
        if timestamps:
            oldest_timestamp = timestamps[0]
            time_diff = now - oldest_timestamp
            leaked = int(time_diff * leak_rate)
            
            # Remove leaked requests
            if leaked >= len(timestamps):
                timestamps = []
            else:
                timestamps = timestamps[leaked:]
        
        # Check against burst limit
        if len(timestamps) >= burst_limit:
            return False
            
        # Record this request
        timestamps.append(now)
        request_counts[key] = timestamps
        return True
    
    async def check_rate_limit(self, request: Request, user: Optional[User] = None) -> None:
        """
        Check if a request exceeds rate limits and raise an exception if it does.
        
        Args:
            request: FastAPI request object
            user: Optional user making the request
            
        Raises:
            HTTPException: If rate limit is exceeded
        """
        if not self.config.enabled:
            return
            
        # Get rate limits for this user
        requests_per_minute, burst_limit = self._get_rate_limits(user)
        
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # Check user limits if user is authenticated
        allowed = True
        if user:
            user_key = f"user:{user.id}"
            allowed = await self._check_rate_limit(user_key, self.user_request_counts, self.user_tokens, 
                                              requests_per_minute, burst_limit)
        
        # Always check IP limits as well
        ip_key = f"ip:{client_ip}"
        ip_allowed = await self._check_rate_limit(ip_key, self.ip_request_counts, self.ip_tokens, 
                                            self.config.requests_per_minute, self.config.burst_limit)
        
        # If either check fails, rate limit is exceeded
        if not allowed or not ip_allowed:
            logger.warning(f"Rate limit exceeded: {user.id if user else 'anonymous'} from {client_ip}")
            
            # Calculate retry-after time
            retry_after = self._calculate_retry_after(user.id if user else None, client_ip)
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later.",
                headers={"Retry-After": str(retry_after)}
            )
    
    async def _check_rate_limit(self, key: str, request_counts: Dict[str, List[float]], 
                              token_buckets: Dict[str, Tuple[float, float]],
                              requests_per_minute: int, burst_limit: int) -> bool:
        """
        Check rate limit using the configured strategy.
        
        Args:
            key: Identifier for the requester
            request_counts: Dictionary of request timestamps
            token_buckets: Dictionary of token bucket states
            requests_per_minute: Maximum requests per minute
            burst_limit: Maximum burst of requests
            
        Returns:
            True if request is allowed, False otherwise
        """
        strategy = self.config.strategy
        
        if strategy == RateLimitStrategy.FIXED_WINDOW:
            return await self._check_fixed_window(key, request_counts, requests_per_minute, burst_limit)
            
        elif strategy == RateLimitStrategy.SLIDING_WINDOW:
            return await self._check_sliding_window(key, request_counts, requests_per_minute, burst_limit)
            
        elif strategy == RateLimitStrategy.TOKEN_BUCKET:
            return await self._check_token_bucket(key, token_buckets, requests_per_minute, burst_limit)
            
        elif strategy == RateLimitStrategy.LEAKY_BUCKET:
            return await self._check_leaky_bucket(key, request_counts, requests_per_minute, burst_limit)
            
        # Default to sliding window
        return await self._check_sliding_window(key, request_counts, requests_per_minute, burst_limit)
    
    def _calculate_retry_after(self, user_id: Optional[str], client_ip: str) -> int:
        """
        Calculate the time in seconds before a client should retry.
        
        Args:
            user_id: Optional user ID
            client_ip: Client IP address
            
        Returns:
            Seconds to wait before retrying
        """
        now = time.time()
        user_key = f"user:{user_id}" if user_id else None
        ip_key = f"ip:{client_ip}"
        
        if self.config.strategy in [RateLimitStrategy.FIXED_WINDOW, RateLimitStrategy.SLIDING_WINDOW]:
            if user_key and user_key in self.user_request_counts:
                timestamps = sorted(self.user_request_counts[user_key])
                if timestamps:
                    # For fixed window, wait until the start of the next minute
                    if self.config.strategy == RateLimitStrategy.FIXED_WINDOW:
                        next_window = (int(now) - (int(now) % 60)) + 60
                        return max(1, min(int(next_window - now) + 1, self.config.max_delay))
                    
                    # For sliding window, wait until enough requests expire from the window
                    future_window_start = now + 1 - self.config.window_size
                    new_count = len([ts for ts in timestamps if ts >= future_window_start])
                    
                    # If the rate limit would still be exceeded, return rate limit exceeded
                    if new_count >= requests_per_minute:
                        raise HTTPException(
                            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail=f"Rate limit exceeded for endpoint: {endpoint}"
                        )
            
            # Check IP rate limits as well
            if ip_key in self.ip_request_counts:
                timestamps = sorted(self.ip_request_counts[ip_key])
                if timestamps:
                    # For sliding window, similar calculation as above but for IP
                    if self.config.strategy == RateLimitStrategy.SLIDING_WINDOW:
                        future_window_start = now + 1 - self.config.window_size
                        new_count = len([ts for ts in timestamps if ts >= future_window_start])
                        if new_count >= self.config.requests_per_minute:
                            expired_needed = new_count - self.config.requests_per_minute + 1
                            if expired_needed > 0 and len(timestamps) >= expired_needed:
                                time_until_expire = timestamps[expired_needed - 1] + self.config.window_size - now
                                return max(1, min(int(time_until_expire) + 1, self.config.max_delay))
        
        elif self.config.strategy == RateLimitStrategy.TOKEN_BUCKET:
            if user_key and user_key in self.user_tokens:
                tokens, last_refill = self.user_tokens[user_key]
                if tokens < 1:
                    time_until_refill = (1 - tokens) / self.config.token_refill_rate
                    return max(1, min(int(time_until_refill) + 1, self.config.max_delay))
            
            if ip_key in self.ip_tokens:
                tokens, last_refill = self.ip_tokens[ip_key]
                if tokens < 1:
                    time_until_refill = (1 - tokens) / self.config.token_refill_rate
                    return max(1, min(int(time_until_refill) + 1, self.config.max_delay))
        
        # Default retry after
        return self.config.max_delay
    
    async def set_user_rate_limit(self, user_rate_limit: UserRateLimit) -> None:
        """
        Set a custom rate limit for a specific user.
        
        Args:
            user_rate_limit: User rate limit configuration
        """
        if user_rate_limit.user_id:
            self.user_rate_limits[user_rate_limit.user_id] = user_rate_limit
        elif user_rate_limit.role:
            self.role_rate_limits[user_rate_limit.role] = user_rate_limit
    
    async def remove_user_rate_limit(self, user_id: Optional[str] = None, role: Optional[str] = None) -> bool:
        """
        Remove a custom rate limit for a user or role.
        
        Args:
            user_id: Optional user ID
            role: Optional role name
            
        Returns:
            True if removed, False if not found
        """
        if user_id and user_id in self.user_rate_limits:
            del self.user_rate_limits[user_id]
            return True
            
        if role and role in self.role_rate_limits:
            del self.role_rate_limits[role]
            return True
            
        return False 