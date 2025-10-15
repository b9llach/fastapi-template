"""
Rate Limiting Middleware
"""
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import time
from collections import defaultdict
from typing import Dict, Tuple

from app.core.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware using in-memory storage
    For production, consider using Redis for distributed rate limiting
    """

    def __init__(self, app):
        super().__init__(app)
        # Store: {client_ip: [(timestamp, count), ...]}
        self.requests: Dict[str, list[Tuple[float, int]]] = defaultdict(list)
        self.rate_limit = settings.RATE_LIMIT_PER_MINUTE
        self.window = 60  # 60 seconds window

    async def dispatch(self, request: Request, call_next):
        """
        Process request and check rate limit
        """
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)

        # Get client IP
        client_ip = request.client.host if request.client else "unknown"

        # Skip rate limiting for health checks
        if request.url.path in ["/", "/api/v1/health", "/api/docs", "/api/redoc"]:
            return await call_next(request)

        # Check rate limit
        current_time = time.time()

        # Clean old requests outside the window
        self.requests[client_ip] = [
            (timestamp, count)
            for timestamp, count in self.requests[client_ip]
            if current_time - timestamp < self.window
        ]

        # Count requests in current window
        request_count = sum(count for _, count in self.requests[client_ip])

        if request_count >= self.rate_limit:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Please try again later.",
                    "rate_limit": self.rate_limit,
                    "window": f"{self.window}s"
                }
            )

        # Add current request
        self.requests[client_ip].append((current_time, 1))

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.rate_limit)
        response.headers["X-RateLimit-Remaining"] = str(
            max(0, self.rate_limit - request_count - 1)
        )
        response.headers["X-RateLimit-Reset"] = str(
            int(current_time + self.window)
        )

        return response
