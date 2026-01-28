"""
Monitoring, observability, and structured logging for the Rootly MCP Server.

This module provides:
- Structured JSON logging with correlation IDs
- Request/response logging (sanitized)
- Performance metrics collection
- Health check utilities
"""

import json
import logging
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from contextlib import contextmanager
from functools import wraps
from threading import Lock
from typing import Any

from .security import mask_sensitive_data

# Correlation ID storage (thread-local would be better in production)
_correlation_ids: dict[int, str] = {}
_correlation_lock = Lock()


def get_correlation_id() -> str:
    """Get or create a correlation ID for the current request."""
    import threading

    thread_id = threading.get_ident()

    with _correlation_lock:
        if thread_id not in _correlation_ids:
            _correlation_ids[thread_id] = str(uuid.uuid4())
        return _correlation_ids[thread_id]


def set_correlation_id(correlation_id: str) -> None:
    """Set the correlation ID for the current request."""
    import threading

    thread_id = threading.get_ident()

    with _correlation_lock:
        _correlation_ids[thread_id] = correlation_id


def clear_correlation_id() -> None:
    """Clear the correlation ID for the current request."""
    import threading

    thread_id = threading.get_ident()

    with _correlation_lock:
        _correlation_ids.pop(thread_id, None)


class StructuredLogger:
    """
    Structured JSON logger with correlation ID support.

    Provides consistent structured logging across the application.
    """

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.name = name

    def _log_structured(
        self,
        level: int,
        message: str,
        extra: dict[str, Any] | None = None,
        exc_info: Exception | None = None,
    ) -> None:
        """Log a structured message with correlation ID and metadata."""
        log_data = {
            "message": message,
            "correlation_id": get_correlation_id(),
            "logger": self.name,
            "timestamp": time.time(),
        }

        if extra:
            # Mask sensitive data before logging
            log_data["extra"] = mask_sensitive_data(extra)

        # Use standard logger with JSON-formatted message
        self.logger.log(
            level,
            json.dumps(log_data),
            exc_info=exc_info,
        )

    def debug(self, message: str, **kwargs) -> None:
        """Log a debug message."""
        self._log_structured(logging.DEBUG, message, extra=kwargs)

    def info(self, message: str, **kwargs) -> None:
        """Log an info message."""
        self._log_structured(logging.INFO, message, extra=kwargs)

    def warning(self, message: str, **kwargs) -> None:
        """Log a warning message."""
        self._log_structured(logging.WARNING, message, extra=kwargs)

    def error(self, message: str, exc_info: Exception | None = None, **kwargs) -> None:
        """Log an error message."""
        self._log_structured(logging.ERROR, message, extra=kwargs, exc_info=exc_info)

    def critical(self, message: str, exc_info: Exception | None = None, **kwargs) -> None:
        """Log a critical message."""
        self._log_structured(logging.CRITICAL, message, extra=kwargs, exc_info=exc_info)


class MetricsCollector:
    """
    Simple metrics collector for tracking request statistics.

    Tracks:
    - Request counts by endpoint and status
    - Response latencies (p50, p95, p99)
    - Error rates
    - Active connections
    """

    def __init__(self):
        self._lock = Lock()
        self._request_counts: dict[str, int] = defaultdict(int)
        self._error_counts: dict[str, int] = defaultdict(int)
        self._latencies: dict[str, list[float]] = defaultdict(list)
        self._active_requests = 0
        self._max_latency_samples = 1000  # Keep last 1000 samples per endpoint

    def increment_requests(self, endpoint: str, status_code: int) -> None:
        """Increment request counter for an endpoint."""
        with self._lock:
            key = f"{endpoint}:{status_code}"
            self._request_counts[key] += 1

            if status_code >= 400:
                self._error_counts[endpoint] += 1

    def record_latency(self, endpoint: str, latency_ms: float) -> None:
        """Record request latency for an endpoint."""
        with self._lock:
            self._latencies[endpoint].append(latency_ms)

            # Keep only recent samples
            if len(self._latencies[endpoint]) > self._max_latency_samples:
                self._latencies[endpoint] = self._latencies[endpoint][-self._max_latency_samples :]

    def increment_active_requests(self) -> None:
        """Increment active request counter."""
        with self._lock:
            self._active_requests += 1

    def decrement_active_requests(self) -> None:
        """Decrement active request counter."""
        with self._lock:
            self._active_requests = max(0, self._active_requests - 1)

    def get_metrics(self) -> dict[str, Any]:
        """Get current metrics snapshot."""
        with self._lock:
            # Calculate latency percentiles
            latency_stats = {}
            for endpoint, latencies in self._latencies.items():
                if latencies:
                    sorted_latencies = sorted(latencies)
                    latency_stats[endpoint] = {
                        "p50": self._percentile(sorted_latencies, 50),
                        "p95": self._percentile(sorted_latencies, 95),
                        "p99": self._percentile(sorted_latencies, 99),
                        "count": len(latencies),
                    }

            return {
                "request_counts": dict(self._request_counts),
                "error_counts": dict(self._error_counts),
                "latency_stats": latency_stats,
                "active_requests": self._active_requests,
            }

    def _percentile(self, sorted_values: list[float], percentile: int) -> float:
        """Calculate percentile from sorted values."""
        if not sorted_values:
            return 0.0

        index = int(len(sorted_values) * percentile / 100)
        index = min(index, len(sorted_values) - 1)
        return sorted_values[index]

    def reset(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self._request_counts.clear()
            self._error_counts.clear()
            self._latencies.clear()
            self._active_requests = 0


# Global metrics collector
_metrics_collector = MetricsCollector()


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance."""
    return _metrics_collector


@contextmanager
def track_request(endpoint: str):
    """
    Context manager to track request metrics.

    Usage:
        with track_request("/api/incidents"):
            # ... make request ...
            pass
    """
    collector = get_metrics_collector()
    collector.increment_active_requests()
    start_time = time.time()
    status_code = 200  # Default

    try:
        yield
    except Exception:
        status_code = 500
        raise
    finally:
        latency_ms = (time.time() - start_time) * 1000
        collector.record_latency(endpoint, latency_ms)
        collector.increment_requests(endpoint, status_code)
        collector.decrement_active_requests()


def log_request(logger: StructuredLogger):
    """
    Decorator to log requests and responses.

    Args:
        logger: StructuredLogger instance to use
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Generate new correlation ID for this request
            set_correlation_id(str(uuid.uuid4()))

            # Log request
            logger.info(
                f"Request started: {func.__name__}",
                function=func.__name__,
                args_count=len(args),
                kwargs_keys=list(kwargs.keys()),
            )

            start_time = time.time()
            try:
                result = await func(*args, **kwargs)

                # Log success
                duration_ms = (time.time() - start_time) * 1000
                logger.info(
                    f"Request completed: {func.__name__}",
                    function=func.__name__,
                    duration_ms=duration_ms,
                    status="success",
                )

                return result

            except Exception as e:
                # Log error
                duration_ms = (time.time() - start_time) * 1000
                logger.error(
                    f"Request failed: {func.__name__}",
                    exc_info=e,
                    function=func.__name__,
                    duration_ms=duration_ms,
                    status="error",
                    error_type=type(e).__name__,
                )
                raise

            finally:
                clear_correlation_id()

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Generate new correlation ID for this request
            set_correlation_id(str(uuid.uuid4()))

            # Log request
            logger.info(
                f"Request started: {func.__name__}",
                function=func.__name__,
                args_count=len(args),
                kwargs_keys=list(kwargs.keys()),
            )

            start_time = time.time()
            try:
                result = func(*args, **kwargs)

                # Log success
                duration_ms = (time.time() - start_time) * 1000
                logger.info(
                    f"Request completed: {func.__name__}",
                    function=func.__name__,
                    duration_ms=duration_ms,
                    status="success",
                )

                return result

            except Exception as e:
                # Log error
                duration_ms = (time.time() - start_time) * 1000
                logger.error(
                    f"Request failed: {func.__name__}",
                    exc_info=e,
                    function=func.__name__,
                    duration_ms=duration_ms,
                    status="error",
                    error_type=type(e).__name__,
                )
                raise

            finally:
                clear_correlation_id()

        # Return appropriate wrapper based on function type
        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


def get_health_status() -> dict[str, Any]:
    """
    Get health check status of the server.

    Returns:
        Dictionary with health status information
    """
    metrics = get_metrics_collector().get_metrics()

    # Calculate overall health based on error rate
    total_requests = sum(metrics["request_counts"].values())
    total_errors = sum(metrics["error_counts"].values())

    error_rate = (total_errors / total_requests * 100) if total_requests > 0 else 0

    # Determine status based on error rate
    if error_rate > 50:
        status = "unhealthy"
    elif error_rate > 10:
        status = "degraded"
    else:
        status = "healthy"

    return {
        "status": status,
        "error_rate_percent": round(error_rate, 2),
        "active_requests": metrics["active_requests"],
        "total_requests": total_requests,
        "total_errors": total_errors,
    }
