"""Monitoring and Metrics Collection Module

This module provides monitoring and metrics collection functionality for the
Threat Analysis MCP Server. It includes:

- System metrics collection (CPU, memory, disk usage)
- Request tracking and latency monitoring
- Threat score tracking
- Error tracking
- Health status monitoring
- Prometheus metrics integration
"""

import time
import psutil
import logging
from typing import Dict, Any
from datetime import datetime
from fastapi import Request
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import threading
import json
import os

# Prometheus metrics
REQUEST_COUNT = Counter('threat_analysis_requests_total', 'Total number of requests')
REQUEST_LATENCY = Histogram('threat_analysis_request_latency_seconds', 'Request latency in seconds')
THREAT_SCORE = Gauge('threat_analysis_score', 'Current threat score')
SYSTEM_MEMORY = Gauge('system_memory_usage_bytes', 'System memory usage')
SYSTEM_CPU = Gauge('system_cpu_usage_percent', 'System CPU usage')
ERROR_COUNT = Counter('threat_analysis_errors_total', 'Total number of errors')

class Monitoring:
    """Monitoring class for collecting and managing application metrics.
    
    This class handles:
    - System metrics collection
    - Request tracking
    - Threat score monitoring
    - Error tracking
    - Health status monitoring
    - Metrics persistence
    """
    
    def __init__(self):
        """Initialize monitoring system.
        
        Sets up:
        - Logging
        - Metrics file
        - System monitoring thread
        - Initial metrics collection
        """
        self.logger = logging.getLogger('threat_analysis.monitoring')
        self.metrics_file = 'logs/metrics.json'
        self._setup_metrics_file()
        self._lock = threading.Lock()
        self._collect_metrics()  # Collect metrics immediately
        self._start_system_monitoring()

    def _setup_metrics_file(self):
        """Initialize metrics file if it doesn't exist.
        
        Creates a new metrics file with initial structure if it doesn't exist,
        or validates and repairs existing metrics file.
        
        The metrics file structure includes:
        - Request counts
        - Error counts
        - Response time statistics
        - Threat score history
        - System metrics history
        """
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        initial_metrics = {
            'requests': 0,
            'errors': 0,
            'avg_response_time': 0,
            'max_response_time': 0,
            'threat_scores': [],
            'system_metrics': []
        }
        
        if not os.path.exists(self.metrics_file):
            with open(self.metrics_file, 'w') as f:
                json.dump(initial_metrics, f)
        else:
            try:
                with open(self.metrics_file, 'r') as f:
                    metrics = json.load(f)
                    # Ensure all required fields are present
                    for key in initial_metrics:
                        if key not in metrics:
                            metrics[key] = initial_metrics[key]
                with open(self.metrics_file, 'w') as f:
                    json.dump(metrics, f)
            except (json.JSONDecodeError, IOError):
                # If file is corrupted, recreate it
                with open(self.metrics_file, 'w') as f:
                    json.dump(initial_metrics, f)

    def _read_metrics(self) -> Dict[str, Any]:
        """Read metrics from file with proper locking.
        
        Returns:
            Dict[str, Any]: Current metrics data
            
        Note:
            Uses thread locking to prevent concurrent access issues
        """
        with self._lock:
            with open(self.metrics_file, 'r') as f:
                return json.load(f)

    def _write_metrics(self, metrics: Dict[str, Any]):
        """Write metrics to file with proper locking.
        
        Args:
            metrics (Dict[str, Any]): Metrics data to write
            
        Note:
            Uses thread locking to prevent concurrent access issues
        """
        with self._lock:
            with open(self.metrics_file, 'w') as f:
                json.dump(metrics, f)

    def _collect_metrics(self):
        """Collect system metrics.
        
        Collects:
        - Memory usage
        - CPU usage
        - Timestamp
        
        Updates the metrics file with new system metrics.
        """
        try:
            memory = psutil.virtual_memory()
            cpu = psutil.cpu_percent()
            metrics = self._read_metrics()
            metrics['system_metrics'].append({
                'timestamp': datetime.now().isoformat(),
                'memory_used': memory.used,
                'cpu_percent': cpu
            })
            self._write_metrics(metrics)
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {str(e)}")

    def _start_system_monitoring(self):
        """Start background thread for system metrics collection.
        
        Launches a daemon thread that collects system metrics every minute.
        The thread handles errors gracefully and increases retry delay on failure.
        """
        def collect_system_metrics():
            while True:
                try:
                    self._collect_metrics()
                    time.sleep(60)  # Collect every minute
                except Exception as e:
                    self.logger.error(f"Error collecting system metrics: {str(e)}")
                    time.sleep(300)  # Wait longer on error

        thread = threading.Thread(target=collect_system_metrics, daemon=True)
        thread.start()

    async def track_request(self, request: Request, response_time: float):
        """Track request metrics.
        
        Updates:
        - Request count
        - Response time statistics
        - Prometheus metrics
        
        Args:
            request (Request): The FastAPI request object
            response_time (float): Time taken to process the request
        """
        REQUEST_COUNT.inc()
        REQUEST_LATENCY.observe(response_time)
        
        # Update metrics file
        metrics = self._read_metrics()
        metrics['requests'] += 1
        metrics['avg_response_time'] = (
            (metrics['avg_response_time'] * (metrics['requests'] - 1) + response_time) 
            / metrics['requests']
        )
        metrics['max_response_time'] = max(metrics['max_response_time'], response_time)
        self._write_metrics(metrics)

    def track_threat_score(self, score: float):
        """Track threat score metrics.
        
        Updates:
        - Current threat score
        - Threat score history
        - Prometheus metrics
        
        Args:
            score (float): The threat score to track
        """
        THREAT_SCORE.set(score)
        
        # Update metrics file
        metrics = self._read_metrics()
        metrics['threat_scores'].append({
            'timestamp': datetime.now().isoformat(),
            'score': score
        })
        # Keep only last 1000 entries
        if len(metrics['threat_scores']) > 1000:
            metrics['threat_scores'] = metrics['threat_scores'][-1000:]
        self._write_metrics(metrics)

    def track_error(self, error_type: str):
        """Track error metrics.
        
        Updates:
        - Error count
        - Prometheus metrics
        
        Args:
            error_type (str): Type of error that occurred
        """
        ERROR_COUNT.inc()
        
        # Update metrics file
        metrics = self._read_metrics()
        metrics['errors'] += 1
        self._write_metrics(metrics)

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics.
        
        Returns:
            Dict[str, Any]: Current metrics including:
                - Request counts
                - Error counts
                - Response time statistics
                - Threat score history
                - System metrics history
        """
        return self._read_metrics()

    def get_health_status(self) -> Dict[str, Any]:
        """Get health status.
        
        Returns:
            Dict[str, Any]: Health status including:
                - System metrics (memory, CPU, disk)
                - Application stats (requests, errors, response times)
                - Current status
                - Timestamp
        """
        memory = psutil.virtual_memory()
        cpu = psutil.cpu_percent()
        
        return {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'system': {
                'memory_used_percent': memory.percent,
                'cpu_percent': cpu,
                'disk_usage_percent': psutil.disk_usage('/').percent
            },
            'application': {
                'requests_processed': REQUEST_COUNT._value.get(),
                'error_count': ERROR_COUNT._value.get(),
                'avg_response_time': REQUEST_LATENCY._sum.get() / max(1, REQUEST_COUNT._value.get())
            }
        }

# Initialize monitoring
monitoring = Monitoring() 