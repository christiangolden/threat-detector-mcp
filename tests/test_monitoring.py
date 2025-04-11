import pytest
from fastapi.testclient import TestClient
from src.monitoring import monitoring
import time
import json
import os

def test_metrics_file_creation():
    """Test that metrics file is created properly"""
    assert os.path.exists('logs/metrics.json')
    with open('logs/metrics.json', 'r') as f:
        metrics = json.load(f)
        assert 'requests' in metrics
        assert 'errors' in metrics
        assert 'avg_response_time' in metrics
        assert 'max_response_time' in metrics
        assert 'threat_scores' in metrics
        assert 'system_metrics' in metrics

def test_request_tracking(test_client):
    """Test request tracking functionality"""
    response = test_client.post(
        "/analyze",
        json={"text": "Test message"}
    )
    assert response.status_code == 200
    
    metrics = monitoring.get_metrics()
    assert metrics['requests'] > 0
    assert metrics['avg_response_time'] > 0

def test_threat_score_tracking(test_client):
    """Test threat score tracking"""
    monitoring.track_threat_score(0.5)
    
    metrics = monitoring.get_metrics()
    assert len(metrics['threat_scores']) > 0
    assert metrics['threat_scores'][-1]['score'] == 0.5

def test_error_tracking(test_client):
    """Test error tracking"""
    monitoring.track_error("TestError")
    
    metrics = monitoring.get_metrics()
    assert metrics['errors'] > 0

def test_health_check(test_client):
    """Test health check endpoint"""
    response = test_client.get("/health")
    assert response.status_code == 200
    
    health_data = response.json()
    assert 'status' in health_data
    assert 'system' in health_data
    assert 'application' in health_data
    assert health_data['status'] == 'healthy'

def test_metrics_endpoint(test_client):
    """Test metrics endpoint"""
    response = test_client.get("/metrics")
    assert response.status_code == 200
    
    metrics = response.json()
    assert 'requests' in metrics
    assert 'errors' in metrics
    assert 'avg_response_time' in metrics
    assert 'max_response_time' in metrics
    assert 'threat_scores' in metrics
    assert 'system_metrics' in metrics

def test_process_time_header(test_client):
    """Test that process time is added to response headers"""
    response = test_client.post(
        "/analyze",
        json={"text": "Test message"}
    )
    assert response.status_code == 200
    assert 'X-Process-Time' in response.headers
    assert float(response.headers['X-Process-Time']) > 0

def test_system_metrics_collection():
    """Test system metrics collection"""
    # Wait for at least one collection cycle
    time.sleep(65)
    
    metrics = monitoring.get_metrics()
    assert len(metrics['system_metrics']) > 0
    assert 'memory_used' in metrics['system_metrics'][0]
    assert 'cpu_percent' in metrics['system_metrics'][0] 