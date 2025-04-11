import pytest
from fastapi.testclient import TestClient
from src.app import app, analyze_text
from src.app import TextAnalysisRequest, TextAnalysisResponse

client = TestClient(app)


def test_benign_message():
    """Test analysis of a benign message."""
    response = client.post("/analyze", json={"text": "Hello, how are you today?"})
    assert response.status_code == 200
    data = response.json()
    assert data["threat_score"] == 0.0
    assert len(data["suspicious_patterns"]) == 0


def test_threatening_message():
    """Test analysis of a threatening message."""
    response = client.post(
        "/analyze", json={"text": "I will kill you and destroy everything"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["threat_score"] > 0.5
    assert "kill" in data["suspicious_patterns"]
    assert "destroy" in data["suspicious_patterns"]


def test_ambiguous_message():
    """Test analysis of an ambiguous message."""
    response = client.post(
        "/analyze", json={"text": "The company plans to destroy the old building"}
    )
    assert response.status_code == 200
    data = response.json()
    assert 0 < data["threat_score"] < 0.5
    assert "destroy" in data["suspicious_patterns"]


def test_empty_message():
    """Test analysis of an empty message."""
    response = client.post("/analyze", json={"text": ""})
    assert response.status_code == 422


def test_long_message():
    """Test analysis of a long message."""
    long_text = "This is a very long message " * 50
    response = client.post("/analyze", json={"text": long_text})
    assert response.status_code == 200
    data = response.json()
    assert data["threat_score"] is not None
    assert data["sentiment"] is not None


def test_special_characters():
    """Test analysis of a message with special characters."""
    response = client.post("/analyze", json={"text": "Hello! @#$%^&*()"})
    assert response.status_code == 200
    data = response.json()
    assert data["threat_score"] is not None
    assert data["sentiment"] is not None


def test_multiple_languages():
    """Test analysis of a message in multiple languages."""
    response = client.post("/analyze", json={"text": "Hello! 你好! Bonjour!"})
    assert response.status_code == 200
    data = response.json()
    assert data["threat_score"] is not None
    assert data["sentiment"] is not None


def test_response_structure():
    """Test the structure of the API response."""
    response = client.post("/analyze", json={"text": "Test message"})
    assert response.status_code == 200
    data = response.json()

    # Check all required fields are present
    assert "threat_score" in data
    assert "sentiment" in data
    assert "suspicious_patterns" in data
    assert "entities" in data
    assert "timestamp" in data

    # Check field types
    assert isinstance(data["threat_score"], float)
    assert isinstance(data["sentiment"], str)
    assert isinstance(data["suspicious_patterns"], list)
    assert isinstance(data["entities"], list)
    assert isinstance(data["timestamp"], str)


def test_health_endpoint():
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "uptime" in data
    assert "version" in data


def test_invalid_json():
    """Test handling of invalid JSON."""
    response = client.post("/analyze", data="invalid json")
    assert response.status_code == 422


def test_missing_text_field():
    """Test handling of missing text field."""
    response = client.post("/analyze", json={})
    assert response.status_code == 422


def test_very_short_message():
    """Test analysis of a very short message."""
    response = client.post("/analyze", json={"text": "Hi"})
    assert response.status_code == 200
    data = response.json()
    assert data["threat_score"] == 0.0


def test_unicode_characters():
    """Test analysis of a message with Unicode characters."""
    response = client.post("/analyze", json={"text": "Hello 🌍 World!"})
    assert response.status_code == 200
    data = response.json()
    assert data["threat_score"] is not None


def test_html_content():
    """Test analysis of a message containing HTML."""
    response = client.post("/analyze", json={"text": "<p>Hello <b>World</b></p>"})
    assert response.status_code == 200
    data = response.json()
    assert data["threat_score"] is not None


def test_response_time(test_client):
    """Test response time for different message lengths"""
    import time

    messages = ["Short message", "Medium message " * 10, "Long message " * 100]

    for message in messages:
        start_time = time.time()
        response = test_client.post("/analyze", json={"text": message})
        end_time = time.time()
        assert response.status_code == 200
        assert end_time - start_time < 2.0  # Response should be under 2 seconds
