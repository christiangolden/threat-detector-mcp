import pytest
import json
from typing import Dict, Any

class TestThreatAnalysis:
    def test_benign_message(self, test_client):
        """Test analysis of a benign message"""
        response = test_client.post(
            "/analyze",
            json={"text": "I'm going to have lunch with my friends at the park."}
        )
        assert response.status_code == 200
        result = response.json()
        assert result['threat_score'] == 0.0
        assert len(result['suspicious_patterns']) == 0
        assert result['sentiment']['compound'] >= 0
    
    def test_threatening_message(self, test_client):
        """Test analysis of a threatening message"""
        response = test_client.post(
            "/analyze",
            json={"text": "We need to destroy the target building and execute our plan."}
        )
        assert response.status_code == 200
        result = response.json()
        assert result['threat_score'] > 0.5
        assert len(result['suspicious_patterns']) > 0
        assert result['sentiment']['compound'] < 0
    
    def test_ambiguous_message(self, test_client):
        """Test analysis of an ambiguous message"""
        response = test_client.post(
            "/analyze",
            json={"text": "The band will destroy the stage with their amazing performance!"}
        )
        assert response.status_code == 200
        result = response.json()
        assert result['threat_score'] > 0
        assert result['threat_score'] < 0.5
        assert 'destroy' in result['suspicious_patterns']
    
    def test_empty_message(self, test_client):
        """Test handling of empty message"""
        response = test_client.post(
            "/analyze",
            json={"text": ""}
        )
        assert response.status_code == 422
    
    def test_long_message(self, test_client):
        """Test handling of a long message"""
        long_text = "This is a very long message. " * 100
        response = test_client.post(
            "/analyze",
            json={"text": long_text}
        )
        assert response.status_code == 200
        result = response.json()
        assert result['threat_score'] is not None
        assert result['sentiment'] is not None
    
    def test_special_characters(self, test_client):
        """Test handling of special characters"""
        response = test_client.post(
            "/analyze",
            json={"text": "!@#$%^&* Testing special ch@racters *&^%$#@!"}
        )
        assert response.status_code == 200
        result = response.json()
        assert result['threat_score'] is not None
        assert result['sentiment'] is not None
    
    def test_multiple_languages(self, test_client):
        """Test handling of non-English text"""
        response = test_client.post(
            "/analyze",
            json={"text": "Bonjour! Hello! ¡Hola! Здравствуйте!"}
        )
        assert response.status_code == 200
        result = response.json()
        assert result['threat_score'] is not None
        assert result['sentiment'] is not None
    
    def test_response_structure(self, test_client):
        """Test the structure of the API response"""
        response = test_client.post(
            "/analyze",
            json={"text": "Test message"}
        )
        assert response.status_code == 200
        result = response.json()
        required_fields = ['threat_score', 'suspicious_patterns', 'confidence', 
                         'sentiment', 'entities', 'pos_tags']
        for field in required_fields:
            assert field in result
        
        assert isinstance(result['threat_score'], float)
        assert isinstance(result['suspicious_patterns'], list)
        assert isinstance(result['confidence'], float)
        assert isinstance(result['sentiment'], dict)
        assert isinstance(result['entities'], list)
        assert isinstance(result['pos_tags'], list)

    def test_metadata_handling(self, test_client):
        """Test handling of metadata in request"""
        response = test_client.post(
            "/analyze",
            json={
                "text": "Test message",
                "metadata": {
                    "source": "test",
                    "timestamp": "2024-04-11T12:00:00Z"
                }
            }
        )
        assert response.status_code == 200
        result = response.json()
        assert result['threat_score'] is not None

    def test_health_endpoint(self, test_client):
        """Test health check endpoint"""
        response = test_client.get("/health")
        assert response.status_code == 200
        health_data = response.json()
        assert 'status' in health_data
        assert 'system' in health_data
        assert 'application' in health_data
        assert health_data['status'] == 'healthy'

    def test_invalid_json(self, test_client):
        """Test handling of invalid JSON"""
        response = test_client.post(
            "/analyze",
            content="invalid json"
        )
        assert response.status_code == 422

    def test_missing_text_field(self, test_client):
        """Test handling of missing text field"""
        response = test_client.post(
            "/analyze",
            json={"metadata": {}}
        )
        assert response.status_code == 422

    def test_very_short_message(self, test_client):
        """Test handling of very short messages"""
        response = test_client.post(
            "/analyze",
            json={"text": "Hi"}
        )
        assert response.status_code == 200
        result = response.json()
        assert result['threat_score'] == 0.0

    def test_unicode_characters(self, test_client):
        """Test handling of Unicode characters"""
        response = test_client.post(
            "/analyze",
            json={"text": "Hello 🌍 World! 😊"}
        )
        assert response.status_code == 200
        result = response.json()
        assert result['threat_score'] is not None

    def test_html_content(self, test_client):
        """Test handling of HTML content"""
        response = test_client.post(
            "/analyze",
            json={"text": "<p>Hello <b>World</b>!</p>"}
        )
        assert response.status_code == 200
        result = response.json()
        assert result['threat_score'] is not None 

    def test_metadata_validation(self, test_client):
        """Test validation of metadata fields"""
        response = test_client.post(
            "/analyze",
            json={
                "text": "Test message",
                "metadata": {
                    "source": "test",
                    "timestamp": "2024-04-11T12:00:00Z",
                    "user_id": "12345"
                }
            }
        )
        assert response.status_code == 200
        result = response.json()
        assert result['threat_score'] is not None

    def test_rate_limiting(self, test_client):
        """Test handling of rapid consecutive requests"""
        for _ in range(5):
            response = test_client.post(
                "/analyze",
                json={"text": "Test message"}
            )
            assert response.status_code == 200

    def test_malformed_metadata(self, test_client):
        """Test handling of malformed metadata"""
        response = test_client.post(
            "/analyze",
            json={
                "text": "Test message",
                "metadata": "invalid_metadata"
            }
        )
        assert response.status_code == 422

    def test_large_metadata(self, test_client):
        """Test handling of large metadata objects"""
        large_metadata = {"key" + str(i): "value" * 100 for i in range(100)}
        response = test_client.post(
            "/analyze",
            json={
                "text": "Test message",
                "metadata": large_metadata
            }
        )
        assert response.status_code == 200

    def test_concurrent_requests(self, test_client):
        """Test handling of concurrent requests"""
        import concurrent.futures
        
        def make_request():
            return test_client.post(
                "/analyze",
                json={"text": "Test message"}
            )
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request) for _ in range(5)]
            results = [future.result() for future in futures]
            
        for response in results:
            assert response.status_code == 200

    def test_error_handling(self, test_client):
        """Test error handling and response format"""
        response = test_client.post(
            "/analyze",
            json={"text": "Test message" * 1000}  # Exceeds length limit
        )
        assert response.status_code == 422
        error_data = response.json()
        assert "detail" in error_data
        assert isinstance(error_data["detail"], list)  # FastAPI returns a list of validation errors
        assert len(error_data["detail"]) > 0
        assert "msg" in error_data["detail"][0]
        assert "loc" in error_data["detail"][0]

    def test_response_time(self, test_client):
        """Test response time for different message lengths"""
        import time
        
        messages = [
            "Short message",
            "Medium message " * 10,
            "Long message " * 100
        ]
        
        for message in messages:
            start_time = time.time()
            response = test_client.post(
                "/analyze",
                json={"text": message}
            )
            end_time = time.time()
            assert response.status_code == 200
            assert end_time - start_time < 2.0  # Response should be under 2 seconds 