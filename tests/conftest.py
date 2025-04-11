import pytest
import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture(scope="session")
def test_client():
    """Create a test client for the FastAPI application"""
    from fastapi.testclient import TestClient
    from src.app import app
    return TestClient(app) 