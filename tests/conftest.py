"""Test configuration and fixtures."""

import pytest
from fastapi.testclient import TestClient
from src.app import app

@pytest.fixture
def test_client():
    """Create a test client for the FastAPI application."""
    return TestClient(app)

@pytest.fixture
def test_db():
    """Create a test database in memory."""
    from src.database import Database
    db = Database('sqlite:///:memory:')
    yield db
    # Cleanup is automatic for in-memory database 