"""Tests for the database module."""

import pytest
import os
import shutil
from datetime import datetime
from src.database import Database, Analysis, DatabaseError


@pytest.fixture
def test_db():
    """Create a test database in memory."""
    db = Database("sqlite:///:memory:")
    yield db


def test_database_initialization(test_db):
    """Test database initialization."""
    assert test_db.engine is not None
    assert test_db.Session is not None


def test_store_analysis(test_db):
    """Test storing an analysis."""
    text = "This is a test message"
    threat_score = 0.5
    sentiment = "neutral"
    suspicious_patterns = ["test"]
    entities = [{"text": "test", "label": "TEST"}]
    pos_tags = [{"text": "test", "pos": "NOUN"}]

    analysis_id = test_db.store_analysis(
        text=text,
        threat_score=threat_score,
        sentiment=sentiment,
        suspicious_patterns=suspicious_patterns,
        entities=entities,
        pos_tags=pos_tags,
    )

    assert analysis_id is not None
    assert isinstance(analysis_id, int)


def test_get_recent_analyses(test_db):
    """Test retrieving recent analyses."""
    # Store multiple analyses with increasing threat scores
    for i in range(5):
        test_db.store_analysis(
            text=f"Test message {i}",
            threat_score=0.1 * (5 - i),  # Decreasing order: 0.5, 0.4, 0.3, 0.2, 0.1
            sentiment="neutral",
            suspicious_patterns=[f"pattern{i}"],
        )

    analyses = test_db.get_recent_analyses(limit=3)
    assert len(analyses) == 3
    # The most recent entries should have higher threat scores
    assert analyses[0]["threat_score"] > analyses[1]["threat_score"]


def test_get_analysis_by_id(test_db):
    """Test retrieving analysis by ID."""
    analysis_id = test_db.store_analysis(
        text="Test message", threat_score=0.5, sentiment="neutral"
    )

    analysis = test_db.get_analysis_by_id(analysis_id)
    assert analysis is not None
    assert analysis["text"] == "Test message"
    assert analysis["threat_score"] == 0.5
    assert analysis["sentiment"] == "neutral"


def test_get_nonexistent_analysis(test_db):
    """Test retrieving a nonexistent analysis."""
    analysis = test_db.get_analysis_by_id(999)
    assert analysis is None


def test_delete_analysis(test_db):
    """Test deleting an analysis."""
    analysis_id = test_db.store_analysis(
        text="Test message", threat_score=0.5, sentiment="neutral"
    )

    result = test_db.delete_analysis(analysis_id)
    assert result is True

    # Verify deletion
    analysis = test_db.get_analysis_by_id(analysis_id)
    assert analysis is None


def test_delete_nonexistent_analysis(test_db):
    """Test deleting a nonexistent analysis."""
    result = test_db.delete_analysis(999)
    assert result is False


def test_analysis_to_dict():
    """Test the to_dict method of Analysis model."""
    analysis = Analysis(
        text="Test message",
        threat_score=0.5,
        sentiment="neutral",
        suspicious_patterns=["test"],
        entities=[{"text": "test", "label": "TEST"}],
        pos_tags=[{"text": "test", "pos": "NOUN"}],
    )

    result = analysis.to_dict()
    assert result["text"] == "Test message"
    assert result["threat_score"] == 0.5
    assert result["sentiment"] == "neutral"
    assert result["suspicious_patterns"] == ["test"]
    assert result["entities"] == [{"text": "test", "label": "TEST"}]
    assert result["pos_tags"] == [{"text": "test", "pos": "NOUN"}]
    assert "created_at" in result


def test_database_error():
    """Test the DatabaseError exception."""
    with pytest.raises(DatabaseError):
        raise DatabaseError("Test error")


def test_database_file_creation():
    """Test database file creation in data directory."""
    # Remove data directory if it exists
    data_dir = "data"
    if os.path.exists(data_dir):
        try:
            shutil.rmtree(data_dir)
        except PermissionError:
            # If we can't remove the directory, skip the test
            pytest.skip("Cannot remove data directory - file in use")

    # Create a new database
    db = Database()
    assert os.path.exists(data_dir)
    assert os.path.exists(os.path.join(data_dir, "analyses.db"))

    # Close the database connection
    db.engine.dispose()

    # Clean up
    try:
        shutil.rmtree(data_dir)
    except PermissionError:
        # If we can't remove the directory, that's okay
        pass


def test_session_rollback(test_db):
    """Test session rollback on error."""
    # Store initial analysis
    analysis_id = test_db.store_analysis(
        text="Test message", threat_score=0.5, sentiment="neutral"
    )

    # Try to store invalid data (should rollback)
    with pytest.raises(DatabaseError):
        test_db.store_analysis(
            text=None,  # This should cause an error
            threat_score=0.5,
            sentiment="neutral",
        )

    # Verify the initial analysis still exists
    analysis = test_db.get_analysis_by_id(analysis_id)
    assert analysis is not None
