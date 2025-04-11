"""Database module for storing and retrieving text analyses."""

from sqlalchemy import create_engine, Column, Integer, Float, String, DateTime, JSON
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from datetime import datetime, UTC
from typing import List, Optional, Dict, Any
from contextlib import contextmanager
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create base class for declarative models
Base = declarative_base()


class Analysis(Base):
    """SQLAlchemy model for storing text analysis results."""

    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True)
    text = Column(String, nullable=False)
    threat_score = Column(Float, nullable=False)
    sentiment = Column(String, nullable=False)
    suspicious_patterns = Column(JSON, nullable=True)
    entities = Column(JSON, nullable=True)
    pos_tags = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))

    def to_dict(self) -> Dict[str, Any]:
        """Convert the analysis to a dictionary."""
        return {
            "id": self.id,
            "text": self.text,
            "threat_score": self.threat_score,
            "sentiment": self.sentiment,
            "suspicious_patterns": self.suspicious_patterns or [],
            "entities": self.entities or [],
            "pos_tags": self.pos_tags or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Database:
    """Database handler using SQLAlchemy."""

    def __init__(self, db_url: Optional[str] = None):
        """Initialize database connection.

        Args:
            db_url: Optional database URL. If not provided, uses SQLite in data directory.
        """
        if db_url is None:
            # Create data directory if it doesn't exist
            if not os.path.exists("data"):
                os.makedirs("data")
            db_url = "sqlite:///data/analyses.db"

        self.engine = create_engine(db_url)
        self.Session = sessionmaker(bind=self.engine)

        # Create tables if they don't exist
        Base.metadata.create_all(self.engine)
        logger.info(f"Database initialized with URL: {db_url}")

    @contextmanager
    def get_session(self) -> Session:
        """Context manager for database sessions.

        Yields:
            Session: SQLAlchemy session
        """
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise DatabaseError(f"Database error: {str(e)}") from e
        finally:
            session.close()

    def store_analysis(
        self,
        text: str,
        threat_score: float,
        sentiment: str,
        suspicious_patterns: Optional[List[str]] = None,
        entities: Optional[List[Dict[str, str]]] = None,
        pos_tags: Optional[List[Dict[str, str]]] = None,
    ) -> int:
        """Store a new analysis in the database.

        Args:
            text: The analyzed text
            threat_score: Calculated threat score
            sentiment: Detected sentiment
            suspicious_patterns: List of suspicious patterns found
            entities: List of detected entities
            pos_tags: List of part-of-speech tags

        Returns:
            The ID of the stored analysis
        """
        with self.get_session() as session:
            analysis = Analysis(
                text=text,
                threat_score=threat_score,
                sentiment=sentiment,
                suspicious_patterns=suspicious_patterns,
                entities=entities,
                pos_tags=pos_tags,
            )
            session.add(analysis)
            session.flush()  # This will populate the id
            analysis_id = analysis.id
            logger.info(f"Stored analysis with ID {analysis_id}")
            return analysis_id

    def get_recent_analyses(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve recent analyses from the database.

        Args:
            limit: Maximum number of analyses to retrieve

        Returns:
            List of analysis dictionaries ordered by threat_score in descending order
        """
        with self.get_session() as session:
            analyses = (
                session.query(Analysis)
                .order_by(Analysis.threat_score.desc())
                .limit(limit)
                .all()
            )
            logger.info(f"Retrieved {len(analyses)} recent analyses")
            return [analysis.to_dict() for analysis in analyses]

    def get_analysis_by_id(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a specific analysis by ID.

        Args:
            analysis_id: ID of the analysis to retrieve

        Returns:
            Analysis dictionary if found, None otherwise
        """
        with self.get_session() as session:
            analysis = session.query(Analysis).filter_by(id=analysis_id).first()
            if analysis:
                logger.info(f"Retrieved analysis with ID {analysis_id}")
                return analysis.to_dict()
            logger.warning(f"Analysis with ID {analysis_id} not found")
            return None

    def delete_analysis(self, analysis_id: int) -> bool:
        """Delete an analysis from the database.

        Args:
            analysis_id: ID of the analysis to delete

        Returns:
            True if deletion was successful, False otherwise
        """
        with self.get_session() as session:
            analysis = session.query(Analysis).filter_by(id=analysis_id).first()
            if analysis:
                session.delete(analysis)
                logger.info(f"Deleted analysis with ID {analysis_id}")
                return True
            logger.warning(f"Analysis with ID {analysis_id} not found")
            return False


class DatabaseError(Exception):
    """Custom exception for database errors."""

    pass
