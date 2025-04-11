"""Validation Utilities Module.

This module provides validation functions for input data and requests.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, validator

class TextAnalysisRequest(BaseModel):
    """Request model for text analysis endpoint.
    
    Attributes:
        text (str): The text to analyze. Must be non-empty and under 10000 characters.
        metadata (Optional[Dict]): Additional metadata about the text.
    """
    text: str
    metadata: Optional[Dict[str, Any]] = None
    
    @validator('text')
    @classmethod
    def validate_text(cls, v: str) -> str:
        """Validate the text input.
        
        Args:
            v (str): The text to validate
            
        Returns:
            str: The validated text
            
        Raises:
            ValueError: If text is empty or exceeds length limit
        """
        if not v.strip():
            raise ValueError("Text cannot be empty")
        if len(v) > 10000:
            raise ValueError("Text length exceeds maximum limit of 10000 characters")
        return v

class TextAnalysisResponse(BaseModel):
    """Response model for text analysis endpoint.
    
    Attributes:
        threat_score (float): Score between 0 and 1 indicating threat level
        suspicious_patterns (List[str]): List of detected threat-related patterns
        confidence (float): Confidence score for the analysis
        sentiment (Dict[str, float]): Sentiment analysis results
        entities (List[Dict[str, str]]): Named entities found in text
        pos_tags (List[Dict[str, str]]): Part-of-speech tags for each word
    """
    threat_score: float
    suspicious_patterns: list[str]
    confidence: float
    sentiment: dict[str, float]
    entities: list[dict[str, str]]
    pos_tags: list[dict[str, str]] 