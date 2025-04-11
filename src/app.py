"""Threat Analysis MCP Server - FastAPI Application

This module provides a FastAPI-based server for analyzing text communications
for potential terrorist threats using NLP and machine learning techniques.

The server provides endpoints for:
- Text analysis (/analyze)
- Health monitoring (/health)
- Metrics collection (/metrics)

Key features:
- Text analysis using NLTK
- Sentiment analysis using VADER
- Named entity recognition
- Threat keyword detection
- Comprehensive logging
- Performance monitoring
"""

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, validator
from typing import List, Dict, Optional
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
from nltk.tokenize import word_tokenize
from nltk.tag import pos_tag
from nltk.chunk import ne_chunk
import re
import logging
from logging.handlers import RotatingFileHandler
import traceback
from datetime import datetime
import os
import time
from .monitoring import monitoring

# Configure logging
def setup_logging():
    """Configure logging for the application.
    
    Sets up:
    - Rotating file handlers for general and error logs
    - Console handler with colored output
    - Custom log levels for analysis and threat detection
    - Detailed log formatting with timestamps and context
    
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Create a detailed formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(funcName)s - %(message)s'
    )
    
    # Create file handler with rotation
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=1024*1024,  # 1MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    # Create error file handler
    error_handler = RotatingFileHandler(
        'logs/error.log',
        maxBytes=1024*1024,  # 1MB
        backupCount=5,
        encoding='utf-8'
    )
    error_handler.setFormatter(formatter)
    error_handler.setLevel(logging.ERROR)
    
    # Create console handler with color
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(error_handler)
    root_logger.addHandler(console_handler)
    
    # Create application logger
    logger = logging.getLogger('threat_analysis')
    logger.setLevel(logging.INFO)
    
    # Add custom log levels
    logging.addLevelName(logging.INFO + 5, "ANALYSIS")
    logging.addLevelName(logging.INFO + 10, "THREAT")
    
    return logger

logger = setup_logging()

app = FastAPI(title="Threat Analysis MCP Server")

# Initialize NLTK components
try:
    nltk.download('punkt')
    nltk.download('averaged_perceptron_tagger')
    nltk.download('maxent_ne_chunker')
    nltk.download('words')
    nltk.download('vader_lexicon')
    logger.info("Successfully initialized NLTK components")
except Exception as e:
    logger.error(f"Error downloading NLTK data: {str(e)}")
    raise

class TextAnalysisRequest(BaseModel):
    """Request model for text analysis endpoint.
    
    Attributes:
        text (str): The text to analyze. Must be non-empty and under 10000 characters.
        metadata (Optional[Dict]): Additional metadata about the text (e.g., source, timestamp).
    """
    text: str
    metadata: Optional[Dict] = None
    
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
    suspicious_patterns: List[str]
    confidence: float
    sentiment: Dict[str, float]
    entities: List[Dict[str, str]]
    pos_tags: List[Dict[str, str]]

# Threat-related keywords and their weights
THREAT_KEYWORDS = {
    'attack': 0.3,
    'destroy': 0.3,
    'bomb': 0.4,
    'explosive': 0.4,
    'target': 0.2,
    'execute': 0.3,
    'plan': 0.2,
    'operation': 0.2,
    'weapon': 0.3,
    'kill': 0.4
}

def analyze_text(text: str) -> TextAnalysisResponse:
    """Analyze text for potential threats using NLP techniques.
    
    Performs:
    - Tokenization and POS tagging
    - Named entity recognition
    - Threat keyword detection
    - Sentiment analysis
    
    Args:
        text (str): The text to analyze
        
    Returns:
        TextAnalysisResponse: Analysis results including threat score and patterns
        
    Raises:
        Exception: If any analysis step fails
    """
    try:
        logger.info(f"Starting analysis of text (length: {len(text)})")
        
        # Initialize sentiment analyzer
        sia = SentimentIntensityAnalyzer()
        
        # Calculate threat score
        threat_score = 0.0
        suspicious_patterns = []
        confidence = 0.0
        
        # Tokenize and tag parts of speech
        try:
            tokens = word_tokenize(text.lower())
            pos_tags = pos_tag(tokens)
            logger.debug(f"Successfully tokenized text into {len(tokens)} tokens")
        except Exception as e:
            logger.error(f"Error in tokenization: {str(e)}")
            raise
        
        # Named entity recognition
        try:
            named_entities = ne_chunk(pos_tags)
            logger.debug("Successfully performed named entity recognition")
        except Exception as e:
            logger.error(f"Error in named entity recognition: {str(e)}")
            raise
        
        # Extract entities
        entities = []
        current_entity = []
        current_label = None
        
        try:
            for chunk in named_entities:
                if hasattr(chunk, 'label'):
                    if current_entity:
                        entities.append({
                            'text': ' '.join(current_entity),
                            'type': current_label
                        })
                    current_entity = [chunk[0][0]]
                    current_label = chunk.label()
                else:
                    if current_entity:
                        current_entity.append(chunk[0])
                    else:
                        entities.append({
                            'text': chunk[0],
                            'type': chunk[1]
                        })
            
            if current_entity:
                entities.append({
                    'text': ' '.join(current_entity),
                    'type': current_label
                })
            logger.debug(f"Extracted {len(entities)} entities")
        except Exception as e:
            logger.error(f"Error in entity extraction: {str(e)}")
            raise
        
        # Check for threat keywords
        try:
            for word in tokens:
                if word in THREAT_KEYWORDS:
                    threat_score += THREAT_KEYWORDS[word]
                    suspicious_patterns.append(word)
            
            # Normalize threat score
            threat_score = min(threat_score, 1.0)
            logger.debug(f"Calculated threat score: {threat_score}")
        except Exception as e:
            logger.error(f"Error in threat analysis: {str(e)}")
            raise
        
        # Calculate confidence
        try:
            confidence = min(len(suspicious_patterns) * 0.1 + len(text) * 0.001, 1.0)
            logger.debug(f"Calculated confidence score: {confidence}")
        except Exception as e:
            logger.error(f"Error in confidence calculation: {str(e)}")
            raise
        
        # Get sentiment scores
        try:
            sentiment_scores = sia.polarity_scores(text)
            logger.debug(f"Calculated sentiment scores: {sentiment_scores}")
        except Exception as e:
            logger.error(f"Error in sentiment analysis: {str(e)}")
            raise
        
        response = TextAnalysisResponse(
            threat_score=threat_score,
            suspicious_patterns=suspicious_patterns,
            confidence=confidence,
            sentiment=sentiment_scores,
            entities=entities,
            pos_tags=[{'word': word, 'tag': tag} for word, tag in pos_tags]
        )
        
        logger.info("Successfully completed text analysis")
        return response
        
    except Exception as e:
        logger.error(f"Unexpected error in analyze_text: {str(e)}\n{traceback.format_exc()}")
        raise

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Middleware to track request processing time.
    
    Adds X-Process-Time header and updates monitoring metrics.
    
    Args:
        request (Request): The incoming request
        call_next: Function to call the next middleware/route handler
        
    Returns:
        Response: The response with added process time header
    """
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    await monitoring.track_request(request, process_time)
    return response

@app.get("/metrics")
async def get_metrics():
    """Get current application metrics.
    
    Returns:
        Dict[str, Any]: Current metrics including request counts, response times,
                       threat scores, and system metrics
    """
    return monitoring.get_metrics()

@app.get("/health")
async def health_check():
    """Health check endpoint.
    
    Returns:
        Dict[str, Any]: Health status including system metrics and application stats
    """
    try:
        health_status = monitoring.get_health_status()
        return health_status
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Health check failed")

@app.post("/analyze", response_model=TextAnalysisResponse)
async def analyze(request: TextAnalysisRequest):
    """Analyze text for potential threats.
    
    Args:
        request (TextAnalysisRequest): The text to analyze and optional metadata
        
    Returns:
        TextAnalysisResponse: Analysis results
        
    Raises:
        HTTPException: If analysis fails
    """
    try:
        logger.info(f"Received analysis request")
        logger.info(f"Starting analysis of text (length: {len(request.text)})")
        
        start_time = time.time()
        response = analyze_text(request.text)
        process_time = time.time() - start_time
        
        # Track metrics
        monitoring.track_threat_score(response.threat_score)
        await monitoring.track_request(request, process_time)
        
        logger.info("Successfully completed text analysis")
        return response
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}\n{traceback.format_exc()}")
        monitoring.track_error("analysis_error")
        raise HTTPException(status_code=500, detail="Analysis failed") 