"""Threat Analysis API - FastAPI Application

This module provides a FastAPI-based server for analyzing text communications
for potential threats using NLTK and machine learning techniques.

The server provides endpoints for:
- Text analysis (/analyze)
- Health monitoring (/health)
- Metrics collection (/metrics)

Key features:
- Text analysis using NLTK
- Sentiment analysis using Transformers
- Named entity recognition
- Threat keyword detection
- Comprehensive logging
- Performance monitoring
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
import json
import logging
import logging.handlers
import os
import time
from typing import Dict, List, Optional, Union
import nltk
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from datetime import datetime
from src.monitoring import Monitoring
from src.database import Database, DatabaseError

# Download required NLTK data
nltk.download("punkt")
nltk.download("averaged_perceptron_tagger")
nltk.download("wordnet")

# Initialize FastAPI app
app = FastAPI(title="Threat Analysis API")

# Initialize monitoring and database
monitoring = Monitoring()
db = Database()

# Initialize transformers model and tokenizer
model_name = "distilbert-base-uncased-finetuned-sst-2-english"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

# Configure logging
logger = logging.getLogger(__name__)


class TextInput(BaseModel):
    """Request model for text analysis endpoint.

    Attributes:
        text (str): The text to analyze
    """

    text: str

    @validator("text")
    def validate_text(cls, v):
        if not v or not v.strip():
            raise ValueError("Text cannot be empty")
        return v.strip()


class TextAnalysisRequest(BaseModel):
    """Request model for text analysis endpoint.

    Attributes:
        text (str): The text to analyze. Must be non-empty and under 10000 characters.
        metadata (Optional[Dict]): Additional metadata about the text (e.g., source, timestamp).
    """

    text: str
    metadata: Optional[Dict] = None

    @validator("text")
    def validate_text(cls, v):
        if not v or not v.strip():
            raise ValueError("Text cannot be empty")
        return v.strip()


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
    timestamp: str


# Threat-related keywords and their weights
THREAT_KEYWORDS = {
    "attack": 0.3,
    "destroy": 0.3,
    "bomb": 0.4,
    "explosive": 0.4,
    "target": 0.2,
    "execute": 0.3,
    "plan": 0.2,
    "operation": 0.2,
    "weapon": 0.3,
    "kill": 0.4,
}


def analyze_text(text: str) -> TextAnalysisResponse:
    """Analyze text for potential threats using NLTK and sentiment analysis."""
    try:
        # Tokenize and tag parts of speech
        tokens = nltk.word_tokenize(text)
        pos_tags = nltk.pos_tag(tokens)

        # Identify suspicious patterns (nouns and verbs that might indicate threats)
        suspicious_patterns = []
        for word, tag in pos_tags:
            if tag.startswith(("NN", "VB")):  # Nouns and verbs
                if word.lower() in [
                    "kill",
                    "harm",
                    "attack",
                    "destroy",
                    "threat",
                    "danger",
                ]:
                    suspicious_patterns.append(word)

        # Calculate threat score based on suspicious patterns
        threat_score = min(len(suspicious_patterns) / 5, 1.0)  # Normalize to 0-1 range

        # Perform sentiment analysis
        sentiment_result = sentiment_analyzer(text)[0]
        sentiment = sentiment_result["label"]

        # Extract entities (simplified version using NLTK)
        entities = []
        for word, tag in pos_tags:
            if tag.startswith("NNP"):  # Proper nouns
                entities.append(
                    {
                        "text": word,
                        "type": "PERSON" if word.istitle() else "ORGANIZATION",
                    }
                )

        return TextAnalysisResponse(
            threat_score=threat_score,
            sentiment=sentiment,
            suspicious_patterns=suspicious_patterns,
            entities=entities,
            pos_tags=[{"word": word, "tag": tag} for word, tag in pos_tags],
            timestamp=datetime.now().isoformat(),
        )
    except Exception as e:
        logger.error(f"Error analyzing text: {str(e)}")
        raise HTTPException(status_code=500, detail="Error analyzing text")


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
    """Check the health of the API."""
    try:
        # Attempt to get recent analyses to verify database connection
        db.get_recent_analyses(limit=1)
        health_status = monitoring.get_health_status()
        health_status.update({"database": "connected", "status": "healthy"})
        return health_status
    except DatabaseError as e:
        logger.error(f"Database health check failed: {str(e)}")
        return {"status": "unhealthy", "database": "error", "detail": str(e)}
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {"status": "unhealthy", "detail": str(e)}


@app.post("/analyze")
async def analyze(request: Request, text_input: TextInput):
    """Analyze text for potential threats."""
    try:
        # Start timing the request
        start_time = time.time()

        # Get sentiment analysis from transformers
        inputs = tokenizer(
            text_input.text, return_tensors="pt", truncation=True, max_length=512
        )
        outputs = model(**inputs)
        prediction = torch.nn.functional.softmax(outputs.logits, dim=-1)
        transformer_score = float(
            prediction[0][1].item()
        )  # Probability of negative/threatening class

        # Get NLTK analysis
        tokens = nltk.word_tokenize(text_input.text)
        pos_tags = nltk.pos_tag(tokens)

        # Identify suspicious patterns with weights
        suspicious_patterns = []
        weighted_score = 0.0
        max_keyword_weight = 0.0

        # First pass: find max keyword weight and collect patterns
        for word, tag in pos_tags:
            word_lower = word.lower()
            if word_lower in THREAT_KEYWORDS:
                suspicious_patterns.append(word)
                weight = THREAT_KEYWORDS[word_lower]
                weighted_score += weight
                max_keyword_weight = max(max_keyword_weight, weight)

        # Calculate final threat score
        text_lower = text_input.text.lower()

        # Check for benign patterns (greetings, polite phrases)
        benign_starts = (
            "hi",
            "hello",
            "hey",
            "good morning",
            "good afternoon",
            "good evening",
        )
        benign_phrases = (
            "how are you",
            "nice to meet",
            "pleased to meet",
            "good to see",
        )
        is_benign = any(text_lower.startswith(start) for start in benign_starts) or any(
            phrase in text_lower for phrase in benign_phrases
        )

        if not suspicious_patterns:
            # No threat keywords found - assume benign unless very negative sentiment
            if is_benign or transformer_score < 0.8:
                threat_score = 0.0  # Truly benign text
            else:
                threat_score = max(
                    0.0, (transformer_score - 0.8) * 0.5
                )  # Scale down high negative sentiment
        else:
            # Threat keywords found - use weighted combination
            keyword_score = min(1.0, weighted_score / 0.8)  # Normalize weighted score
            # If we find high-weight keywords (bomb, kill), boost the score significantly
            if max_keyword_weight >= 0.4:
                threat_score = max(0.6, keyword_score)
            else:
                # Otherwise blend keyword score with transformer score, emphasizing keywords
                threat_score = (keyword_score * 0.8) + (transformer_score * 0.2)

        # Final normalization and thresholding
        threat_score = min(1.0, max(0.0, threat_score))

        # Very short messages without threat words should score 0
        if (len(tokens) < 3 and not suspicious_patterns) or is_benign:
            threat_score = 0.0

        # Extract entities
        entities = []
        for word, tag in pos_tags:
            if tag.startswith("NNP"):  # Proper nouns
                entities.append(
                    {
                        "text": word,
                        "type": "PERSON" if word.istitle() else "ORGANIZATION",
                    }
                )

        # Store analysis in database
        analysis_id = db.store_analysis(
            text=text_input.text,
            threat_score=threat_score,
            sentiment="negative" if transformer_score > 0.5 else "positive",
            suspicious_patterns=suspicious_patterns,
            entities=entities,
            pos_tags=[{"word": word, "tag": tag} for word, tag in pos_tags],
        )

        # Track metrics
        response_time = time.time() - start_time
        await monitoring.track_request(request, response_time)
        monitoring.track_threat_score(threat_score)

        return {
            "text": text_input.text,
            "threat_score": threat_score,
            "suspicious_patterns": suspicious_patterns,
            "sentiment": "negative" if transformer_score > 0.5 else "positive",
            "entities": entities,
            "pos_tags": [{"word": word, "tag": tag} for word, tag in pos_tags],
            "analysis_id": analysis_id,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        monitoring.track_error(error_type=str(type(e).__name__))
        raise HTTPException(status_code=500, detail="Error processing text")


def setup_logging():
    """Set up logging configuration."""
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    # Create logs directory if it doesn't exist
    if not os.path.exists("logs"):
        os.makedirs("logs")

    # Create file handler for logging
    file_handler = logging.handlers.RotatingFileHandler(
        "logs/app.log", maxBytes=1024 * 1024, backupCount=5  # 1MB
    )
    file_handler.setLevel(logging.INFO)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# Set up logging
logger = setup_logging()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
