"""NLP Utilities Module.

This module provides NLP-related utilities for text analysis,
including tokenization, sentiment analysis, and threat detection.
"""

import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
from nltk.tokenize import word_tokenize
from nltk.tag import pos_tag
from nltk.chunk import ne_chunk
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

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


def initialize_nltk() -> None:
    """Initialize NLTK components and download required data.

    Raises:
        Exception: If NLTK data download fails
    """
    try:
        nltk.download("punkt")
        nltk.download("averaged_perceptron_tagger")
        nltk.download("maxent_ne_chunker")
        nltk.download("words")
        nltk.download("vader_lexicon")
        logger.info("Successfully initialized NLTK components")
    except Exception as e:
        logger.error(f"Error downloading NLTK data: {str(e)}")
        raise


def analyze_text(text: str) -> Dict[str, Any]:
    """Analyze text for potential threats using NLP techniques.

    Args:
        text (str): The text to analyze

    Returns:
        Dict[str, Any]: Analysis results including:
            - threat_score (float): Score between 0 and 1
            - suspicious_patterns (List[str]): Detected patterns
            - confidence (float): Analysis confidence
            - sentiment (Dict[str, float]): Sentiment scores
            - entities (List[Dict[str, str]]): Named entities
            - pos_tags (List[Dict[str, str]]): POS tags

    Raises:
        Exception: If any analysis step fails
    """
    try:
        logger.info(f"Starting analysis of text (length: {len(text)})")

        # Initialize sentiment analyzer
        sia = SentimentIntensityAnalyzer()

        # Tokenize and tag parts of speech
        tokens = word_tokenize(text.lower())
        pos_tags = pos_tag(tokens)
        logger.debug(f"Successfully tokenized text into {len(tokens)} tokens")

        # Named entity recognition
        named_entities = ne_chunk(pos_tags)
        logger.debug("Successfully performed named entity recognition")

        # Extract entities
        entities = extract_entities(named_entities)
        logger.debug(f"Extracted {len(entities)} entities")

        # Calculate threat score and patterns
        threat_score, suspicious_patterns = calculate_threat_score(tokens)
        logger.debug(f"Calculated threat score: {threat_score}")

        # Calculate confidence
        confidence = calculate_confidence(suspicious_patterns, text)
        logger.debug(f"Calculated confidence score: {confidence}")

        # Get sentiment scores
        sentiment_scores = sia.polarity_scores(text)
        logger.debug(f"Calculated sentiment scores: {sentiment_scores}")

        return {
            "threat_score": threat_score,
            "suspicious_patterns": suspicious_patterns,
            "confidence": confidence,
            "sentiment": sentiment_scores,
            "entities": entities,
            "pos_tags": [{"word": word, "tag": tag} for word, tag in pos_tags],
        }

    except Exception as e:
        logger.error(f"Unexpected error in analyze_text: {str(e)}")
        raise


def extract_entities(named_entities: Any) -> List[Dict[str, str]]:
    """Extract named entities from NLTK chunked data.

    Args:
        named_entities: NLTK chunked data

    Returns:
        List[Dict[str, str]]: List of entities with text and type
    """
    entities = []
    current_entity = []
    current_label = None

    for chunk in named_entities:
        if hasattr(chunk, "label"):
            if current_entity:
                entities.append(
                    {"text": " ".join(current_entity), "type": current_label}
                )
            current_entity = [chunk[0][0]]
            current_label = chunk.label()
        else:
            if current_entity:
                current_entity.append(chunk[0])
            else:
                entities.append({"text": chunk[0], "type": chunk[1]})

    if current_entity:
        entities.append({"text": " ".join(current_entity), "type": current_label})

    return entities


def calculate_threat_score(tokens: List[str]) -> tuple[float, List[str]]:
    """Calculate threat score based on keywords.

    Args:
        tokens (List[str]): Tokenized text

    Returns:
        tuple[float, List[str]]: Threat score and suspicious patterns
    """
    threat_score = 0.0
    suspicious_patterns = []

    for word in tokens:
        if word in THREAT_KEYWORDS:
            threat_score += THREAT_KEYWORDS[word]
            suspicious_patterns.append(word)

    # Normalize threat score
    threat_score = min(threat_score, 1.0)

    return threat_score, suspicious_patterns


def calculate_confidence(suspicious_patterns: List[str], text: str) -> float:
    """Calculate confidence score for analysis.

    Args:
        suspicious_patterns (List[str]): Detected suspicious patterns
        text (str): Original text

    Returns:
        float: Confidence score between 0 and 1
    """
    return min(len(suspicious_patterns) * 0.1 + len(text) * 0.001, 1.0)
