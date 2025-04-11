from flask import Flask, request, jsonify
from typing import Dict, List, Tuple
import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.tag import pos_tag
from nltk.chunk import ne_chunk
from nltk.sentiment import SentimentIntensityAnalyzer
from nltk.corpus import stopwords
from nltk.tokenize import RegexpTokenizer
import logging
import sys
from datetime import datetime
import networkx as nx
import json
import os
import time
import psutil
import threading
import numpy as np
from prometheus_client import Counter, Gauge, Histogram
from prometheus_client.core import CollectorRegistry

# Download required NLTK data
try:
    nltk.download('punkt')
    nltk.download('averaged_perceptron_tagger')
    nltk.download('maxent_ne_chunker')
    nltk.download('words')
    nltk.download('vader_lexicon')
    nltk.download('stopwords')
except Exception as e:
    print(f"Error downloading NLTK data: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f'logs/threat_analysis_{datetime.now().strftime("%Y%m%d")}.log')
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize NLP components
try:
    logger.info("Initializing NLP components...")
    sia = SentimentIntensityAnalyzer()
    stop_words = set(stopwords.words('english'))
    tokenizer = RegexpTokenizer(r'\w+')
    logger.info("NLP components initialized successfully")
except Exception as e:
    logger.error(f"Error initializing NLP components: {str(e)}", exc_info=True)
    sia = None

def extract_entity_relationships(text: str) -> Tuple[List[Dict], List[Dict]]:
    """Extract entities and their relationships using NLTK"""
    entities = []
    relationships = []
    
    # Tokenize and tag the text
    sentences = sent_tokenize(text)
    
    # Create entity graph
    entity_graph = nx.Graph()
    
    for sentence in sentences:
        # Extract named entities
        tokens = word_tokenize(sentence)
        pos_tags = pos_tag(tokens)
        tree = ne_chunk(pos_tags)
        
        # Extract entities from the tree
        sentence_entities = []
        for chunk in tree:
            if hasattr(chunk, 'label'):
                entity = {
                    "text": ' '.join(c[0] for c in chunk.leaves()),
                    "label": chunk.label(),
                    "start": tokens.index(chunk.leaves()[0][0]),
                    "end": tokens.index(chunk.leaves()[-1][0])
                }
                entities.append(entity)
                sentence_entities.append(entity)
                entity_graph.add_node(entity["text"], label=entity["label"])
        
        # Find relationships between entities in the same sentence
        for i, ent1 in enumerate(sentence_entities):
            for ent2 in sentence_entities[i+1:]:
                # Get words between entities
                start_idx = ent1["end"] + 1
                end_idx = ent2["start"]
                if start_idx < end_idx:
                    between_words = tokens[start_idx:end_idx]
                    relationship = {
                        "source": ent1["text"],
                        "target": ent2["text"],
                        "relationship": ' '.join(between_words)
                    }
                    relationships.append(relationship)
                    entity_graph.add_edge(
                        ent1["text"],
                        ent2["text"],
                        relationship=' '.join(between_words)
                    )
    
    return entities, relationships

def analyze_entity_threat_patterns(entities: List[Dict], relationships: List[Dict]) -> Dict:
    """Analyze threat patterns in entity relationships"""
    threat_patterns = []
    entity_threat_score = 0.0
    
    # Suspicious entity combinations
    suspicious_entity_pairs = [
        ("PERSON", "ORGANIZATION"),
        ("PERSON", "GPE"),
        ("ORGANIZATION", "GPE"),
        ("PERSON", "PERSON")
    ]
    
    # Suspicious verbs and actions
    suspicious_actions = [
        "attack", "kill", "bomb", "destroy", "threaten",
        "assassinate", "detonate", "explode", "target"
    ]
    
    # Check for suspicious entity combinations
    for rel in relationships:
        source_ent = next((e for e in entities if e["text"] == rel["source"]), None)
        target_ent = next((e for e in entities if e["text"] == rel["target"]), None)
        
        if source_ent and target_ent:
            pair = (source_ent["label"], target_ent["label"])
            if pair in suspicious_entity_pairs:
                # Check if relationship contains suspicious actions
                rel_words = tokenizer.tokenize(rel["relationship"].lower())
                if any(action in rel_words for action in suspicious_actions):
                    threat_patterns.append(
                        f"Suspicious relationship detected: {source_ent['text']} -> "
                        f"{rel['relationship']} -> {target_ent['text']}"
                    )
                    entity_threat_score += 0.3
                else:
                    threat_patterns.append(
                        f"Potential entity relationship of interest: {source_ent['text']} -> "
                        f"{rel['relationship']} -> {target_ent['text']}"
                    )
                    entity_threat_score += 0.1
    
    return {
        "entity_threat_patterns": threat_patterns,
        "entity_threat_score": min(1.0, entity_threat_score)
    }

def analyze_sentiment(text: str) -> Dict[str, float]:
    """Analyze sentiment using NLTK's VADER"""
    return sia.polarity_scores(text)

@app.route("/analyze", methods=["POST"])
def analyze_text():
    try:
        data = request.get_json()
        if not data or "text" not in data:
            return jsonify({"error": "No text provided"}), 400
        
        text = data["text"]
        
        logger.info(f"Received analysis request for text: {text[:100]}...")
        
        if not sia:
            logger.error("NLP components not initialized")
            return jsonify({"error": "NLP components not initialized"}), 503
        
        try:
            # Extract entities and relationships
            entities, relationships = extract_entity_relationships(text)
            
            # Analyze entity threat patterns
            entity_analysis = analyze_entity_threat_patterns(entities, relationships)
            
            # Split into sentences
            sentences = sent_tokenize(text)
            
            # Analyze sentiment
            logger.debug("Analyzing sentiment...")
            sentiment_result = analyze_sentiment(text)
            
            # Basic threat detection
            logger.debug("Performing threat detection...")
            suspicious_patterns = []
            threat_score = 0.0
            keyword_count = 0
            
            # Threat indicators
            suspicious_keywords = [
                "attack", "bomb", "kill", "terror", "weapon", "threat", "explosive",
                "detonate", "assassinate", "massacre", "hostage", "jihad"
            ]
            
            # Check each sentence for threats
            for sentence in sentences:
                sentence_lower = sentence.lower()
                
                # Check for suspicious keywords
                sentence_keywords = []
                for word in suspicious_keywords:
                    if word in sentence_lower:
                        logger.warning(
                            f"Found suspicious keyword '{word}' in sentence: {sentence}"
                        )
                        suspicious_patterns.append(
                            f"Found suspicious keyword '{word}' in: {sentence}"
                        )
                        sentence_keywords.append(word)
                        keyword_count += 1
                
                # Add exponential score based on number of keywords in same sentence
                if sentence_keywords:
                    threat_score += 0.3 * (1.5 ** (len(sentence_keywords) - 1))
                
                # Add sentiment analysis to threat score
                sent_sentiment = analyze_sentiment(sentence)
                if sent_sentiment['compound'] < -0.5:  # Very negative sentiment
                    threat_score += 0.2
                    suspicious_patterns.append(
                        f"Found very negative sentiment in: {sentence}"
                    )
                elif sent_sentiment['compound'] < -0.3:  # Moderately negative
                    threat_score += 0.1
                    suspicious_patterns.append(
                        f"Found negative sentiment in: {sentence}"
                    )
            
            # Add bonus for multiple keywords across different sentences
            if keyword_count > 1:
                threat_score += 0.1 * (keyword_count - 1)
            
            # Combine keyword-based and entity-based threat scores
            final_threat_score = min(1.0, threat_score + entity_analysis["entity_threat_score"])
            
            # Combine all suspicious patterns
            all_patterns = suspicious_patterns + entity_analysis["entity_threat_patterns"]
            
            logger.info(f"Analysis completed. Final threat score: {final_threat_score}")
            
            return jsonify({
                "threat_score": final_threat_score,
                "entities": entities,
                "entity_relationships": relationships,
                "sentiment": sentiment_result,
                "suspicious_patterns": all_patterns,
                "sentences": sentences
            })
        except Exception as e:
            logger.error(f"Error during text analysis: {str(e)}", exc_info=True)
            return jsonify({"error": "Error during text analysis"}), 500
    
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        return jsonify({"error": "Invalid request"}), 400

@app.route("/health", methods=["GET"])
def health_check():
    logger.info("Health check requested")
    return jsonify({
        "status": "healthy",
        "nltk_initialized": bool(sia),
        "timestamp": datetime.now().isoformat()
    })

if __name__ == "__main__":
    app.run(debug=True) 