# Threat Analysis API

A FastAPI-based service for analyzing text for potential threats using NLTK and sentiment analysis.

## Features

- Text analysis using NLTK for tokenization and part-of-speech tagging
- Sentiment analysis using Transformers
- Basic threat detection based on keyword patterns
- Entity recognition for proper nouns
- Comprehensive logging
- Extensive test coverage

## Project Structure

```
.
├── src/
│   ├── app.py              # Main FastAPI application
│   ├── config.py           # Configuration settings
│   ├── database.py         # Database operations
│   ├── monitoring.py       # System monitoring
│   └── models.py           # Data models
├── tests/
│   ├── conftest.py         # Test configuration
│   └── test_threat_analysis.py  # Test cases
├── logs/                   # Application logs
├── requirements.txt        # Project dependencies
└── README.md              # Project documentation
```

## Setup

1. Create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Download NLTK data:
```bash
python -c "import nltk; nltk.download('punkt'); nltk.download('averaged_perceptron_tagger'); nltk.download('wordnet')"
```

## Running the Server

Start the server with:
```bash
uvicorn src.app:app --reload
```

The server will be available at `http://localhost:8000`

## API Documentation

### Analyze Text

**Endpoint:** `POST /analyze`

Analyzes text for potential threats and sentiment.

**Request:**
```json
{
    "text": "Your text to analyze"
}
```

**Response:**
```json
{
    "threat_score": 0.5,
    "sentiment": "negative",
    "suspicious_patterns": ["kill", "destroy"],
    "entities": [
        {"text": "John", "type": "PERSON"}
    ],
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Health Check

**Endpoint:** `GET /health`

Returns the health status of the API.

**Response:**
```json
{
    "status": "healthy",
    "uptime": 3600,
    "version": "1.0.0"
}
```

## Error Handling

The API handles various error cases:
- Empty text (422 Unprocessable Entity)
- Invalid JSON (422 Unprocessable Entity)
- Server errors (500 Internal Server Error)

## Logging

Logs are written to `logs/app.log` with the following format:
```
2024-01-01 12:00:00,000 - app - INFO - Starting analysis of text
```

Log rotation is configured to:
- Rotate after 1MB
- Keep up to 5 backup files

## Running Tests

Run the test suite with:
```bash
python -m pytest tests/ -v
```

## Development

### Adding New Features

1. Create a new branch
2. Implement the feature
3. Add tests
4. Update documentation
5. Submit a pull request

### Code Style

- Follow PEP 8 guidelines
- Use type hints
- Write docstrings for all functions
- Keep functions small and focused

## License

MIT License 