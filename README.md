# Threat Analysis MCP Server

A FastAPI-based server for analyzing text communications for potential terrorist threats using NLP and machine learning.

## Project Structure

```
.
├── src/                    # Source code
│   ├── app.py             # Main FastAPI application
│   ├── monitoring.py      # Monitoring and metrics
│   ├── config.py          # Configuration settings
│   ├── database.py        # Database utilities
│   ├── models.py          # Data models
│   └── __init__.py        # Package initialization
├── tests/                  # Test files
│   ├── conftest.py        # Test configuration
│   ├── test_threat_analysis.py  # Test cases
│   └── test_monitoring.py # Monitoring tests
├── docs/                  # Documentation
│   ├── conf.py           # Sphinx configuration
│   ├── index.rst         # Documentation index
│   └── modules.rst       # Module documentation
├── logs/                  # Application logs
│   ├── app.log           # General application logs
│   ├── error.log         # Error logs
│   └── metrics.json      # Metrics data
├── requirements.txt       # Project dependencies
├── pytest.ini            # Pytest configuration
└── README.md             # This file
```

## Features

- Text analysis using spaCy
- Sentiment analysis using Transformers
- Basic threat detection
- Entity recognition
- REST API endpoints
- Comprehensive logging
- Extensive test coverage
- Rate limiting
- Concurrent request handling
- Error tracking and monitoring
- Real-time system metrics
- Prometheus integration
- Performance monitoring
- Health checks

## Monitoring

### Metrics Collection
- Request count and latency
- Threat scores over time
- System resource usage (CPU, memory, disk)
- Error tracking and classification
- Response time statistics

### Health Checks
- System resource monitoring
- Application performance metrics
- Error rate tracking
- Response time monitoring
- Disk space monitoring

### Prometheus Integration
- Exposes metrics in Prometheus format
- Available at `/metrics` endpoint
- Includes custom metrics for threat analysis
- System resource metrics
- Request/response metrics

### Logging
- Detailed application logs
- Error-specific logging
- Performance metrics logging
- System resource logging
- Threat detection logging

## API Endpoints

### POST /analyze
Analyzes text for potential threats.

Request body:
```json
{
    "text": "Text to analyze",
    "metadata": {
        "source": "optional source information",
        "timestamp": "optional timestamp"
    }
}
```

Response:
```json
{
    "threat_score": 0.0,
    "suspicious_patterns": [],
    "confidence": 0.0,
    "sentiment": {
        "pos": 0.0,
        "neg": 0.0,
        "neu": 0.0,
        "compound": 0.0
    },
    "entities": [],
    "pos_tags": []
}
```

### GET /health
Enhanced health check endpoint.

Response:
```json
{
    "status": "healthy",
    "timestamp": "2024-04-11T12:00:00Z",
    "system": {
        "memory_used_percent": 45.2,
        "cpu_percent": 12.5,
        "disk_usage_percent": 30.1
    },
    "application": {
        "requests_processed": 1000,
        "error_count": 5,
        "avg_response_time": 0.125
    }
}
```

### GET /metrics
Get current metrics data.

Response:
```json
{
    "requests": 1000,
    "errors": 5,
    "avg_response_time": 0.125,
    "max_response_time": 0.5,
    "threat_scores": [
        {
            "timestamp": "2024-04-11T12:00:00Z",
            "score": 0.5
        }
    ],
    "system_metrics": [
        {
            "timestamp": "2024-04-11T12:00:00Z",
            "memory_used": 1024000000,
            "cpu_percent": 12.5
        }
    ]
}
```

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Download spaCy model:
```bash
python -m spacy download en_core_web_sm
```

## Running the Server

Start the server with:
```bash
uvicorn src.app:app --reload
```

The server will be available at `http://localhost:8000`

## Monitoring Setup

### Prometheus
1. Install Prometheus
2. Configure prometheus.yml to scrape metrics from the server
3. Access metrics at `http://localhost:8000/metrics`

### Grafana
1. Install Grafana
2. Add Prometheus as a data source
3. Create dashboards for:
   - System metrics
   - Application performance
   - Threat detection statistics
   - Error rates

## Development

### Adding New Features

1. Create a new branch:
```bash
git checkout -b feature/new-feature
```

2. Make your changes
3. Add tests for the new feature
4. Run the test suite
5. Submit a pull request

### Code Style

- Follow PEP 8 guidelines
- Use type hints
- Add docstrings to functions and classes
- Write tests for new features
- Maintain test coverage above 90%

### Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Documentation

The project includes comprehensive documentation generated using Sphinx. To build the documentation:

1. Install the documentation dependencies:
```bash
pip install -r requirements.txt
```

2. Build the documentation:
```bash
cd docs
make html
```

The documentation will be available in `docs/_build/html/index.html`.

The documentation includes:
- API reference
- Module documentation
- Type hints
- Code examples
- Configuration details 