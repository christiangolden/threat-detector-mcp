"""FastAPI Application Module.

This module provides the main FastAPI application and endpoints for the
Threat Analysis MCP Server.
"""

from fastapi import FastAPI, HTTPException, Request
import logging
from logging.handlers import RotatingFileHandler
import traceback
import time
import os
from typing import Dict, Any

from .monitoring import monitoring
from .utils.nlp import initialize_nltk, analyze_text
from .utils.validation import TextAnalysisRequest, TextAnalysisResponse

# Configure logging
def setup_logging() -> logging.Logger:
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

# Initialize FastAPI app
app = FastAPI(
    title="Threat Analysis MCP Server",
    description="A FastAPI-based server for analyzing text communications for potential terrorist threats",
    version="0.1.0"
)

# Initialize NLTK
try:
    initialize_nltk()
except Exception as e:
    logger.error(f"Failed to initialize NLTK: {str(e)}")
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
async def get_metrics() -> Dict[str, Any]:
    """Get current application metrics.
    
    Returns:
        Dict[str, Any]: Current metrics including request counts, response times,
                       threat scores, and system metrics
    """
    return monitoring.get_metrics()

@app.get("/health")
async def health_check() -> Dict[str, Any]:
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
async def analyze(request: TextAnalysisRequest) -> TextAnalysisResponse:
    """Analyze text for potential threats.
    
    Args:
        request (TextAnalysisRequest): The text to analyze and optional metadata
        
    Returns:
        TextAnalysisResponse: Analysis results
        
    Raises:
        HTTPException: If analysis fails
    """
    try:
        start_time = time.time()
        analysis_result = analyze_text(request.text)
        process_time = time.time() - start_time
        
        # Track metrics
        monitoring.track_threat_score(analysis_result['threat_score'])
        await monitoring.track_request(request, process_time)
        
        return TextAnalysisResponse(**analysis_result)
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}\n{traceback.format_exc()}")
        monitoring.track_error("analysis_error")
        raise HTTPException(status_code=500, detail="Analysis failed") 