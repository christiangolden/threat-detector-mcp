"""Threat Analysis MCP Server Package.

A FastAPI-based server for analyzing text communications for potential
terrorist threats using NLP and machine learning.
"""

__version__ = "0.1.0"

from .app import app
from .monitoring import monitoring

__all__ = ["app", "monitoring"] 