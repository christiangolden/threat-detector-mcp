import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database settings
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///threat_analysis.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    
    # Application settings
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    TESTING = os.getenv('TESTING', 'False').lower() == 'true'
    
    # NLP settings
    NLTK_DATA_PATH = os.getenv('NLTK_DATA_PATH', 'nltk_data')
    
    # Threat analysis settings
    THREAT_THRESHOLD = float(os.getenv('THREAT_THRESHOLD', '0.7'))
    MIN_CONFIDENCE = float(os.getenv('MIN_CONFIDENCE', '0.5')) 