from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON

db = SQLAlchemy()

class AnalysisResult(db.Model):
    __tablename__ = 'analysis_results'
    
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    threat_score = db.Column(db.Float, nullable=False)
    entities = db.Column(JSON, nullable=True)
    sentiment = db.Column(JSON, nullable=True)
    suspicious_patterns = db.Column(JSON, nullable=True)
    metadata = db.Column(JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Entity(db.Model):
    __tablename__ = 'entities'
    
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)
    analysis_result_id = db.Column(db.Integer, db.ForeignKey('analysis_results.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    analysis_result = db.relationship('AnalysisResult', backref=db.backref('entity_objects', lazy=True))

class ThreatPattern(db.Model):
    __tablename__ = 'threat_patterns'
    
    id = db.Column(db.Integer, primary_key=True)
    pattern = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.Float, nullable=False)
    analysis_result_id = db.Column(db.Integer, db.ForeignKey('analysis_results.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    analysis_result = db.relationship('AnalysisResult', backref=db.backref('pattern_objects', lazy=True)) 