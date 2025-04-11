from flask import Flask
from flask_migrate import Migrate
from models import db
from config import Config

def init_app(app: Flask):
    """Initialize the database with the Flask app"""
    app.config.from_object(Config)
    db.init_app(app)
    migrate = Migrate(app, db)
    
    with app.app_context():
        db.create_all()
        
    return app 