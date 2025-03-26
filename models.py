from config_database import db
from datetime import datetime, timedelta, timezone
import uuid
from sqlalchemy import String
from flask import current_app
import os

class User(db.Model):
    __tablename__ = 'user'  # Nome correto da tabela no banco de dados

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))  # Gerar UUID de forma correta
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email_valid = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_image = db.Column(db.String(255), nullable=True)
    
    # Relacionamento com a tabela 'password_reset_token'
    reset_tokens = db.relationship('PasswordResetToken', backref='user', lazy=True)
    
    def update_profile_image(self, new_image_path):
        """Remove a imagem antiga e atualiza para a nova."""
        if self.profile_image:
            old_path = os.path.join(current_app.config['UPLOAD_FOLDER'], self.profile_image)
            if os.path.exists(old_path):
                os.remove(old_path)  # Exclui a imagem antiga
        self.profile_image = new_image_path

    def __init__(self, id=None, name=None, email=None, password=None, otp_secret=None, email_valid=False):
        if id is None:
            self.id = str(uuid.uuid4())  # Gerar um id aleatório se não for fornecido
        self.name = name
        self.email = email
        self.password = password
        self.otp_secret = otp_secret
        self.email_valid = email_valid

class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_token'  # Nome correto da tabela no banco de dados

    token = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)  # Referência ao 'id' de User
    expires_at = db.Column(db.DateTime, nullable=False)


    def is_expired(self):
        return datetime.now(tz=timezone.utc) > self.expires_at
    


   
