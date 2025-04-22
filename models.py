from config_database import db
from datetime import datetime, timedelta, timezone
import uuid
from sqlalchemy import String
from flask import current_app
import os
import enum
from sqlalchemy.dialects.postgresql import ENUM  # <-- Use ENUM específico do PostgreSQL
from typing import Optional


class ProviderTypeEnum(enum.Enum):
    google = "google"
    credentials = "credentials"


# Cria o tipo ENUM do PostgreSQL antes de usá-lo no modelo
provider_type_enum = ENUM(ProviderTypeEnum, name="provider_type_enum", create_type=False)


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email_valid = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_image = db.Column(db.String(255), nullable=False)  # Alterado para nullable=False
    providerType = db.Column(provider_type_enum, nullable=False)  # Alterado para nullable=False

    reset_tokens = db.relationship('PasswordResetToken', backref='user', lazy=True)

    def update_profile_image(self, new_image_path):
        """Remove a imagem antiga e atualiza para a nova."""
        if self.profile_image:
            old_path = os.path.join(current_app.config['UPLOAD_FOLDER'], self.profile_image)
            if os.path.exists(old_path):
                os.remove(old_path)
        self.profile_image = new_image_path

    def __init__(self, id=None, name=None, email=None, password=None, otp_secret=None, email_valid=False, profile_image=None, providerType=None):
        if id is None:
            self.id = str(uuid.uuid4())
        self.name = name
        self.email = email
        self.password = password
        self.otp_secret = otp_secret
        self.email_valid = email_valid
        self.profile_image = profile_image  # Agora aceita esse argumento
        self.providerType = providerType


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_token'

    token = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    def is_expired(self):
        return datetime.now(tz=timezone.utc) > self.expires_at
