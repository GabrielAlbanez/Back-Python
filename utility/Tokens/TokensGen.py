import jwt
from datetime import datetime, timedelta, timezone
from config import Config


ACCESS_SECRET_KEY = Config.ACCESS_SECRET_KEY
REFRESH_SECRET_KEY = Config.REFRESH_SECRET_KEY


def generate_access_token(user_id):
    payload = {
        'sub': str(user_id),
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(minutes=15)  # Token válido por 15 minutos
    }
    return jwt.encode(payload, ACCESS_SECRET_KEY, algorithm='HS256')

def generate_refresh_token(user_id):
    payload = {
        'sub': str(user_id),
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(days=7)  # Token válido por 7 dias
    }
    return jwt.encode(payload, REFRESH_SECRET_KEY, algorithm='HS256')