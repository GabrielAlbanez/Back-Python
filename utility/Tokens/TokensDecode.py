import jwt 
from config import Config
def decode_access_token(token):
    try:
        payload = jwt.decode(token, Config.ACCESS_SECRET_KEY, algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, Config.REFRESH_SECRET_KEY, algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None