from functools import wraps
from flask import request, jsonify
from utility.Tokens.TokensDecode import decode_access_token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # O token pode ser passado no header Authorization
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token de acesso ausente!'}), 401
        user_id = decode_access_token(token)
        if not user_id:
            return jsonify({'message': 'Token de acesso inválido ou expirado!'}), 401
        return f(user_id, *args, **kwargs)
    return decorated
