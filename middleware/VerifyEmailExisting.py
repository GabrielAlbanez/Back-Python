from functools import wraps
from flask import request, jsonify
from models import User, ProviderTypeEnum

def user_exist():
    def wrapper(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            data = request.get_json()
            email = data.get('email')
            provider_type = data.get('providerType')

            if not email:
                return jsonify({"message": "E-mail não fornecido."}), 400

            if not provider_type:
                return jsonify({"message": "Provedor não fornecido."}), 400

            # Verifica se o e-mail já está vinculado a algum provedor
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                # Se o e-mail já estiver vinculado a um provedor diferente, retorna erro
                if existing_user.providerType.name != provider_type:
                    return jsonify({
                        "message": f"O e-mail {email} já está vinculado a outro provedor."
                    }), 400

            return func(*args, **kwargs)

        return decorated_function
    return wrapper
