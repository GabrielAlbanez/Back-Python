import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

def decode_google_jwt(token: str):
    try:
        print("Token recebido para validação:", token[:30], "...")  # Mostrar só o início
        request = google_requests.Request()

        # Verifica e decodifica o token
        id_info = id_token.verify_oauth2_token(token, request)

        return id_info
    except ValueError as ve:
        print("Erro ao validar token:", ve)
        raise Exception("Token inválido ou expirado.")
    except Exception as e:
        print("Erro inesperado ao validar token:", e)
        raise Exception("Não foi possível validar o token.")
