from utility.VerfyToken import decode_google_jwt
from models import ProviderTypeEnum
from flask import Blueprint, request, jsonify
from models import User, PasswordResetToken
from config_database import db
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import pyotp
from flask_mail import Mail, Message
from config import Config
import uuid
from datetime import datetime, timedelta, timezone
import os
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from middleware.VerifyEmailExisting import user_exist
from datetime import datetime
import time
auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()
mail = Mail()


GOOGLE_CLIENT_ID = "911018498691-04lkb4r2c24cjdnevpnr2e266v8cho6p.apps.googleusercontent.com"


def send_password_reset_otp(email, otp_code):
    """Função para enviar email com o código de redefinição de senha (OTP)"""
    msg = Message("Redefinir senha - Código OTP", recipients=[email])
    msg.body = f"Seu código de redefinição de senha é: {otp_code}. Ele expira em 2 minutos."
    mail.send(msg)


def send_email_verification(email, otp_code):
    """Função para enviar email com o código OTP"""
    msg = Message("Confirme seu email - Código OTP", recipients=[email])
    msg.body = f"Seu código de ativação é: {otp_code}. Ele expira em 2 minutos."
    mail.send(msg)


def send_password_reset_email(user):
    """Função para enviar um e-mail com o link para redefinir a senha"""
    reset_token = str(uuid.uuid4())  # Gera um token único
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    # O token expira em 1 hora

    # Criar o token de redefinição de senha no banco de dados
    reset_token_entry = PasswordResetToken(
        user_id=user.id,  # Relacionamento agora é feito pelo id
        token=reset_token,
        expires_at=expires_at
    )
    db.session.add(reset_token_entry)
    db.session.commit()

    # Enviar o e-mail com o link
    reset_link = f"https://rest-password-page-next.vercel.app/reset-password/{reset_token}"
    msg = Message("Redefinir Senha", recipients=[user.email])
    msg.body = f"Para redefinir sua senha, clique no link abaixo:\n\n{reset_link}"
    mail.send(msg)


@auth_bp.route('/register', methods=['POST'])
@user_exist()
def register():
    idRamdom = str(uuid.uuid4())  # Gerar ID único
    data = request.get_json()

    # Alterado para verificar o id do usuário
    existing_user = User.query.filter_by(email=data['email']).first()

    if existing_user:
        return jsonify({'message': 'e-mail já cadastrado!'}), 400

    hashed_password = bcrypt.generate_password_hash(
        data['password']).decode('utf-8')
    otp_secret = pyotp.random_base32()
    print(list(ProviderTypeEnum))

    # Criar um novo usuário
    user = User(id=idRamdom, name=data['name'], email=data['email'],
                password=hashed_password, otp_secret=otp_secret, email_valid=False, providerType=ProviderTypeEnum.credentials, profile_image="")

    db.session.add(user)
    db.session.commit()

    # Gerar código OTP baseado no otp_secret
    totp = pyotp.TOTP(otp_secret,  interval=120)
    otp_code = totp.now()

    # Enviar código por email
    send_email_verification(data['email'], otp_code)

    return jsonify({'message': 'Usuário registrado! Verifique seu email para ativar a conta.'}), 201


@auth_bp.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    print(
        f"verify-email : email-req -  {data['email']} - otp-req - {data['otp']}")

    # Alterado para buscar pelo id ao invés do email
    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'message': 'Usuário não encontrado!'}), 404
    if user.email_valid:
        return jsonify({'message': 'Email já validado!'}), 400

    totp = pyotp.TOTP(user.otp_secret, interval=120)

    print(f"user encontrado : {user}")
    print(f" codigo otp pegod do user : {user.otp_secret}")
    print(f"codigo otp gerado : {totp.now()}")

    if totp.verify(data['otp']):  # ✅ Verifica se o OTP digitado é válido
        user.email_valid = True
        db.session.commit()
        return jsonify({'message': 'Email validado com sucesso!'}), 200
    else:
        return jsonify({'message': 'Código OTP inválido ou expirado!'}), 400


@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()

    # Alterado para buscar pelo id ao invés do email
    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'message': 'Usuário não encontrado!'}), 404
    if user.email_valid:
        return jsonify({'message': 'Email já validado!'}), 400

    # Gerar um novo código OTP
    totp = pyotp.TOTP(user.otp_secret, interval=120)
    otp_code = totp.now()

    # Enviar novo código por email
    send_email_verification(data['email'], otp_code)

    return jsonify({'message': 'Novo código OTP enviado para o email.'}), 200


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # Alterado para buscar pelo email ao invés do id
    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'message': 'Usuário não encontrado!'}), 404

    if not user.email_valid:
        return jsonify({'message': 'Email ainda não validado! Verifique seu email.'}), 403

    if bcrypt.check_password_hash(user.password, data['password']):
        # Gerar JWT após login bem-sucedido com o ID do usuário
        userData = {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'profile_image': user.profile_image,
            'provedorType': user.providerType.name
        }
        return jsonify({'message': 'Login bem-sucedido!', 'user': userData})

    return jsonify({'message': 'Credenciais inválidas!'}), 401


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()

    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'message': 'Usuário não encontrado!'}), 404

    # Gerar novo OTP
    otp_secret = user.otp_secret
    if not otp_secret:
        otp_secret = pyotp.random_base32()
        user.otp_secret = otp_secret
        db.session.commit()

    totp = pyotp.TOTP(otp_secret, interval=120)
    otp_code = totp.now()

    # Enviar o OTP para o email
    send_password_reset_otp(user.email, otp_code)

    return jsonify({'message': 'Código OTP enviado para redefinir a senha.'}), 200




@auth_bp.route('/verify-password-code', methods=['POST'])
def verify_password_code():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'Usuário não encontrado!'}), 404

    if not user.otp_secret:
        return jsonify({'message': 'OTP não foi solicitado!'}), 400

    totp = pyotp.TOTP(user.otp_secret, interval=120)

    if totp.verify(otp):
        hashed_password = bcrypt.generate_password_hash(
            new_password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        return jsonify({'message': 'Senha redefinida com sucesso!'}), 200
    else:
        return jsonify({'message': 'Código OTP inválido ou expirado!'}), 400




@auth_bp.route('/get-user-data', methods=['GET'])
@jwt_required()
def get_user_data():
    # Obtém o ID do usuário do JWT
    user_id = get_jwt_identity()

    # Recupera todos os dados do usuário usando o ID
    user = User.query.get(user_id)

    if not user:
        return jsonify({'message': 'Usuário não encontrado!'}), 404

    # Retorna os dados do usuário
    user_data = {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'email_valid': user.email_valid,
        'created_at': user.created_at,
    }

    return jsonify({'user': user_data}), 200


@auth_bp.route('/googlee', methods=['POST'])
@user_exist()  # Middleware de verificação
def google_login():
    data = request.get_json()
    token = data.get("token")

    if not token:
        return jsonify({"message": "Token não fornecido"}), 400

    try:
        # Código de validação do token
        id_info = decode_google_jwt(token)

        email = id_info.get("email")
        name = id_info.get("name")
        picture = id_info.get("picture")

        # Verifica se o usuário já existe no banco
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({
                "user": {
                    "id": existing_user.id,
                    "email": existing_user.email,
                    "name": existing_user.name,
                    "profile_image": existing_user.profile_image,
                    "providerType": existing_user.providerType.name,
                }
            }), 200

        # Caso o usuário não exista, cria um novo usuário com o provedor Google
        user = User(
            email=email,
            name=name,
            password="google_user_password",  # ou alguma senha padrão
            otp_secret="",
            email_valid=True,
            profile_image=picture,
            providerType=ProviderTypeEnum.google
        )
        db.session.add(user)
        db.session.commit()

        return jsonify({
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "profile_image": user.profile_image,
                "providerType": user.providerType.name,
            }
        }), 200

    except ValueError as e:
        return jsonify({"message": "Token inválido"}), 400

    except Exception as e:
        return jsonify({"message": "Erro ao validar o token"}), 400
