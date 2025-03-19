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

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()
mail = Mail()


def send_email_verification(email, otp_code):
    """Função para enviar email com o código OTP"""
    msg = Message("Confirme seu email - Código OTP", recipients=[email])
    msg.body = f"Seu código de ativação é: {otp_code}. Ele expira em 2 minutos."
    mail.send(msg)


def send_password_reset_email(user):
    """Função para enviar um e-mail com o link para redefinir a senha"""
    reset_token = str(uuid.uuid4())  # Gera um token único
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)  # O token expira em 1 hora

    # Criar o token de redefinição de senha no banco de dados
    reset_token_entry = PasswordResetToken(
        user_id=user.id,  # Relacionamento agora é feito pelo id
        token=reset_token,
        expires_at=expires_at
    )
    db.session.add(reset_token_entry)
    db.session.commit()

    # Enviar o e-mail com o link
    reset_link = f"http://example.com/reset-password/{reset_token}"
    msg = Message("Redefinir Senha", recipients=[user.email])
    msg.body = f"Para redefinir sua senha, clique no link abaixo:\n\n{reset_link}"
    mail.send(msg)


@auth_bp.route('/register', methods=['POST'])
def register():
    idRamdom = str(uuid.uuid4())  # Gerar ID único
    data = request.get_json()

    # Alterado para verificar o id do usuário
    existing_user = User.query.filter_by(email=data['email']).first()

    if existing_user:
        return jsonify({'message': 'e-mail já cadastrado!'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    otp_secret = pyotp.random_base32()

    # Criar um novo usuário
    user = User(id=idRamdom, name=data['name'], email=data['email'], password=hashed_password, otp_secret=otp_secret, email_valid=False)

    db.session.add(user)
    db.session.commit()

    # Gerar código OTP baseado no otp_secret
    totp = pyotp.TOTP(otp_secret)
    otp_code = totp.now()

    # Enviar código por email
    send_email_verification(data['email'], otp_code)

    return jsonify({'message': 'Usuário registrado! Verifique seu email para ativar a conta.'}), 201


@auth_bp.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()

    # Alterado para buscar pelo id ao invés do email
    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'message': 'Usuário não encontrado!'}), 404
    if user.email_valid:
        return jsonify({'message': 'Email já validado!'}), 400

    totp = pyotp.TOTP(user.otp_secret, interval=120)

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
        access_token = create_access_token(identity=user.id)
        return jsonify({'message': 'Login bem-sucedido!', 'access_token': access_token})

    return jsonify({'message': 'Credenciais inválidas!'}), 401


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()

    # Alterado para buscar pelo email ao invés do id
    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'message': 'Usuário não encontrado!'}), 404

    # Enviar e-mail com o link para redefinir a senha
    send_password_reset_email(user)

    return jsonify({'message': 'Instruções para redefinir a senha foram enviadas para seu e-mail.'}), 200


@auth_bp.route('/reset-password/<reset_token>', methods=['POST'])
def reset_password(reset_token):
    data = request.get_json()

    # Buscar o token no banco de dados
    reset_token_entry = PasswordResetToken.query.filter_by(token=reset_token).first()

    if not reset_token_entry:
        return jsonify({'message': 'Token de redefinição inválido!'}), 400

    # Verificar se o token expirou
    if reset_token_entry.is_expired():
        return jsonify({'message': 'Token de redefinição expirado!'}), 400

    # Buscar o usuário associado ao token
    user = User.query.filter_by(id=reset_token_entry.user_id).first()

    if not user:
        return jsonify({'message': 'Usuário não encontrado!'}), 404

    # Atualizar a senha do usuário
    new_password = data['password']
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password
    db.session.commit()

    # Remover o token de redefinição após o uso
    db.session.delete(reset_token_entry)
    db.session.commit()

    return jsonify({'message': 'Senha redefinida com sucesso!'}), 200


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
 
 
