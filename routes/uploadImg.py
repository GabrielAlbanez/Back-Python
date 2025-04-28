from werkzeug.utils import secure_filename
import uuid
import os
from flask import Blueprint, request, jsonify, current_app, send_from_directory
from models import User
from config_database import db

upload = Blueprint('upload', __name__)

# Extensões de arquivos permitidas
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Verifica se a extensão do arquivo é permitida."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@upload.route('/profile_image/<user_id>', methods=['POST'])
def upload_profile_image(user_id):
    """Rota para upload de imagem de perfil."""
    print(f"User ID recebido: {user_id}")

    # Buscar usuário no banco
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'Usuário não encontrado'}), 404

    # Buscar o arquivo enviado
    file = request.files.get('file')
    if file is None:
        return jsonify({'message': 'Nenhum arquivo enviado'}), 400

    if file.filename == '':
        return jsonify({'message': 'Nenhuma imagem selecionada'}), 400

    if not allowed_file(file.filename):
        return jsonify({'message': 'Formato de arquivo não permitido'}), 400

    # Gerar nome único para a imagem
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"

    # Pasta de uploads
    upload_folder = current_app.config['UPLOAD_FOLDER']
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    file_path = os.path.join(upload_folder, unique_filename)

    # Deletar imagem anterior se existir
    if user.profile_image:
        old_image_path = os.path.join(upload_folder, user.profile_image)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

    # Salvar nova imagem
    file.save(file_path)

    # Atualizar usuário
    user.profile_image = unique_filename
    db.session.commit()

    # ✅ Retornar só o nome da imagem no response
    return jsonify({
        "message": "Imagem de perfil atualizada com sucesso",
        "image_name": unique_filename
    }), 200

@upload.route('/get_image/<image_name>', methods=['GET'])
def get_image(image_name):
    """Rota para retornar a imagem do perfil."""
    upload_folder = current_app.config['UPLOAD_FOLDER']

    if not os.path.exists(os.path.join(upload_folder, image_name)):
        return jsonify({'message': 'Imagem não encontrada'}), 404

    return send_from_directory(upload_folder, image_name)
