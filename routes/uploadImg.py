from werkzeug.utils import secure_filename
import uuid
import os
from flask import Blueprint, request, jsonify, current_app, send_from_directory
from models import User
from config_database import db

upload = Blueprint('upload', __name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Verifica se a extensão do arquivo é permitida."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@upload.route('/profile_image/<user_id>', methods=['POST'])
def upload_profile_image(user_id):
    # Exibindo o ID do usuário para depuração
    print(f"{user_id}")

    # Consultando o usuário no banco de dados pelo ID
    user = User.query.get(user_id)

    # Verificando se o usuário existe
    if not user:
        return jsonify({'message': 'Usuário não encontrado'}), 404

    # Obtendo o arquivo enviado na requisição
    file = request.files.get('file')  # Usando .get() para evitar o KeyError

    # Verificando se o arquivo foi enviado
    if file is None:
        return jsonify({'message': 'Nenhum arquivo enviado'}), 400

    # Verificando se o nome do arquivo não está vazio
    if file.filename == '':
        return jsonify({"error": "Nenhuma imagem selecionada"}), 400

    # Verificando se o arquivo tem uma extensão permitida
    if file and allowed_file(file.filename):
        # Gerando um nome único para o arquivo, utilizando uuid
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"

        # Acessando a pasta configurada para uploads
        upload_folder = current_app.config['UPLOAD_FOLDER']
        
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        # Definindo o caminho completo do arquivo a ser salvo diretamente em 'uploads'
        file_path = os.path.join(upload_folder, unique_filename)

        # Apagando a imagem antiga antes de salvar a nova, se existir
        if user.profile_image:
            old_image_path = os.path.join(upload_folder, user.profile_image)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        # Salvando o novo arquivo na pasta de uploads
        file.save(file_path)

        # Atualizando a informação no banco de dados com o nome da nova imagem
        user.profile_image = unique_filename
        db.session.commit()

        # Retornando uma resposta de sucesso com a URL do arquivo
        return jsonify({"message": "Imagem de perfil atualizada com sucesso", "image_url": file_path}), 200

    # Caso o formato do arquivo não seja permitido
    return jsonify({"error": "Formato de arquivo não permitido"}), 400

@upload.route('/get_image/<image_name>', methods=['GET'])
def get_image(image_name):
    # Obtendo o caminho da pasta de uploads
    upload_folder = current_app.config['UPLOAD_FOLDER']

    # Construindo o caminho completo do arquivo de imagem
    image_path = os.path.join(upload_folder, image_name)

    print(f"image path: {image_path}")

    # Verificando se a imagem existe
    if not os.path.exists(image_path):
        return jsonify({'message': 'Imagem não encontrada'}), 404

    # Retornando o arquivo de imagem
    return send_from_directory(upload_folder, image_name)
