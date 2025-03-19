from flask import Blueprint, request, jsonify


teste_bp = Blueprint('teste', __name__)

@teste_bp.route('/teste', methods=['GET'])
def teste():
    return jsonify({'message': 'Teste OK'})