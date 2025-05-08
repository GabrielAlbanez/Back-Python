from flask import Flask
from config import Config
from config_database import db
from flask_jwt_extended import JWTManager
from routes.auth import auth_bp
import os
from routes.teste import teste_bp
from routes.uploadImg import upload
from flask_mail import Mail
from flask_migrate import Migrate
from dotenv import load_dotenv
from flask_cors import CORS
from sqlalchemy import text



app = Flask(__name__)
load_dotenv()
CORS(app)
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config.from_object(Config)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db.init_app(app)
mail = Mail(app)  # ✅ Inicializar Flask-Mail
jwt = JWTManager(app)
migrate = Migrate(app, db)

app.register_blueprint(auth_bp, url_prefix='/auth')

app.register_blueprint(teste_bp, url_prefix='/')

app.register_blueprint(upload, url_prefix='/upload')

PORT = int(os.environ.get("PORT"))  # Usa a porta definida na variável PORT, ou 5000 por padrão

print(f"PORT: {PORT}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        try:
            db.session.execute(text("SELECT 1"))
            print("✅ Conexão com o banco de dados estabelecida com sucesso!")
        except Exception as e:
            print("❌ Erro ao conectar com o banco de dados:", e)
    app.run(host='0.0.0.0', port=PORT, debug=True)
    
    



