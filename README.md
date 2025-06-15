Back-Python
🛠️ Configuração do Ambiente
Este projeto utiliza um ambiente virtual para isolar as dependências. Siga os passos abaixo para configurar e rodar o backend.

1. Criar o ambiente virtual
python -m venv venv

2. Ativar o ambiente virtual
No Windows:
venv\Scripts\activate
No Linux/macOS:
source venv/bin/activate

3. Instalar as dependências
Instale as dependências listadas no arquivo requirements.txt:
pip install -r requirements.txt

4. Instalar dependências adicionais (caso necessário)
pip install python-dotenv
pip install requests
pip install google-auth
pip install Flask
pip install Flask-SQLAlchemy==3.1.1
pip install Flask-JWT-Extended==4.7.1
pip install Flask-Bcrypt
pip install pyotp
pip install Flask-Mail
pip install Flask-Migrate
pip install flask-cors
pip install psycopg2-binary

🚀 Executando o projeto
Após ativar o ambiente virtual e instalar as dependências, você pode rodar o backend com:
python app.py

📋 Observações
Certifique-se de que seu banco de dados esteja configurado corretamente (ex: PostgreSQL).
Ajuste as variáveis de ambiente conforme necessário (use um arquivo .env para configuração).
aUtilize o Flask-Migrate para gerenciar migrações do banco de dados.
