import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SQLALCHEMY_DATABASE_URI = 'postgresql://python-Db_owner:npg_ZX1BDtbwF0TM@ep-sparkling-pond-a4oc6c76-pooler.us-east-1.aws.neon.tech/python-Db?sslmode=require'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'supersecretkey'
    REFRESH_SECRET_KEY="supersecretkey"
    ACCESS_SECRET_KEY="supersecretkey"
    


    # Configuração do servidor SMTP
    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))  # Usando 587 como valor padrão
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True') == 'True'  # Converte para booleano
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')