class Config:
    SQLALCHEMY_DATABASE_URI = 'postgresql://username:password@db:5432/user_db'  # Use the service name in docker-compose
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'your_jwt_secret_key'  # Change this!