from flask import Flask
from config import config_by_name

def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    from app.routes.auth_routes import auth_bp
    from app.routes.rbac_routes import rbac_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(rbac_bp, url_prefix='/api/rbac')

    return app
