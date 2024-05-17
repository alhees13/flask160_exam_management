from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        from .routes import auth, test, question, grade
        app.register_blueprint(auth.bp)
        app.register_blueprint(test.bp)
        app.register_blueprint(question.bp)
        app.register_blueprint(grade.bp)

        db.create_all()

    return app
