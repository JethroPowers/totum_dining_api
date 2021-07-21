from flask_api import FlaskAPI
from flask_sqlalchemy import SQLAlchemy


# local import
from instance.config import app_config

from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env.
print("HEALTH " * 5)
# initialize sql-alchemy
db = SQLAlchemy()


def create_app(config_name):
    load_dotenv()  # take environment variables from .env.

    app = FlaskAPI(__name__, instance_relative_config=True)
    app.config.from_object(app_config[config_name])
    app.config.from_pyfile('config.py')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)


    from .views import auth_blueprint
    app.register_blueprint(auth_blueprint)
    return app