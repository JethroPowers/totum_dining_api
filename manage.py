import os
from flask_script import Manager # class for handling a set of commands
from flask_migrate import Migrate, MigrateCommand
from app import db, create_app
from app import models


from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env.
print(os.getenv('APP_SETTINGS'), "manage.py" *3)
app = create_app(config_name=os.getenv('APP_SETTINGS'))
migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    manager.run()