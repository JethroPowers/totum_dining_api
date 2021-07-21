import os

from app import create_app


from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env.
config_name = os.getenv('APP_SETTINGS') # config_name = "development"
print(config_name, "run.py" *3)
app = create_app(config_name)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port='5000')

