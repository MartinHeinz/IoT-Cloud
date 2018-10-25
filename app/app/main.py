from flask import Flask

from app.api.endpoints.index import home

app = Flask(__name__)

from app.core import app_setup

app.register_blueprint(home)

if __name__ == "__main__":
    # Only for debugging while developing
    app.run(host='0.0.0.0', debug=True, use_reloader=False, port=5000)
