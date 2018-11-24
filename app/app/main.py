import os

from app.app_setup import create_app

app = create_app(os.environ.get('FLASK_ENV'))

if __name__ == "__main__":
    # Only for debugging while developing
    app.run(host='0.0.0.0', debug=True, use_reloader=False, port=5000)
