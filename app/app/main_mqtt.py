import atexit
from functools import partial

from app.app_setup_mqtt import *
from app.config import *
from apscheduler.schedulers.background import BackgroundScheduler

app = create_app(os.environ.get('FLASK_ENV'))

# client.loop_forever()  # this blocks execution forever


scheduler = BackgroundScheduler()
scheduler.add_job(func=client.loop, trigger="interval", seconds=3)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

if __name__ == "__main__":
    # Only for debugging while developing
    app.run(host='0.0.0.0', debug=True, use_reloader=False, port=5000)
