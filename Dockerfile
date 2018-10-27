FROM tiangolo/uwsgi-nginx-flask:python3.7

RUN apt-get update
RUN apt-get -y install python-psycopg2 libpq-dev

RUN pip install flask-mqtt flask-sqlalchemy psycopg2 APScheduler


COPY ./app /app
