import random
import string
from timeit import default_timer as timer
from urllib.parse import urlparse

import psycopg2
from sqlalchemy import create_engine, Boolean, Integer, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy_repr import RepresentableBase

from client.crypto_utils import blind_index


Base = declarative_base(cls=RepresentableBase)


class DataAccessLayer:
    def __init__(self, user, password, db, host='localhost', port=5432):
        # postgres+psycopg2://postgres:postgres@172.17.0.2:5430/postgres
        url = 'postgresql://{}:{}@{}:{}/{}'
        self.engine = None
        self.Session = None
        self.session = None
        self.conn_string = url.format(user, password, host, port, db)

    def connect(self):
        self.engine = create_engine(self.conn_string)
        Base.metadata.bind = self.engine
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, autoflush=False)


class BlindIndex(Base):
    __tablename__ = 'blind_index'
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True)
    status = Column(Boolean, default=False)

    name = Column(String(200), unique=False, nullable=True)
    name_bi = Column(String(200), unique=False, nullable=True)  # Blind index for .name


dal = DataAccessLayer(user="postgres", password="postgres", host="172.26.0.2", port=5430, db="benchmark")

dal.connect()
Base.metadata.drop_all(dal.engine)
Base.metadata.create_all(dal.engine)
connection = dal.engine.connect()
session = dal.Session()

rows = []
rows_num = 1000
searched_row = 500
searched_name = ""
key = b'\xb8z\x1dU)\xb7YY~\xd3>\x00\x85^\x11|\x12K\x95e\xd4\xca\xc9\xf2,\xe0g\xe4\xc44\xd3W'

for i in range(1, rows_num):
    name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    if i == searched_row:
        searched_name = name
    rows.append(BlindIndex(
        id=i,
        name=name,
        name_bi=blind_index(key, name)
    ))

session.add_all(rows)
session.commit()


start = timer()
result = session.query(BlindIndex).filter(BlindIndex.name_bi == blind_index(key, searched_name)).scalar()
end = timer()

print(f'We searched for row with name: {searched_name}')
print(f'We found row: {result}')
print(f'Search over {rows_num} rows took {end - start}\n')

uri = urlparse(dal.conn_string)
username = uri.username
password = uri.password
database = uri.path[1:]
hostname = uri.hostname
port = uri.port
connection = psycopg2.connect(
    database=database,
    user=username,
    password=password,
    host=hostname,
    port=port
)

cursor = connection.cursor()

start = timer()
cursor.execute(f"SELECT * FROM {BlindIndex.__tablename__} WHERE name_bi = '{blind_index(key, searched_name)}'")
result = cursor.fetchone()
end = timer()

print(f'We searched for row with name: {searched_name}')
print(f'We found row: {result}')
print(f'Search over {rows_num} rows took {end - start}')

cursor.close()
connection.close()

# TODO run directly with raw SQL inside PGadmin or psql console
