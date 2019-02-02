import random
import string
from urllib.parse import urlparse

import psycopg2
import pytest
from sqlalchemy import create_engine, Boolean, Integer, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy_repr import RepresentableBase

from client.crypto_utils import hash


Base = declarative_base(cls=RepresentableBase)
searched_row = 5
searched_name = ""


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


def setup():
    dal = DataAccessLayer(user="postgres", password="postgres", host="192.168.0.103", port=5430, db="benchmark")
    dal.connect()
    return dal


@pytest.fixture(scope="module", autouse=True)
def create_data():
    dal = setup()
    session = dal.Session()

    Base.metadata.drop_all(dal.engine)
    Base.metadata.create_all(dal.engine)

    rows = []
    rows_num = 10
    global searched_row
    global searched_name

    for i in range(1, rows_num):
        name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        if i == searched_row:
            searched_name = name
        rows.append(BlindIndex(
            id=i,
            name=name,
            name_bi=hash(name, str(i))
        ))

    session.add_all(rows)
    session.commit()


def setup_cursor():
    dal = setup()

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

    return connection.cursor(), connection


def test_blind_index_orm(benchmark):
    dal = setup()
    result = benchmark.pedantic(query_orm, args=(dal.Session(), searched_name, searched_row), iterations=5, rounds=5)

    assert result.id == searched_row


def query_orm(session, name, row):
    return session.query(BlindIndex).filter(BlindIndex.name_bi == hash(name, str(row))).scalar()


def test_blind_index_cursor(benchmark):
    cursor, connection = setup_cursor()
    result = benchmark.pedantic(query_cursor, args=(cursor, searched_name, searched_row), iterations=5, rounds=5)
    cursor.close()
    connection.close()

    assert result[0] == searched_row


def query_cursor(cursor, name, row):
    cursor.execute(f"SELECT * FROM {BlindIndex.__tablename__} WHERE name_bi = '{hash(name, str(row))}'")
    return cursor.fetchone()

# TODO run directly with raw SQL inside PGadmin or psql console
