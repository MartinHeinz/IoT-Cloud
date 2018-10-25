from flask import Blueprint

home = Blueprint('home', __name__)

@home.route('/')
def hello():
    # for u in db.session.query(User).all():
    #     temp += str(u.__dict__)
    # global Hello
    # return str(db.session.query(User).count())
    return "Hello"
