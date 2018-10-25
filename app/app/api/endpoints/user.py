from flask import jsonify

from ..utils import senseless_print

from ...main import app


@app.route('/users/')
def route_users():
    users_data = []
    user_data = {
        'id': 1,
        'name': 'John',
    }
    users_data.append(user_data)
    senseless_print()
    return jsonify(users_data)
