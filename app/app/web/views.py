from flask import render_template

from app.web import web


@web.route('/')
def index():
    return render_template('index.html', title='Home')
