# -*- coding: utf-8 -*-

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'app')))  # TODO change/add path to client/node-red scripts
from app.app_setup import create_app, db
from app.web import forms, views
