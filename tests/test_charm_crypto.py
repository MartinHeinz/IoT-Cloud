# -*- coding: utf-8 -*-

from .context import handler

import pytest


def test_ABE():
    assert handler.hello({"arg": "test_ABE"}) == {"test_ABE": True}


def test_python_version():
    assert handler.hello({"arg": "python_version"}) == {"python_version": "3.6.5 (default, Apr  1 2018, 05:46:30) \n[GCC 7.3.0]"}
