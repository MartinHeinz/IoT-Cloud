from src.ABE import main
import sys


def hello(params):
    value = params.get("arg", None)

    if value == "test_ABE":
        return {value: main.test_abe()}
    elif value == "python_version":
        return {value: sys.version}

    return {"Default": "Value"}
