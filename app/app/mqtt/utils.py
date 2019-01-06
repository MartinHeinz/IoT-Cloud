import json
from datetime import date, datetime


class Payload:

    def __init__(self, **fields):
        for key, value in fields.items():
            setattr(self, key, value)

    def __bytes__(self):
        result = b'{'
        for attr, value in self.__dict__.items():
            result += b'\'%s\': \'%s\', ' % (attr.encode('utf-8'), convert_based_on_type(value).encode('utf-8'))
        return result[:-2] + b'}'

    def __str__(self):
        result = '{'
        for attr, value in self.__dict__.items():
            value = convert_based_on_type(value).replace("\\", "\\\\")  # TODO can there be a backslash in hash?
            result = f'{result}\"{attr}\": \"{value}\", '
        result = result[:-2] + '}'
        return json.dumps(json.loads(result, strict=False), indent=4)

    def __repr__(self):
        return f'Payload: {self.__str__()}'


def convert_based_on_type(value):
    if isinstance(value, int):
        return str(value)
    if isinstance(value, bytes):
        return value.decode('utf-8')
    if isinstance(value, date):
        return str(value)
    if isinstance(value, datetime):
        return str(value.date())
    return str(value)
