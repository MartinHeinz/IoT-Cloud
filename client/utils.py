import json

from tinydb import TinyDB


def json_string_with_bytes_to_dict(value):
    return json.loads(value.replace("\\", "\\\\"), strict=False)


def _create_payload(user_id, pairs):
    payload = {}
    for k, v in pairs.items():
        payload[f'"{k}"'] = f'"{pairs[k]}"'
    payload['"user_id"'] = user_id
    return f'"{json.dumps(payload)}"'


def get_tinydb_table(path, table_name):
    db = TinyDB(path)
    table = db.table(name=table_name)
    return table


def search_tinydb_doc(path, table_name, query):
    table = get_tinydb_table(path, table_name)
    return table.get(query)


def insert_into_tinydb(path, table_name, value):
    db = TinyDB(path)
    table = db.table(name=table_name)
    table.insert(value)
