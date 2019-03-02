import json

from tinydb import TinyDB, Query


def json_string_with_bytes_to_dict(value):
    return json.loads(value.replace("\\", "\\\\"), strict=False)


def _create_payload(pairs, user_id=None):
    payload = {}
    for k, v in pairs.items():
        if isinstance(v, dict):
            v = _create_payload(v)
            payload[f'"{k}"'] = v
        elif isinstance(v, list):
            v = [f'"{item}"' for item in v]
            payload[f'"{k}"'] = v
        else:
            payload[f'"{k}"'] = f'"{v}"'
    if user_id is not None:
        payload['"user_id"'] = user_id
    return payload


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


def get_shared_key_by_device_id(path, device_id):
    doc = search_tinydb_doc(path, "device_keys", Query().device_id == str(device_id))
    if doc and "shared_key" in doc:
        return doc["shared_key"]
