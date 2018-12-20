import codecs
import json
from uuid import UUID


def is_valid_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = UUID(uuid_to_test, version=version)
    except:
        return False

    return str(uuid_obj) == uuid_to_test


def json_string_with_bytes_to_dict(value):
    escaped_data = codecs.escape_decode(value)[0].decode("UTF-8")
    return json.loads(escaped_data, strict=False)
