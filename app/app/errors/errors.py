from app.consts import SOMETHING_WENT_WRONG_MSG
from app.utils import http_json_response


def handle_error(e):
    if hasattr(e, "code"):
        return http_json_response(False, e.code, **{"error": SOMETHING_WENT_WRONG_MSG})
    return http_json_response(False, 500, **{"error": SOMETHING_WENT_WRONG_MSG})
