from app.api.utils import http_json_response

SOMETHING_WENT_WRONG_MSG = "Something went wrong..."


def handle_error(e):
    return http_json_response(False, e.code, **{"error": SOMETHING_WENT_WRONG_MSG})
