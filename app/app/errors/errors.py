from app.utils import http_json_response

SOMETHING_WENT_WRONG_MSG = "Something went wrong..."


def handle_error(e):  # TODO update test
    if hasattr(e, "code"):
        return http_json_response(False, e.code, **{"error": SOMETHING_WENT_WRONG_MSG})
    return http_json_response(False, 500, **{"error": SOMETHING_WENT_WRONG_MSG})
