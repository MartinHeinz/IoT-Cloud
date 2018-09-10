import json
import logging

log = logging.getLogger()
log.setLevel(logging.DEBUG)


def index(event, context):
    log.debug("Received event %s", json.dumps(event))

    return {
        'statusCode': 200,
        'body': json.dumps({"msg": "hello from Lambda, this is home path (/)"})
    }
