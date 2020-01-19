from flask import Flask, jsonify, request
import os
import hmac
import hashlib
import datetime
import logger

app = Flask(__name__)
app.log_level = logger.DEBUG


def __generate_hmac_signature(timestamp, body):
    # Slack App - Basic Information - App Credentials に記載されている
    # Signing Secret
    secretkey = os.environ['SLACK_API_SIGNING_SECRET']
    secretkey_bytes = bytes(secretkey, 'UTF-8')

    message = "v0:{}:{}".format(timestamp, body)
    message_bytes = bytes(message, 'UTF-8')
    return hmac.new(secretkey_bytes, message_bytes, hashlib.sha256).hexdigest()


def is_valid_request(req):
    app.logger.debug(req.headers)
    if "X-Slack-Request-Timestamp" not in req.headers \
            or "X-Slack-Signature" not in req.headers:
        return False

    request_timestamp = int(req.headers["X-Slack-Request-Timestamp"])
    now_timestamp = int(datetime.datetime.now().timestamp())

    if abs(request_timestamp - now_timestamp) > (60 * 5):
        return False

    expected_hash = __generate_hmac_signature(
        req.headers["X-Slack-Request-Timestamp"],
        req.get_data(as_text=True)
    )

    expected = "v0={}".format(expected_hash)
    actual = req.headers["X-Slack-Signature"]

    app.logger.debug("Expected HMAC signature: {}".format(expected))
    app.logger.debug("Actual HMAC signature: {}".format(actual))

    return hmac.compare_digest(expected_hash, actual)


@app.route('/string_random', methods=['POST'])
def string_random():
    if not is_valid_request(request):
        return jsonify(message='invalid request'), 400

    return jsonify(
        text='stub',
        response_type='in_channel',
    )
