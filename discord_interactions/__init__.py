__version__ = '0.4.1'

from functools import wraps
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from flask import request, jsonify

class InteractionType:
    PING = 1
    APPLICATION_COMMAND = 2
    MESSAGE_COMPONENT = 3
    APPLICATION_COMMAND_AUTOCOMPLETE = 4
    MODAL_SUBMIT = 5

class InteractionResponseType:
    PONG = 1
    CHANNEL_MESSAGE_WITH_SOURCE = 4
    DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE = 5
    DEFERRED_UPDATE_MESSAGE = 6
    UPDATE_MESSAGE = 7
    APPLICATION_COMMAND_AUTOCOMPLETE_RESULT = 8
    MODAL = 9

class InteractionResponseFlags:
    EPHEMERAL = 1 << 6

class Interaction:
    def __init__(self, raw_body: bytes, signature: str, timestamp: str, client_public_key: str):
        self.raw_body = raw_body
        self.signature = signature
        self.timestamp = timestamp
        self.client_public_key = client_public_key

    def verify(self) -> bool:
        message = self.timestamp.encode() + self.raw_body
        try:
            vk = VerifyKey(bytes.fromhex(self.client_public_key))
            vk.verify(message, bytes.fromhex(self.signature))
            return True
        except Exception as ex:
            print(ex)
            return False

    def handle(self, func):
        def wrapper(*args, **kwargs):
            if not self.verify():
                return 'Bad request signature', 401

            # Automatically respond to pings
            if request.json and request.json.get('type') == InteractionType.PING:
                return jsonify({'type': InteractionResponseType.PONG})

            return func(*args, **kwargs)
        return wrapper

class InteractionVerifier:
    def __init__(self, client_public_key: str):
        self.client_public_key = client_public_key

    def __call__(self, func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            raw_body = request.data
            signature = request.headers.get('X-Signature-Ed25519')
            timestamp = request.headers.get('X-Signature-Timestamp')

            interaction = Interaction(raw_body, signature, timestamp, self.client_public_key)

            return interaction.handle(func)(*args, **kwargs)
        return decorated_function

# Usage example:
# @InteractionVerifier(client_public_key="your_public_key_here")
# def some_function():
#     # Your function implementation here.
