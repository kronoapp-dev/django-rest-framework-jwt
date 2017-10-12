import datetime

from django.conf import settings
from rest_framework.settings import APISettings


USER_SETTINGS = getattr(settings, 'JWT_AUTH', None)

DEFAULTS = {
    'JWT_ENCODE_HANDLER':
    'rest_framework_jwt.utils.jwt_encode_handler',

    'JWT_DECODE_HANDLER':
    'rest_framework_jwt.utils.jwt_decode_handler',

    'JWT_DECODE_HANDLER_REFRESH':
    'rest_framework_jwt.utils.jwt_decode_handler_refresh',

    'JWT_PAYLOAD_HANDLER':
    'rest_framework_jwt.utils.jwt_payload_handler',

    'JWT_CLIENT_HANDLER': #CLIENT
    'rest_framework_jwt.utils.jwt_payload_handler_client',

    'JWT_KRONERO_HANDLER': #AKRONEROS
    'rest_framework_jwt.utils.jwt_payload_handler_kronero',

    'JWT_ADMINISTRATOR_HANDLER': #ADMINISTRATORS
    'rest_framework_jwt.utils.jwt_payload_handler_administrator',

    'JWT_PAYLOAD_GET_USER_ID_HANDLER':
    'rest_framework_jwt.utils.jwt_get_user_id_from_payload_handler',

    'JWT_PRIVATE_KEY':None,

    'JWT_PUBLIC_KEY':None,

    'JWT_PAYLOAD_GET_USERNAME_HANDLER':
    'rest_framework_jwt.utils.jwt_get_username_from_payload_handler',

    'JWT_RESPONSE_PAYLOAD_HANDLER':
    'rest_framework_jwt.utils.jwt_response_payload_handler',

    'JWT_SECRET_KEY': settings.SECRET_KEY,
    'JWT_GET_USER_SECRET_KEY': None,
    'JWT_ALGORITHM': 'RS256',
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_EXPIRATION_DELTA': datetime.timedelta(days=1),
    'JWT_AUDIENCE': None,
    'JWT_ISSUER': None,

    'JWT_ALLOW_REFRESH': True, #SET TRUE
    'JWT_REFRESH_EXPIRATION_DELTA': datetime.timedelta(days=365),

    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    'JWT_AUTH_COOKIE': None,
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'JWT_ENCODE_HANDLER', 
    'JWT_DECODE_HANDLER',
    'JWT_DECODE_HANDLER_REFRESH',
    'JWT_PAYLOAD_HANDLER',
    'JWT_CLIENT_HANDLER', #CLIENT
    'JWT_KRONERO_HANDLER', #KRONEROS 
    'JWT_ADMINISTRATOR_HANDLER',#ADMINISTRATORS
    'JWT_PAYLOAD_GET_USER_ID_HANDLER',
    'JWT_PAYLOAD_GET_USERNAME_HANDLER',
    'JWT_RESPONSE_PAYLOAD_HANDLER',
    'JWT_GET_USER_SECRET_KEY',
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
