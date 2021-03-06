# -*- coding: utf-8 -*-
#
#
#   Name:
#       utils.py
#
#   Description
#
#   Modify By:
#       Andres Navarro
#
#   Version:
#       0.1
#

import jwt
import uuid
import warnings
from django.contrib.auth import get_user_model
from calendar import timegm
from datetime import datetime
from rest_framework_jwt.compat import get_username
from rest_framework_jwt.compat import get_username_field
from rest_framework_jwt.settings import api_settings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from rest_api.global_setting import PUBLIC_KEY_PEM, PRIVATE_KEY_PEM
from rest_api.settings import BASE_DIR


#from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
#jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))




def jwt_get_secret_key(payload=None):
    """
    For enhanced security you may want to use a secret key based on user.

    This way you have an option to logout only this user if:
        - token is compromised
        - password is changed
        - etc.
    """
    if api_settings.JWT_GET_USER_SECRET_KEY:
        User = get_user_model()  # noqa: N806
        user = User.objects.get(pk=payload.get('user_id'))
        key = str(api_settings.JWT_GET_USER_SECRET_KEY(user))
        return key
    return api_settings.JWT_SECRET_KEY


def jwt_payload_handler(user):
    username_field = get_username_field()
    username = get_username(user)

    warnings.warn(
        'The following fields will be removed in the future: '
        '`email` and `user_id`. ',
        DeprecationWarning
    )

    payload = {
        'user_id': user.pk,
        'username': username,
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA
    }
    if hasattr(user, 'email'):
        payload['email'] = user.email
    if isinstance(user.pk, uuid.UUID):
        payload['user_id'] = str(user.pk)

    payload[username_field] = username

    # Include original issued at time for a brand new token,
    # to allow token refresh
    if api_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = timegm(
            datetime.utcnow().utctimetuple()
        )

    if api_settings.JWT_AUDIENCE is not None:
        payload['aud'] = api_settings.JWT_AUDIENCE

    if api_settings.JWT_ISSUER is not None:
        payload['iss'] = api_settings.JWT_ISSUER

    return payload


def jwt_get_user_id_from_payload_handler(payload):
    """
    Override this function if user_id is formatted differently in payload
    """
    warnings.warn(
        'The following will be removed in the future. '
        'Use `JWT_PAYLOAD_GET_USERNAME_HANDLER` instead.',
        DeprecationWarning
    )

    return payload.get('user_id')


def jwt_get_username_from_payload_handler(payload):
    """
    Override this function if username is formatted differently in payload
    """
    return payload.get('username')


def jwt_encode_handler(payload):
    return jwt.encode(
        payload,
        PRIVATE_KEY_PEM,
        api_settings.JWT_ALGORITHM
    ).decode('utf-8')


def jwt_decode_handler(token):
    options = {
        'verify_exp': api_settings.JWT_VERIFY_EXPIRATION,
    }
    return jwt.decode(
        token,
        PUBLIC_KEY_PEM,
        api_settings.JWT_VERIFY,
        options=options,
        leeway=api_settings.JWT_LEEWAY,
        audience=api_settings.JWT_AUDIENCE,
        issuer=api_settings.JWT_ISSUER,
        algorithms=[api_settings.JWT_ALGORITHM]
    )

def jwt_decode_handler_refresh(token):
    options = {
        'verify_exp': False,
    }
    return jwt.decode(
        token,
        PUBLIC_KEY_PEM,
        options=options,
        leeway=api_settings.JWT_LEEWAY,
        audience=api_settings.JWT_AUDIENCE,
        issuer=api_settings.JWT_ISSUER,
        algorithms=[api_settings.JWT_ALGORITHM]
    )

def jwt_response_payload_handler(token, user=None, request=None):
    """
    Returns the response data for both the login and refresh views.
    Override to return a custom response such as including the
    serialized representation of the User.

    Example:

    def jwt_response_payload_handler(token, user=None, request=None):
        return {
            'token': token,
            'user': UserSerializer(user, context={'request': request}).data
        }

    """
    return {
        'token': token
    }

######################################################33

#CLIENT

def jwt_payload_handler_client(user):
    #username_field = get_username_field()
    #username = get_username(user)
    warnings.warn(
        'The following fields will be removed in the future: '
        '`email` and `user_id`. ',
        DeprecationWarning
    )
    payload = {
        'user_id': user.pk,
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA,
        'email':user.email,
        'applicationId': user.applicationId.id,
        'role': 'Client'
    }

    # Include original issued at time for a brand new token,
    # to allow token refresh
    if api_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = timegm(
            datetime.utcnow().utctimetuple()
        )

    if api_settings.JWT_AUDIENCE is not None:
        payload['aud'] = api_settings.JWT_AUDIENCE

    if api_settings.JWT_ISSUER is not None:
        payload['iss'] = api_settings.JWT_ISSUER

    return payload

#KRONERO

def jwt_payload_handler_kronero(user):
    #username_field = get_username_field()
    #username = get_username(user)
    warnings.warn(
        'The following fields will be removed in the future: '
        '`email` and `user_id`. ',
        DeprecationWarning
    )
    payload = {
        'user_id': user.pk,
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA,
        'email':user.email,
        'storeId': user.storeId.id,
        'chainId': user.storeId.chainId.id,
        'role': 'Kronero'
    }

    # Include original issued at time for a brand new token,
    # to allow token refresh
    if api_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = timegm(
            datetime.utcnow().utctimetuple()
        )

    if api_settings.JWT_AUDIENCE is not None:
        payload['aud'] = api_settings.JWT_AUDIENCE

    if api_settings.JWT_ISSUER is not None:
        payload['iss'] = api_settings.JWT_ISSUER

    return payload

#ADMINISTRATORS

def jwt_payload_handler_administrator(user):
    #username_field = get_username_field()
    #username = get_username(user)
    warnings.warn(
        'The following fields will be removed in the future: '
        '`email` and `user_id`. ',
        DeprecationWarning
    )
    payload = {
        'user_id': user.pk,
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA,
        'email':user.email,
        'role': user.role
    }

    if user.role == 'Store':
        payload['storeId'] = user.storeId.id
        payload['chainId'] = user.storeId.chainId.id
    elif user.role == 'Chain':
        payload['chainId'] = user.chainId.id
    elif user.role == 'Application':
        payload['applicationId'] = user.applicationId.id

    # Include original issued at time for a brand new token,
    # to allow token refresh
    if api_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = timegm(
            datetime.utcnow().utctimetuple()
        )

    if api_settings.JWT_AUDIENCE is not None:
        payload['aud'] = api_settings.JWT_AUDIENCE

    if api_settings.JWT_ISSUER is not None:
        payload['iss'] = api_settings.JWT_ISSUER

    return payload