# -*- coding: utf-8 -*-
#
#
#   Name:
#       customauthentication.py
#
#   Description
#
#   Author:
#       Andres Navarro
#
#   Version:
#       0.1
#

import jwt

from django.contrib.auth import get_user_model
from django.utils.encoding import smart_text
from rest_framework import exceptions
from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header
)

from rest_framework_jwt.settings import api_settings
from backend.models import *
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


class BaseCustomJSONWebTokenAuthentication(BaseAuthentication):
    """
    Token based authentication using the JSON Web Token standard.
    """

    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication.  Otherwise returns `None`.
        """
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None
        try:
            payload = jwt_decode_handler(jwt_value) 
        except jwt.ExpiredSignature:
            raise exceptions.ValidationError({"error":9})
        except jwt.DecodeError:
            raise exceptions.ValidationError({"error":10})
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed()
        user = self.authenticate_credentials(payload)
        array = [user,payload.get('role')]
        return (array, jwt_value)

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        #print(payload.get('role'))
        try:
            role = payload.get('role')
            user_id = payload.get('user_id')
        except:
            raise exceptions.ValidationError({"error":11})
        try:
            if role == 'Client':
                user = UserClient.objects.get(pk=user_id)
            elif role == 'Kronero':
                user = UserKronero.objects.get(pk=user_id)
            elif (role == 'Global') or (role == 'Store') or (role == 'Chain') or (role == 'Application'):
                user = Administrator.objects.get(pk=user_id)
            else:
                raise exceptions.ValidationError({"error":21})
        except:
            raise exceptions.AuthenticationFailed({"error":20})

        if not user.is_active:
            raise exceptions.ValidationError({"error":8})

        return user


class JSONCustomWebTokenAuthentication(BaseCustomJSONWebTokenAuthentication):
    """
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:

        Authorization: JWT eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """
    www_authenticate_realm = 'api'

    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth:
            if api_settings.JWT_AUTH_COOKIE:
                return request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)
            return None

        if smart_text(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            raise exceptions.ValidationError({"error":12})
        elif len(auth) > 2:
            raise exceptions.ValidationError({"error":13})

        return auth[1]

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return '{0} realm="{1}"'.format(api_settings.JWT_AUTH_HEADER_PREFIX, self.www_authenticate_realm)