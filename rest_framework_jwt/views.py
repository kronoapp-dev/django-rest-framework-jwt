# -*- coding: utf-8 -*-
#
#
#   Name:
#       views.py
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
import requests
import json
from django.utils.translation import ugettext as _
from calendar import timegm
from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from backend.models import *
from backend.serializers import *
from rest_framework import exceptions
from .settings import api_settings
from .serializers import (
    JSONWebTokenSerializer, RefreshJSONWebTokenSerializer,
    VerifyJSONWebTokenSerializer
)

jwt_response_payload_handler = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER
jwt_payload_handler_client = api_settings.JWT_CLIENT_HANDLER
jwt_payload_handler_kronero = api_settings.JWT_KRONERO_HANDLER
jwt_payload_handler_administrator = api_settings.JWT_ADMINISTRATOR_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER

url_google = 'https://www.googleapis.com/oauth2/v2/tokeninfo?id_token='
url_facebook = 'https://graph.facebook.com/me?fields=id,email&access_token='

class JSONWebTokenAPIView(APIView):
    """
    Base API View that various JWT interactions inherit from.
    """
    permission_classes = ()
    authentication_classes = ()

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        return {
            'request': self.request,
            'view': self,
        }

    def get_serializer_class(self):
        """
        Return the class to use for the serializer.
        Defaults to using `self.serializer_class`.
        You may want to override this if you need to provide different
        serializations depending on the incoming request.
        (Eg. admins get full serialization, others get basic serialization)
        """
        assert self.serializer_class is not None, (
            "'%s' should either include a `serializer_class` attribute, "
            "or override the `get_serializer_class()` method."
            % self.__class__.__name__)
        return self.serializer_class

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = self.get_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.object.get('user') or request.user
            token = serializer.object.get('token')
            response_data = jwt_response_payload_handler(token, user, request)
            response = Response(response_data)
            if api_settings.JWT_AUTH_COOKIE:
                expiration = (datetime.utcnow() +
                              api_settings.JWT_EXPIRATION_DELTA)
                response.set_cookie(api_settings.JWT_AUTH_COOKIE,
                                    token,
                                    expires=expiration,
                                    httponly=True)
            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ObtainJSONWebToken(JSONWebTokenAPIView):
    """
    API View that receives a POST with a user's username and password.

    Returns a JSON Web Token that can be used for authenticated requests.
    """
    serializer_class = JSONWebTokenSerializer

class VerifyJSONWebToken(JSONWebTokenAPIView):
    """
    API View that checks the veracity of a token, returning the token if it
    is valid.
    """
    serializer_class = VerifyJSONWebTokenSerializer

class RefreshJSONWebToken(JSONWebTokenAPIView):
    """
    API View that returns a refreshed token (with new expiration) based on
    existing token

    If 'orig_iat' field (original issued-at-time) is found, will first check
    if it's within expiration window, then copy it to the new token
    """
    serializer_class = RefreshJSONWebTokenSerializer

obtain_jwt_token = ObtainJSONWebToken.as_view()
refresh_jwt_token = RefreshJSONWebToken.as_view()
verify_jwt_token = VerifyJSONWebToken.as_view()

######################################################
#CUSTOM MODIFY

class CustomTokenVerify():

    def _check_payload(self, token):
        try:
            payload = jwt_decode_handler(token)
        except jwt.ExpiredSignature:
            raise exceptions.ValidationError({"error":9})
        except jwt.DecodeError:
            raise exceptions.ValidationError({"error":10})
        return payload

    def _check_userclient(self, payload):
        if (not "email" in payload) or ( not "applicationId" in payload):
            raise exceptions.ValidationError({"error":11})

        email = payload["email"]
        applicationId = payload["applicationId"]
        try:
            user = UserClient.objects.get(email=email,applicationId=applicationId)
        except UserClient.DoesNotExist:
            raise exceptions.NotAuthenticated({"error":6})
        if not user.is_active:
            raise exceptions.PermissionDenied({"error":8})
        return user

    def _check_userkronero(self, payload):
        if (not "email" in payload) or  (not "storeId" in payload):
            raise exceptions.ValidationError({"error":11})
        email = payload["email"]
        storeId = payload["storeId"]
        try:
            user = UserKronero.objects.get(email=email,storeId=storeId)
        except UserKronero.DoesNotExist:
            raise exceptions.NotAuthenticated({"error":6})
        if not user.is_active:
            raise exceptions.PermissionDenied({"error":8})
        return user

    def _check_administrator(self, payload):
        if (not "email" in payload) or (not "role" in payload):
            raise exceptions.ValidationError({"error":11})
        email = payload["email"]
        role = payload["role"]
        try:
            user = Administrator.objects.get(email=email,role=role)
        except Administrator.DoesNotExist:
            raise exceptions.NotAuthenticated({"error":6})

        if not user.is_active:
            raise exceptions.PermissionDenied({"error":8})
        return user

    def token_response(self, token, user, request):
        response_data = jwt_response_payload_handler(token, user, request)
        response = Response(response_data)
        if api_settings.JWT_AUTH_COOKIE:
            expiration = (datetime.utcnow() +
                          api_settings.JWT_EXPIRATION_DELTA)
            response.set_cookie(api_settings.JWT_AUTH_COOKIE,
                                token,
                                expires=expiration,
                                httponly=True)
        return response

    def verify_orig_iat(self, payload):
        try:
            orig_iat = payload.get('orig_iat')
            # Verify expiration
            refresh_limit = api_settings.JWT_REFRESH_EXPIRATION_DELTA

            if isinstance(refresh_limit, timedelta):
                refresh_limit = (refresh_limit.days * 24 * 3600 +
                                 refresh_limit.seconds)

            expiration_timestamp = orig_iat + int(refresh_limit)
            now_timestamp = timegm(datetime.utcnow().utctimetuple())

            if now_timestamp > expiration_timestamp:
                raise exceptions.ValidationError({"error":14})
        except Exception:
            raise exceptions.ValidationError({"error":15})

        return orig_iat

    def data_json_convert(self, data):
        new_data = data.decode('utf8').replace("'", '"')
        my_json = json.loads(new_data)
        return my_json
        #return json.dumps(my_json, indent=4, sort_keys=True)

    def plugin_login_verified(self, request, url, pluginkey):
        data = request.data
        if not pluginkey in data or not "applicationId" in data:
            raise exceptions.ParseError({"error":17})
        elif not isinstance(data["applicationId"],int):
            raise exceptions.ParseError({"error":5})
        try:
            app = Application.objects.get(pk=data["applicationId"])
        except:
            raise exceptions.NotFound({"error":16})
        response = requests.get(url + data[pluginkey])
        json_data = self.data_json_convert(response.content)

        if 'email' in json_data:
            try:
                user = UserClient.objects.get(email=json_data["email"],applicationId=app)
            except:
                return Response({"need_register":json_data["email"]}, status=status.HTTP_200_OK)
        else:
            raise exceptions.ParseError({"error":18})
        payload = jwt_payload_handler_client(user)
        token = jwt_encode_handler(payload)
        return self.token_response(token, user, request)

    def get_token_from_request(self, request):
        if not "token" in request.data:
            raise exceptions.NotFound({"error":19})
        return request.data["token"]

######################################################
#CLIENT 

class ObtainUserCLientJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a clients's email, password and applicationId.
    """
    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = UserClientLoginSerializer(data=data)
        user = serializer.validate_post_login(data, UserClient)
        if isinstance(user,Response):
            return user
        payload = jwt_payload_handler_client(user)
        token = jwt_encode_handler(payload)
        return self.token_response(token, user, request)
  
class ObtainUserCLientGoogleJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a clients google auth.
    """
    def post(self, request, *args, **kwargs):
        return self.plugin_login_verified(request,url_google,"id_token")

class ObtainUserCLientFacebookJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a clients facebook auth.
    """
    def post(self, request, *args, **kwargs):
        return self.plugin_login_verified(request,url_facebook, "access_token")

class VerifyUserCLientJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a clients's email, password and applicationId.
    """
    def post(self, request, *args, **kwargs):
        token   = self.get_token_from_request(request)
        payload = self._check_payload(token=token)
        user    = self._check_userclient(payload=payload)
        return self.token_response(token, user, request)
    
class RefreshUserCLientJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a clients's email, password and applicationId.
    """
    def post(self, request, *args, **kwargs):
        token                   = self.get_token_from_request(request)
        payload                 = self._check_payload(token=token)
        user                    = self._check_userclient(payload=payload)
        orig_iat                = self.verify_orig_iat(payload)
        new_payload             = jwt_payload_handler_client(user)
        new_payload['orig_iat'] = orig_iat
        token                   = jwt_encode_handler(new_payload)
        return self.token_response(token, user, request)
    
obtain_jwt_token_client             = ObtainUserCLientJSONWebToken.as_view()
obtain_jwt_token_client_google      = ObtainUserCLientGoogleJSONWebToken.as_view()
obtain_jwt_token_client_facebook    = ObtainUserCLientFacebookJSONWebToken.as_view()
refresh_jwt_token_client            = RefreshUserCLientJSONWebToken.as_view()
verify_jwt_token_client             = VerifyUserCLientJSONWebToken.as_view()


#KRONERO
class ObtainUserKroneroJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a kroneros's email, password and storeId.
    """
    def post(self, request, *args, **kwargs):
        data        = request.data
        serializer  = UserKroneroLoginSerializer(data=data)
        user        = serializer.validate_post_login(data, UserKronero)
        if isinstance(user,Response):
            return user
        payload     = jwt_payload_handler_kronero(user)
        token       = jwt_encode_handler(payload)
        return self.token_response(token, user, request)

class VerifyUserKroneroJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a kroneros's email, password and storeId.
    """
    def post(self, request, *args, **kwargs):
        token   = self.get_token_from_request(request)
        payload = self._check_payload(token=token)
        user    = self._check_userkronero(payload=payload)
        return self.token_response(token, user, request)

class RefreshUserKroneroJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a kroneros's email, password and storeId.
    """
    def post(self, request, *args, **kwargs):
        token                   = self.get_token_from_request(request)
        payload                 = self._check_payload(token=token)
        user                    = self._check_userkronero(payload=payload)
        orig_iat                = self.verify_orig_iat(payload)
        new_payload             = jwt_payload_handler_kronero(user)
        new_payload['orig_iat'] = orig_iat
        token                   = jwt_encode_handler(new_payload)
        return self.token_response(token, user, request)


obtain_jwt_token_kronero    = ObtainUserKroneroJSONWebToken.as_view()
refresh_jwt_token_kronero   = RefreshUserKroneroJSONWebToken.as_view()
verify_jwt_token_kronero    = VerifyUserKroneroJSONWebToken.as_view()

#ADMINISTRATORS

class ObtainAdministratorJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a administrators' email, password and role.
    """
    def post(self, request, *args, **kwargs):
        data        = request.data
        serializer  = AdministratorLoginSerializer(data=data)
        user        = serializer.validate_post_login(data, Administrator)
        if isinstance(user,Response):
            return user
        payload     = jwt_payload_handler_administrator(user)
        token       = jwt_encode_handler(payload)
        return self.token_response(token, user, request)

class VerifyAdministratorJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a administrators' email, password and role.
    """
    def post(self, request, *args, **kwargs):
        token   = self.get_token_from_request(request)
        payload = self._check_payload(token=token)
        user    = self._check_administrator(payload=payload)
        return self.token_response(token, user, request)

class RefreshAdministratorJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a administrators' email, password and role.
    """
    def post(self, request, *args, **kwargs):
        token                   = self.get_token_from_request(request)
        payload                 = self._check_payload(token=token)
        user                    = self._check_administrator(payload=payload)
        orig_iat                = self.verify_orig_iat(payload)
        new_payload             = jwt_payload_handler_administrator(user)
        new_payload['orig_iat'] = orig_iat
        token                   = jwt_encode_handler(new_payload)
        return self.token_response(token, user, request)


#Administrator Autentication
obtain_jwt_token_administrator  = ObtainAdministratorJSONWebToken.as_view()
refresh_jwt_token_administrator = RefreshAdministratorJSONWebToken.as_view()
verify_jwt_token_administrator  = VerifyAdministratorJSONWebToken.as_view()