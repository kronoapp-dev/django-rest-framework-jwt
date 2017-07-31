# -*- coding: utf-8 -*-

import jwt
from django.utils.translation import ugettext as _

from calendar import timegm
from datetime import datetime, timedelta

from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from datetime import datetime
from backend.models import *
from backend.serializers import *

import requests
import json
#from rest_framework_jwt.utils import jwt_payload_handler2

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

######################################################33
#CUSTOM MODIFY

class CustomTokenVerify():

    def _check_payload(self, token):
        try:
            payload = jwt_decode_handler(token)
        except jwt.ExpiredSignature:
            msg = _('Signature has expired.')
            raise serializers.ValidationError(msg)
        except jwt.DecodeError:
            msg = _('Error decoding signature.')
            raise serializers.ValidationError(msg)

        return payload

    def _check_userclient(self, payload):
        if (not "email" in payload) or ( not "applicationId" in payload):
            msg = _('Invalid payload fields for this user.')
            raise serializers.ValidationError(msg)

        email = payload["email"]
        applicationId = payload["applicationId"]

        # Make sure user exists
        try:
            user = UserClient.objects.get(email=email,applicationId=applicationId)
        except UserClient.DoesNotExist:
            msg = _("UserClient doesn't exist.")
            raise serializers.ValidationError(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise serializers.ValidationError(msg)

        return user

    def _check_userkronero(self, payload):
        if (not "email" in payload) or  (not "storeId" in payload):
            msg = _('Invalid payload fields for this user.')
            raise serializers.ValidationError(msg)
        email = payload["email"]
        storeId = payload["storeId"]

        # Make sure user exists
        try:
            user = UserKronero.objects.get(email=email,storeId=storeId)
        except UserKronero.DoesNotExist:
            msg = _("UserKronero doesn't exist.")
            raise serializers.ValidationError(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise serializers.ValidationError(msg)

        return user

    def _check_administrator(self, payload):
        if (not "email" in payload) or (not "role" in payload):
            msg = _('Invalid payload fields for this administrator.')
            raise serializers.ValidationError(msg)
        email = payload["email"]
        role = payload["role"]

        # Make sure user exists
        try:
            user = Administrator.objects.get(email=email,role=role)
        except Administrator.DoesNotExist:
            msg = _("Administrator doesn't exist.")
            raise serializers.ValidationError(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise serializers.ValidationError(msg)

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

    def verify_orig_iat(self,orig_iat):
        if orig_iat:
            # Verify expiration
            refresh_limit = api_settings.JWT_REFRESH_EXPIRATION_DELTA

            if isinstance(refresh_limit, timedelta):
                refresh_limit = (refresh_limit.days * 24 * 3600 +
                                 refresh_limit.seconds)

            expiration_timestamp = orig_iat + int(refresh_limit)
            now_timestamp = timegm(datetime.utcnow().utctimetuple())

            if now_timestamp > expiration_timestamp:
                msg = _('Refresh has expired.')
                raise serializers.ValidationError(msg)
        else:
            msg = _('orig_iat field is required.')
            raise serializers.ValidationError(msg)

    def data_json_convert(self, data):
        new_data = data.decode('utf8').replace("'", '"')
        my_json = json.loads(new_data)
        return my_json
        return json.dumps(my_json, indent=4, sort_keys=True)

    def plugin_login_verified(self, request, url, pluginkey):
        data = request.data
        if not pluginkey in data or not "applicationId" in data:
            return Response({"detail":"%s or application Id not found" % pluginkey}, status=status.HTTP_400_BAD_REQUEST)
        elif not isinstance(data["applicationId"],int):
            return Response({"detail":"applicationId is not integer"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            app = Application.objects.get(pk=data["applicationId"])
        except:
            return Response({"detail":"application not exists "}, status=status.HTTP_400_BAD_REQUEST)

        response = requests.get(url + data[pluginkey])
        json_data = self.data_json_convert(response.content)

        if 'email' in json_data:
            try:
                user = UserClient.objects.get(email=json_data["email"],applicationId=app)
            except:
                return Response({"email":json_data["email"], "detail":"need registration"}, status=status.HTTP_200_OK)
        else:
            return Response({"detail":"expired or invalid %s" % pluginkey}, status=status.HTTP_400_BAD_REQUEST)
        
        payload = jwt_payload_handler_client(user)
        token = jwt_encode_handler(payload)
        return self.token_response(token, user, request)

#CLIENT 

class ObtainUserCLientJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a clients's email, password and applicationId.
    """
    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = UserClientLoginSerializer(data=data)
        user = serializer.validate_post_login(data)
        if isinstance(user,Response):
            return user
        #user = UserClient.objects.get(email=data["email"],password=data["password"],applicationId=data["applicationId"])
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
        data = request.data
        if not "token" in data:
            return Response({"detail":"token not found"}, status=status.HTTP_400_BAD_REQUEST)
        token = data["token"]
        payload = self._check_payload(token=token)
        user = self._check_userclient(payload=payload)
        return self.token_response(token, user, request)
    
class RefreshUserCLientJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a clients's email, password and applicationId.
    """
    def post(self, request, *args, **kwargs):
        data = request.data
        if not "token" in data:
            return Response({"detail":"token not found"}, status=status.HTTP_400_BAD_REQUEST)
        token = data["token"]
        payload = self._check_payload(token=token)
        user = self._check_userclient(payload=payload)
        try:
            orig_iat = payload.get('orig_iat')
            self.verify_orig_iat(orig_iat)
        except Exception:
            msg = _('orig_iat field is required.')
            raise serializers.ValidationError(msg)
        new_payload = jwt_payload_handler_client(user)
        new_payload['orig_iat'] = orig_iat
        token = jwt_encode_handler(new_payload)
        return self.token_response(token, user, request)
    
obtain_jwt_token_client          = ObtainUserCLientJSONWebToken.as_view()
obtain_jwt_token_client_google   = ObtainUserCLientGoogleJSONWebToken.as_view()
obtain_jwt_token_client_facebook = ObtainUserCLientFacebookJSONWebToken.as_view()

refresh_jwt_token_client = RefreshUserCLientJSONWebToken.as_view()
verify_jwt_token_client = VerifyUserCLientJSONWebToken.as_view()


#KRONERO
class ObtainUserKroneroJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a kroneros's email, password and storeId.
    """
    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = UserKroneroLoginSerializer(data=data)
        user = serializer.validate_post_login(data)
        if isinstance(user,Response):
            return user
        #user = UserKronero.objects.get(email=data["email"],password=data["password"])
        payload = jwt_payload_handler_kronero(user)
        token = jwt_encode_handler(payload)
        return self.token_response(token, user, request)

class VerifyUserKroneroJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a kroneros's email, password and storeId.
    """
    def post(self, request, *args, **kwargs):
        data = request.data
        if not "token" in data:
            return Response({"detail":"token not found"}, status=status.HTTP_400_BAD_REQUEST)
        token = data["token"]

        payload = self._check_payload(token=token)
        user = self._check_userkronero(payload=payload)
        return self.token_response(token, user, request)

class RefreshUserKroneroJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a kroneros's email, password and storeId.
    """
    def post(self, request, *args, **kwargs):
        data = request.data
        if not "token" in data:
            return Response({"detail":"token not found"}, status=status.HTTP_400_BAD_REQUEST)
        token = data["token"]

        payload = self._check_payload(token=token)
        user = self._check_userkronero(payload=payload)
        try:
            orig_iat = payload.get('orig_iat')
            self.verify_orig_iat(orig_iat)
        except Exception:
            msg = _('orig_iat field is required.')
            raise serializers.ValidationError(msg)
        new_payload = jwt_payload_handler_kronero(user)
        new_payload['orig_iat'] = orig_iat
        token = jwt_encode_handler(new_payload)
        return self.token_response(token, user, request)


obtain_jwt_token_kronero = ObtainUserKroneroJSONWebToken.as_view()
refresh_jwt_token_kronero = RefreshUserKroneroJSONWebToken.as_view()
verify_jwt_token_kronero = VerifyUserKroneroJSONWebToken.as_view()

#ADMINISTRATORS

class ObtainAdministratorJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a administrators' email, password and role.
    """
    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = AdministratorLoginSerializer(data=data)
        user = serializer.validate_post_login(data)
        if isinstance(user,Response):
            return user
        
        #user = Administrator.objects.get(email=data["email"],password=data["password"])
        payload = jwt_payload_handler_administrator(user)
        token = jwt_encode_handler(payload)
        return self.token_response(token, user, request)

class VerifyAdministratorJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a administrators' email, password and role.
    """
    def post(self, request, *args, **kwargs):
        data = request.data
        if not "token" in data:
            return Response({"detail":"token not found"}, status=status.HTTP_400_BAD_REQUEST)
        token = data["token"]

        payload = self._check_payload(token=token)
        user = self._check_administrator(payload=payload)

        return self.token_response(token, user, request)

class RefreshAdministratorJSONWebToken(APIView,CustomTokenVerify):
    """
    API View that receives a POST with a administrators' email, password and role.
    """
    def post(self, request, *args, **kwargs):
        data = request.data
        if not "token" in data:
            return Response({"detail":"token not found"}, status=status.HTTP_400_BAD_REQUEST)
        token = data["token"]

        payload = self._check_payload(token=token)
        user = self._check_administrator(payload=payload)
        try:
            orig_iat = payload.get('orig_iat')
            self.verify_orig_iat(orig_iat)
        except Exception:
            msg = _('orig_iat field is required.')
            raise serializers.ValidationError(msg)
        new_payload = jwt_payload_handler_administrator(user)
        new_payload['orig_iat'] = orig_iat
        token = jwt_encode_handler(new_payload)
        
        return self.token_response(token, user, request)


#Administrator Autentication
obtain_jwt_token_administrator = ObtainAdministratorJSONWebToken.as_view()
refresh_jwt_token_administrator = RefreshAdministratorJSONWebToken.as_view()
verify_jwt_token_administrator = VerifyAdministratorJSONWebToken.as_view()