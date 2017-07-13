from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from datetime import datetime
from backend.models import *
from backend.serializers import *

from .settings import api_settings
from .serializers import (
    JSONWebTokenSerializer, RefreshJSONWebTokenSerializer,
    VerifyJSONWebTokenSerializer
)

jwt_response_payload_handler = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER

jwt_payload_handler_client = api_settings.JWT_PAYLOAD_HANDLER_CLIENT
#jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
#jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
#jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
#jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


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


class ObtainUserCLientJSONWebToken(APIView):
    """
    API View that receives a POST with a user's username and password.

    Returns a JSON Web Token that can be used for authenticated requests.
    """
    def post(self, request, *args, **kwargs):
        #print (request.data)
        data = request.data
        serializer = UserClientLoginSerializer(data=data)
        #if serializer.is_valid():
        verified = serializer.validate_post_login(data)
        if isinstance(verified,Response):
            return verified
        #print (serializer.data)
        user = UserClient.objects.filter(username=data["username"],password=data["password"],applicationId=data["applicationId"])[0]
        print(user)
        
        #payload = jwt_payload_handler_client(user)
        #print(payload)
        #token = jwt_encode_handler(payload)

        return Response({"detail":"ok"}, status=status.HTTP_200_OK)

        #    token = serializer.object.get('token')
        #    response_data = jwt_response_payload_handler(token, user, request)
        #    response = Response(response_data)
        #    if api_settings.JWT_AUTH_COOKIE:
        #        expiration = (datetime.utcnow() +
        #                      api_settings.JWT_EXPIRATION_DELTA)
        #        response.set_cookie(api_settings.JWT_AUTH_COOKIE,
        #                            token,
        #                            expires=expiration,
        #                            httponly=True)
        #    return response
#
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


obtain_jwt_token = ObtainJSONWebToken.as_view()
refresh_jwt_token = RefreshJSONWebToken.as_view()
verify_jwt_token = VerifyJSONWebToken.as_view()

#UserCLient autentication
obtain_jwt_token_client = ObtainUserCLientJSONWebToken.as_view()
#refresh_jwt_token_client = RefreshUserCLientJSONWebToken.as_view()
#verify_jwt_token_client = VerifyUserCLientJSONWebToken.as_view()

#UserKronero autentication
#obtain_jwt_token_kronero = ObtainUserKroneroJSONWebToken.as_view()
#refresh_jwt_token_kronero = RefreshUserKroneroJSONWebToken.as_view()
#verify_jwt_token_kronero = VerifyUserKroneroJSONWebToken.as_view()

#Administrator Autentication
#obtain_jwt_token_administrator = ObtainAdministratorJSONWebToken.as_view()
#refresh_jwt_token_administrator = RefreshAdministratorJSONWebToken.as_view()
#verify_jwt_token_administrator = VerifyAdministratorJSONWebToken.as_view()