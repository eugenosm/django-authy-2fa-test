from django.shortcuts import render
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework.generics import GenericAPIView, UpdateAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status

from rest_auth.serializers import LoginSerializer as RestAuthLoginSerializer
from rest_auth.views import LoginView as RestAuthLoginView
from rest_auth.app_settings import create_token
from rest_auth.utils import jwt_encode
from authy.api import AuthyApiClient
from rest_framework.exceptions import AuthenticationFailed

from a2fa.models import User
from a2fa.serializers import LoginSerializer, UpdatePhoneSerializeer

authy_api = AuthyApiClient(settings.ACCOUNT_SECURITY_API_KEY)


class RequestConfirmationCodeView(GenericAPIView):
    """
    Request SMS or Authy Notification confirmation code,
    depending on user.authy_method state
    If user is logged in in django then username and password
    could be skipped

    Accept the following POST parameters: username, password
    Return 7 digit SMS code or Authy one touch uuid.
    """
    serializer_class = RestAuthLoginSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if not serializer.is_valid(raise_exception=(request.user is None)):
            user = request.user
        else:
            user = serializer.validated_data['user']
        if not user or user.is_anonymous or not user.is_active:
            return Response(data={'error': 'Invalid user'}, status=status.HTTP_401_UNAUTHORIZED)
        if user.auth_method == User.USE_SMS:
            sms = authy_api.users.request_sms(user.authy_id, {'force': True})
            if sms.ok():
                return Response(data=sms.content, status=status.HTTP_200_OK)
            else:
                return Response(data={'error': 'SMS request failed'}, status=status.HTTP_401_UNAUTHORIZED)
        if user.auth_method == User.USE_Authy:
            details = {
                'user': user.username,
                'application': 'A2FA Test App'
            }
            response = authy_api.one_touch.send_request(
                user.authy_id, "Login requested for A2FA Test App", details=details, seconds_to_expire=120)
            if response.ok():
                return Response(data={'uuid': response.get_uuid()}, status=status.HTTP_200_OK)
            else:
                return Response(data={'errors': response.errors()}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class LoginView(RestAuthLoginView):
    """
    Check the credentials and return the REST Token
    if the credentials are valid and authenticated.
    Calls Django Auth login method to register User ID
    in Django session framework

    Accept the following POST parameters: username, password, confirmation_code
    Return the REST Framework Token Object's key.
    """

    serializer_class = LoginSerializer

    def login(self):
        self.user = self.serializer.validated_data['user']
        confirmation_code = self.serializer.validated_data['confirmation_code']

        verification = authy_api.tokens.verify(self.user.authy_id, token=confirmation_code)
        if verification.ok():
            if getattr(settings, 'REST_USE_JWT', False):
                self.token = jwt_encode(self.user)
            else:
                self.token = create_token(self.token_model, self.user,
                                          self.serializer)
            if getattr(settings, 'REST_SESSION_LOGIN', True):
                self.process_login()

        else:
            raise AuthenticationFailed('SMS/Authy verification failed')


class SetPhoneView(UpdateAPIView):
    """
    Change two factor authentication phone number of user
    previously logged in

    Accept the following POST parameters: country_code, phone
    Return username and new authy_id
    """
    serializer_class = UpdatePhoneSerializeer

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not request.user or request.user.is_anonymous or not request.user.is_active:
            return Response(data={'error': 'Invalid credentials or not logged in'}, status=status.HTTP_401_UNAUTHORIZED)

        old_authy_user = request.user.authy_id
        auty_user = authy_api.users.create(
            email=request.user.email,
            phone=serializer.validated_data['phone'],
            country_code=serializer.validated_data['country_code'])
        if not auty_user.ok():
            return Response(data=auty_user.errors(), status=status.HTTP_304_NOT_MODIFIED)

        if old_authy_user:
            deleted = authy_api.users.delete(old_authy_user)
            if not deleted.ok():
                return Response(data=deleted.errors(), status=status.HTTP_304_NOT_MODIFIED)

        request.user.authy_id = auty_user.id
        request.user.save(update_fields=['authy_id'])
        return Response(data={
            'username': request.user.username,
            'authy_id': request.user.authy_id
        })
