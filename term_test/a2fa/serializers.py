import re

from django.conf import settings

from rest_auth.registration.serializers import RegisterSerializer
from rest_auth.serializers import LoginSerializer as RestAuthLoginSerializer
from rest_framework import serializers
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from authy.api import AuthyApiClient

from a2fa.models import User

authy_api = AuthyApiClient(settings.ACCOUNT_SECURITY_API_KEY)


class PhoneMixin(object):

    def validate_country_code(self, country_code):
        match = re.fullmatch(r'^\d+(-\d+)?', country_code)
        if match is None:
            raise serializers.ValidationError('Country code is invalid.')
        return match.group(0)

    def validate_phone(self, phone):
        match = re.fullmatch(r'^\d+(-\d+)*', phone)
        if match is None:
            raise serializers.ValidationError('Phone number is invalid.')
        return match.group(0)


class RegisterSerializer(RegisterSerializer, PhoneMixin):

    phone = serializers.CharField(min_length=4, max_length=10, required=True)
    country_code = serializers.CharField(max_length=8, required=True)

    def get_cleaned_data(self):
        return {
            'username': self.validated_data.get('username', ''),
            'password1': self.validated_data.get('password1', ''),
            'email': self.validated_data.get('email', ''),
            'phone': self.validated_data.get('phone', ''),
            'country_code': self.validated_data.get('country_code', ''),
        }

    def save(self, request):
        self.cleaned_data = self.get_cleaned_data()
        auty_user = authy_api.users.create(
            email=self.cleaned_data['email'],
            phone=self.cleaned_data['phone'],
            country_code=self.cleaned_data['country_code'])
        if not auty_user.ok():
            raise serializers.ValidationError(detail=auty_user.errors())

        adapter = get_adapter()
        user = adapter.new_user(request)
        user.authy_id = auty_user.id
        adapter.save_user(request, user, self)
        self.custom_signup(request, user)
        setup_user_email(request, user, [])
        return user


class UserDetailsSerializer(serializers.ModelSerializer):
    """
    Impements /rest_auth/user/ endpoint
    on GET/PUT: returns: 'email', 'username', 'auth_method', 'authy_id'
    on PUT allow to change auth_method. values 'SMS' (sms confirm) and
    'ATH'(authy one touch confirm)
    """

    class Meta:
        model = User
        fields = ['email', 'username', 'auth_method', 'authy_id']
        read_only_fields = ('username', 'authy_id', 'email')


class A2FAuthMethodSerializer(serializers.Serializer):

    auth_method = serializers.CharField(max_length=3, default=User.USE_SMS)

    def validate_auth_method(self, auth_method):
        if auth_method is None or auth_method == '':
            auth_method = User.USE_SMS
        for (key,val) in User.AUTH_METHOD_CHOICES:
            if key == auth_method or val == auth_method:
                return key
        raise serializers.ValidationError('Invalid authentication method')


class LoginSerializer(RestAuthLoginSerializer):

    confirmation_code = serializers.CharField(max_length=64, required=False)


class UpdatePhoneSerializeer(serializers.Serializer, PhoneMixin):

    phone = serializers.CharField(min_length=4, max_length=10, required=True)
    country_code = serializers.CharField(max_length=8, required=True)
