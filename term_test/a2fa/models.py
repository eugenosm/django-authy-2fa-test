from django.db import models

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.validators import UnicodeUsernameValidator
from .managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    """
    A class implementing a User model with 2FA using Authy API.

    Username and password are required. Other fields are optional.
    """
    USE_SMS = 'SMS'
    USE_Authy = 'ATH'
    AUTH_METHOD_CHOICES = [
        (USE_SMS, 'SMS'),
        (USE_Authy, 'Authy')
    ]

    username_validator = UnicodeUsernameValidator()

    username = models.CharField(
        'username',
        max_length=64,
        unique=True,
        help_text='Required. 64 characters or fewer. Letters, digits and @/./+/-/_ only.',
        validators=[username_validator],
        error_messages={
            'unique': "A user with that username already exists.",
        },
    )
    email = models.EmailField('email address', blank=True)
    authy_id = models.CharField(max_length=12, null=True, blank=True)
    auth_method = models.CharField(max_length=3, default=USE_SMS, choices=AUTH_METHOD_CHOICES)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = []
