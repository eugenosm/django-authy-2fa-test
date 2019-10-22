"""term_test URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf.urls import url
from django.urls import include
from a2fa.views import RequestConfirmationCodeView, LoginView, SetPhoneView


urlpatterns = [
    path('admin/', admin.site.urls),
    url(r'^rest-auth/login/$', LoginView.as_view(), name='rest_login'),
    url(r'^rest-auth/', include('rest_auth.urls')),
    url(r'^rest-auth/registration/', include('rest_auth.registration.urls')),
    path('rest-auth/login/request-code/', RequestConfirmationCodeView.as_view(), name='request-2fa-code'),
    path('rest-auth/phone/', SetPhoneView.as_view(), name='update-phone')
]
