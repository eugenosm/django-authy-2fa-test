from unittest.mock import patch, Mock

from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework.serializers import ErrorDetail
from rest_framework.test import APITestCase
from authy.api.resources import (
    User as AuthyUser,
    Token as AuthyToken,
    Sms
)

""" 
endpoints:
/rest-auth/user/
^rest-auth/registration/
^rest-auth/login/$ [name='rest_login']
rest-auth/login/request-code/ [name='request-2fa-code']
rest-auth/phone/ [name='update-phone']
"""


class UpdateUserTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.url = reverse('rest_user_details')
        self.user = User.objects.create_user(username='test', password='123', authy_id=12345, email="test@test.com")
        self.user.set_password('123')
        self.user.save()

    def test_user_state(self):
        self.client.login(username='test', password='123')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {
            'email': 'test@test.com',
            'username': 'test',
            'auth_method': 'SMS',
            'authy_id': '12345'})

    def test_nouser_state(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_update_method(self):
        self.client.login(username='test', password='123')
        payload = {'auth_method': 'ATH'}
        response = self.client.put(self.url, data=payload)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {
            'email': 'test@test.com',
            'username': 'test',
            'auth_method': 'ATH',
            'authy_id': '12345'})


class RegistrationTest(APITestCase):
    def setUp(self):
        self.url = reverse('rest_register')
        self.payload = {
            'username': 'test1',
            'password1': 'A1b2c3def', 'password2': 'A1b2c3def',
            'email': 'test@test.com',
            'phone': '1111234567',
            'country_code': '7'
        }
        self.authy_ok_content = {
            "message": "User created successfully.",
            "user": {
                "id": 123,
            },
            "success": True,
        }

    def _mocked_authy_register_req(self, payload, authy_data=None, authy_code=200):
        mock_resp = Mock()
        mock_resp.status_code = authy_code
        data = authy_data if authy_data is not None else self.authy_ok_content
        mock_resp.json = Mock(data)

        with patch('a2fa.serializers.authy_api.users.create') as auc:
            auc.return_value = AuthyUser(None, mock_resp)
            return self.client.post(self.url, data=payload)

    def test_register_success(self):
        response = self._mocked_authy_register_req(self.payload)
        self.assertEqual(response.status_code, 201)
        self.assertTrue('key' in response.data)
        self.assertEqual(len(response.data['key']), 40)

    def test_register_failed_authy(self):
        response = self._mocked_authy_register_req(self.payload, authy_code=400, authy_data={
            "message": "User was not valid",
            "success": False,
            "errors": {
                "email": "is invalid",
                "message": "User was not valid"
            },
            "email": "is invalid",
            "error_code": "60027"
        })
        self.assertEqual(response.status_code, 400)
        self.assertTrue('error' in response.data)

    def test_register_failed_rest_auth(self):

        data = self.payload.copy()
        data['password1'] = '1qa2ws3ed4rf'
        response = self._mocked_authy_register_req(data)

        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(response.data, {'non_field_errors': [
            ErrorDetail(string="The two password fields didn't match.", code='invalid')]})

        data['password1'] = '123'
        data['password2'] = '123'
        response = self._mocked_authy_register_req(data)

        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(response.data, {'password1': [
            ErrorDetail(string='This password is too short. It must contain at least 8 characters.',
                        code='password_too_short'),
            ErrorDetail(string='This password is too common.', code='password_too_common'),
            ErrorDetail(string='This password is entirely numeric.', code='password_entirely_numeric')]})

        User = get_user_model()
        user = User.objects.create_user(username='test1', password='123', authy_id=12345, email="test@test.com")
        user.set_password('123')
        user.save()
        response = self._mocked_authy_register_req(self.payload)
        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(response.data, {
            'username': [ErrorDetail(string='A user with that username already exists.', code='invalid')],
            'email': [ErrorDetail(string='A user is already registered with this e-mail address.', code='invalid')]
        })


class LoginTest(APITestCase):
    def setUp(self):
        self.url = reverse('rest_login')
        User = get_user_model()
        user = User.objects.create_user(username='test1', password='123', authy_id=12345, email="test@test.com")
        user.set_password('123')
        user.save()
        self.payload = {
            'username': 'test1',
            'password': '123',
            'confirmation_code': "1234567"
        }
        # As it turned out, the python authy.api is not very neatly
        # implemented in the given part:
        #
        # def ok(self):
        #     if super(Token, self).ok():
        #         return '"token":"is valid"' in str(self.response.content)
        # return False
        #
        # So, i've got to declare following and relative constants in that way:
        self.authy_ok_content = '''
            {
              "message": "Token is valid.",
              "token":"is valid",
              "success": "true",
              "device": {
                "city": "San Francisco",
                "country": "United States",
                "ip": "97.20.126.156",
                "region": "California",
                "registration_city": "San Francisco",
                "registration_country": "United States",
                "registration_device_id": 456456,
                "registration_ip": "97.34.234.11",
                "registration_method": "push",
                "registration_region": "California",
                "os_type": "android",
                "last_account_recovery_at": null,
                "id": 83372911,
                "registration_date": 1490996931
              }
            }
            '''

    def _mocked_authy_login_req(self, payload, authy_data=None, authy_code=200):
        mock_resp = Mock()
        mock_resp.status_code = authy_code
        data = authy_data if authy_data is not None else self.authy_ok_content
        mock_resp.content = data

        with patch('a2fa.views.authy_api.tokens.verify') as atv:
            atv.return_value = AuthyToken(None, mock_resp)
            return self.client.post(self.url, data=payload)

    def test_login_success(self):
        response = self._mocked_authy_login_req(self.payload)
        self.assertEqual(response.status_code, 200)
        self.assertTrue('key' in response.data)
        self.assertEqual(len(response.data['key']), 40)

    def test_login_unsuccess(self):
        data = self.payload.copy()
        data['password'] = '321'
        response = self._mocked_authy_login_req(data)
        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(response.data, {'non_field_errors': [
            ErrorDetail(string='Unable to log in with provided credentials.', code='invalid')]})

    def test_confirmation_unsuccess(self):
        invalid_content = '''
            {
              "message": "Token is invalid",
              "token": "is invalid",
              "success": false,
              "errors": {
                "message": "Token is invalid"
              },
              "error_code": "60020"
            }            
        '''

        response = self._mocked_authy_login_req(self.payload, authy_code=401, authy_data=invalid_content)
        self.assertEqual(response.status_code, 403)
        self.assertDictEqual(response.data, {
            'detail': ErrorDetail(string='SMS/Authy verification failed', code='authentication_failed')})


class RequestCodeTest(APITestCase):
    def setUp(self):
        self.url = reverse('request-2fa-code')
        User = get_user_model()
        user = User.objects.create_user(username='test1', password='123', authy_id=12345, email="test@test.com")
        user.set_password('123')
        user.save()
        self.payload = {
            'username': 'test1',
            'password': '123',
        }

        self.payload_unknown = {
            'username': 'test2',
            'password': '123',
        }

        self.authy_ok_content = {
            'success': True,
            'message': 'SMS token was sent',
            'cellphone': '+1-XXX-XXX-XX02'
        }

    def _mocked_authy_code_req(self, payload, authy_data=None, authy_code=200):
        mock_resp = Mock()
        mock_resp.status_code = authy_code
        data = authy_data if authy_data is not None else self.authy_ok_content
        mock_resp.json.return_value = data

        with patch('a2fa.views.authy_api.users.request_sms') as atv:
            atv.return_value = Sms(None, mock_resp)
            return self.client.post(self.url, data=payload)

    def test_code_request_success(self):
        response = self._mocked_authy_code_req(self.payload)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, self.authy_ok_content)

        self.client.login(username='test1', password='123')
        response = self._mocked_authy_code_req({})
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, self.authy_ok_content)

    def test_code_request_unsuccess(self):
        invalid_user_error = {'error': 'Invalid user'}
        response = self._mocked_authy_code_req(self.payload_unknown)
        self.assertEqual(response.status_code, 401)
        self.assertDictEqual(response.data, invalid_user_error)

        response = self._mocked_authy_code_req({})
        self.assertEqual(response.status_code, 401)
        self.assertDictEqual(response.data, invalid_user_error)

        response = self._mocked_authy_code_req(self.payload, authy_data={}, authy_code=503)  # non 200 code
        self.assertEqual(response.status_code, 401)
        self.assertDictEqual(response.data, {'error': 'SMS request failed'})


class UpdatePhoneTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.url = reverse('update-phone')
        self.user = User.objects.create_user(username='test', password='123', authy_id=12345, email="test@test.com")
        self.user.set_password('123')
        self.user.save()

        self.authy_ok_content = {
            "message": "User created successfully.",
            "user": {
                "id": 123,
            },
            "success": True,
        }
        self.authy_ok_content_del = {
            "message": "User removed from application",
            "success": True
        }

        self.payload = {
            'phone': '322223322',
            'country_code': '7'
        }

    def _mocked_authy_update_req(self, payload, create_data=None, create_code=200, delete_data=None, delete_code=200):
        mock_resp1 = Mock()
        mock_resp1.status_code = create_code
        data1 = create_data if create_data is not None else self.authy_ok_content
        mock_resp1.json.return_value = data1

        mock_resp2 = Mock()
        mock_resp2.status_code = delete_code
        data2 = delete_data if delete_data is not None else self.authy_ok_content_del
        mock_resp2.json.return_value = data2

        with patch('a2fa.views.authy_api.users.create') as auc, \
                patch('a2fa.views.authy_api.users.delete') as aud:
            auc.return_value = AuthyUser(None, mock_resp1)
            aud.return_value = AuthyUser(None, mock_resp2)
            return self.client.patch(self.url, data=payload)

    def test_update_success(self):
        self.client.login(username='test', password='123')
        response = self._mocked_authy_update_req(self.payload)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {'username': 'test', 'authy_id': 123})

    def test_update_unsuccess(self):
        response = self._mocked_authy_update_req(self.payload)
        self.assertEqual(response.status_code, 401)
        self.assertDictEqual(response.data, {'error': 'Invalid credentials or not logged in'})

        self.client.login(username='test', password='123')
        response = self._mocked_authy_update_req({})
        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(response.data, {
            'phone': [ErrorDetail(string='This field is required.', code='required')],
            'country_code': [ErrorDetail(string='This field is required.', code='required')]})

        fail_to_create = {
          "message": "User was not valid",
          "success": False,
          "errors": {
            "email": "is invalid",
            "message": "User was not valid"
          },
          "email": "is invalid",
          "error_code": "60027"
        }

        response = self._mocked_authy_update_req(self.payload, create_code=401, create_data=fail_to_create)
        self.assertEqual(response.status_code, 304)
        self.assertDictEqual(response.data, {'email': 'is invalid', 'message': 'User was not valid'})

        # such code and error data used cause there is no info in documentation. and in api code only status==200 used
        response = self._mocked_authy_update_req(
            self.payload, delete_code=401,
            delete_data={"errors": {"something": "is invalid", "message": "User removal failed"}}
        )
        self.assertEqual(response.status_code, 304)
        self.assertDictEqual(response.data, {'something': 'is invalid', 'message': 'User removal failed'})
