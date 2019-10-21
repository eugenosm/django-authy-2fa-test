from unittest.mock import patch, mock_open, Mock

from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework.serializers import ErrorDetail
from rest_framework.test import APITestCase
from authy.api.resources import User as AuthiUser


from requests import Response

""" 
endpoints:
/rest-auth/user/
^rest-auth/registration/
^rest-auth/login/$ [name='rest_login']
rest-auth/login/request-code/ [name='request-2fa-code']
rest-auth/phone/ [name='update-phone']
rest-auth/password/ [name='update-phone']
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
            auc.return_value = AuthiUser(None, mock_resp)
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
