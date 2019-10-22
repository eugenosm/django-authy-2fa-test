# django-authy-2fa-test
Test project implementing rest api for two factor authentication using django rest framework, rest_auth and authy servie for 2FA.

API Endpoints

#### User Details
`/rest-auth/user/`  
Allow: GET, PUT, PATCH, HEAD  

    - on GET/PUT/PATCH: returns: 'email', 'username', 'auth_method', 'authy_id'
    - on PUT allow to change auth_method. values 'SMS' (sms confirm) and 
      'ATH'(authy one touch confirm)
```json
# HTTP 200 OK
{
    "email": "test@gmail.com",
    "username": "testuser",
    "auth_method": "ATH",
    "authy_id": "200133705"
}
```


#### Set Phone
`/rest-auth/phone/`  
Allow: PUT, PATCH
  
    Change two factor authentication phone number of user
    previously logged in
    
    Accept the following parameters: country_code, phone
    Return username and new authy_id
    
```json
# HTTP 200 OK
{
    "username": "testuser",
    "authy_id": 200142333
}
```


#### Register
`/rest-auth/registration/`  
Allow: POST  

    New user registration. Register new user in django db and authy service 

```json
# HTTP 201 Created
{
    "key": "a1472e7551f4ad4c581bb941e0ce7b44f8832bdf"
}
```


#### Request Confirmation Code
`/rest-auth/login/request-code/`
Allow: POST

    Request SMS or Authy Notification confirmation code,
    depending on user.authy_method state
    If user is logged in in django then username and password
    could be skipped
    
    Accept the following POST parameters: username, password
    Authy one touch uuid or "SMS token was send" message  

```json
# HTTP 200 OK
{
    "uuid": "0389d5b0-d6a9-0137-f041-0a44db1d137e"
}  
or
# HTTP 200 OK
{
    "success": true,
    "message": "SMS token was sent",
    "cellphone": "+7-XXX-XXX-XX36"
}
```


#### Login
`/rest-auth/login/`  
Allow: POST  

    Check the credentials and return the REST Token
    if the credentials are valid and authenticated.
    Calls Django Auth login method to register User ID
    in Django session framework
    
    Accept the following POST parameters: username, password, confirmation_code
    Return the REST Framework Token Object's key.    
```json
# HTTP 200 OK
{
    "key": "21580883ddc29e94a7d8b675b021868174d62f0e"
}
or 
# HTTP 403 Forbidden
{
    "detail": "SMS/Authy verification failed"
}
```

#### Logout
`/rest-auth/logout/`
Allow: POST

    Calls Django logout method and delete the Token object
    assigned to the current User object.
    
    Accepts/Returns nothing.


#### Password Change
`/rest-auth/password/change/`
Allow: POST
   
    Calls Django Auth SetPasswordForm save method.
    
    Accepts the following POST parameters: new_password1, new_password2
    Returns the success/fail message.
    
 