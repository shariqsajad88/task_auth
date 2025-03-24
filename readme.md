Authentication App Documentation
Overview
This authentication app is built using Django Rest Framework (DRF). It includes email-based authentication, social login, two-factor authentication (2FA), and a user lockout mechanism after multiple failed login attempts.
Features
JWT Authentication using django-rest-framework-simplejwt
Email-based Authentication using Django-allauth
Two-Factor Authentication (2FA) using Django-otp and Django-two-factor-auth
Social Authentication using Django-allauth and dj-rest-auth
Account Lockout: Users are blocked for 1 hour after 3 failed login attempts

Install Dependencies
pip install django djangorestframework django-allauth django-rest-framework-simplejwt \
    django-two-factor-auth django-otp dj-rest-auth django-allauth[socialaccount]

Add to INSTALLED_APPS in settings.py
INSTALLED_APPS = [
    'django.contrib.sites',
    'rest_framework',
    'rest_framework_simplejwt',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'dj_rest_auth',
    'dj_rest_auth.registration',
    'two_factor',
    'otp',
]
SITE_ID = 1

Configuration
JWT Authentication Settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}

Lockout Settings
Add to settings.py:
from django.core.cache import cache

LOGIN_ATTEMPTS_LIMIT = 3
LOCKOUT_TIME = 3600  # 1 hour

Implementing Lockout Mechanism
from django.contrib.auth import authenticate
from django.core.cache import cache
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        key = f'failed_attempts_{email}'
        attempts = cache.get(key, 0)

        if attempts >= LOGIN_ATTEMPTS_LIMIT:
            return Response({'error': 'Too many failed attempts. Try again later.'}, status=status.HTTP_403_FORBIDDEN)

        user = authenticate(email=email, password=password)
        if user:
            cache.delete(key)
            return Response({'message': 'Login successful'})
        else:
            cache.set(key, attempts + 1, timeout=LOCKOUT_TIME)
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

Social Authentication Setup

To enable Google, Facebook, and other providers, configure SOCIALACCOUNT_PROVIDERS in settings.py.
API Endpoints
Endpoint
Method
Description
/auth/login/
POST
Login with email & password
/auth/register/
POST
Register new user
/auth/logout/
POST
Logout user
/auth/2fa/
POST
Enable Two-Factor Authentication
/auth/social/login/
POST
Login via social accounts

Conclusion
This authentication app provides robust security features, including JWT authentication, two-factor authentication, and a lockout mechanism for enhanced security. Further improvements can include email notifications for blocked users and a password reset feature.

