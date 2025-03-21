from django.contrib.auth import authenticate, get_user_model
from django.core.cache import cache
from django.conf import settings
from django.utils.translation import gettext_lazy as _

from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from two_factor.utils import default_device

User = get_user_model()


class RegisterView(APIView):
    """
    Register a new user with email and password.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response(
                {'error': _('Please provide both email and password')},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if User.objects.filter(email=email).exists():
            return Response(
                {'error': _('User with this email already exists')},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        user = User.objects.create_user(email=email, password=password)
        
        return Response(
            {'message': _('User registered successfully')},
            status=status.HTTP_201_CREATED
        )


class LoginView(APIView):
    """
    Authenticate a user and return JWT tokens.
    Implements account lockout after 3 failed attempts.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response(
                {'error': _('Please provide both email and password')},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Check for account lockout
        key = f'failed_attempts_{email}'
        attempts = cache.get(key, 0)
        
        if attempts >= settings.LOGIN_ATTEMPTS_LIMIT:
            return Response(
                {'error': _('Too many failed attempts. Account locked for 1 hour.')},
                status=status.HTTP_403_FORBIDDEN
            )
            
        user = authenticate(email=email, password=password)
        
        if user is None:
            # Increment failed attempts
            cache.set(key, attempts + 1, timeout=settings.LOCKOUT_TIME)
            remaining_attempts = settings.LOGIN_ATTEMPTS_LIMIT - (attempts + 1)
            
            return Response(
                {
                    'error': _('Invalid credentials'),
                    'remaining_attempts': max(0, remaining_attempts)
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        # Check if 2FA is enabled
        if user.is_two_factor_enabled:
            return Response(
                {'message': _('2FA authentication required'), 'user_id': user.id},
                status=status.HTTP_200_OK
            )
            
        # Clear failed attempts on successful login
        cache.delete(key)
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    Logout a user by blacklisting their refresh token.
    """
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': _('Logout successful')}, status=status.HTTP_200_OK)
        except Exception:
            return Response({'error': _('Invalid token')}, status=status.HTTP_400_BAD_REQUEST)


class TwoFactorAuthView(APIView):
    """
    Enable or verify two-factor authentication.
    """
    def post(self, request):
        action = request.data.get('action')
        
        if action == 'enable':
            # In a real implementation, this would generate and send a verification code
            # For demo purposes, we'll just enable 2FA
            request.user.is_two_factor_enabled = True
            request.user.save()
            
            return Response(
                {'message': _('Two-factor authentication enabled')},
                status=status.HTTP_200_OK
            )
            
        elif action == 'verify':
            user_id = request.data.get('user_id')
            verification_code = request.data.get('code')
            
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response(
                    {'error': _('User not found')},
                    status=status.HTTP_404_NOT_FOUND
                )
                
            # In a real implementation, verify the code
            # For demo purposes, any code will work
            
            # Generate JWT tokens after successful 2FA verification
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
            
        else:
            return Response(
                {'error': _('Invalid action')},
                status=status.HTTP_400_BAD_REQUEST
            )


class UserProfileView(APIView):
    """
    Get or update the authenticated user's profile.
    """
    def get(self, request):
        user = request.user
        return Response({
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_two_factor_enabled': user.is_two_factor_enabled,
        }, status=status.HTTP_200_OK)
        
    def patch(self, request):
        user = request.user
        
        # Update allowed fields
        for field in ['first_name', 'last_name']:
            if field in request.data:
                setattr(user, field, request.data[field])
                
        user.save()
        
        return Response({
            'message': _('Profile updated successfully'),
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_two_factor_enabled': user.is_two_factor_enabled,
        }, status=status.HTTP_200_OK)