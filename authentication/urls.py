from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    RegisterView, LoginView, LogoutView, 
    TwoFactorAuthView, UserProfileView
)

urlpatterns = [
    # Authentication endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('2fa/', TwoFactorAuthView.as_view(), name='two_factor_auth'),
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    
    # Social authentication endpoints (from dj-rest-auth)
    path('social/', include('dj_rest_auth.registration.urls')),
]