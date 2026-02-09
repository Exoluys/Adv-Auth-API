from django.urls import path
from accounts.views import RegisterView, LoginView, ProfileView, LoginHistoryView, PasswordResetRequestView, \
    PasswordResetConfirmationView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', ProfileView.as_view(), name='profiles'),
    path('login-history/', LoginHistoryView.as_view(), name='login-history'),
    path('password-reset/', PasswordResetRequestView().as_view(), name='password-reset'),
    path('password-reset-confirmation/', PasswordResetConfirmationView().as_view(), name='password-reset-confirmation'),
]
