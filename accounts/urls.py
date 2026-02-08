from django.urls import path
from accounts.views import RegisterView, LoginView, ProfileView, LoginHistoryView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', ProfileView.as_view(), name='profiles'),
    path('login-history/', LoginHistoryView.as_view(), name='login-history')
]