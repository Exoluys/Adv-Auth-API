from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import User, LoginHistory
from accounts.serializers import LoginSerializer, RegisterSerializer, UserSerializer


def get_client_ip(req):
    x_forwarded_for = req.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = req.META.get('REMOTE_ADDR')
    return ip


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, req):
        serializer = RegisterSerializer(data=req.data)

        if serializer.is_valid():
            user = serializer.save()
            user_data = UserSerializer(user).data
            return Response(user_data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, req):
        serializer = LoginSerializer(data=req.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)

            LoginHistory.objects.create(
                user=user,
                ip_address=get_client_ip(req),
                user_agent=req.META.get('HTTP_USER_AGENT', 'Unknown'),
                success=True
            )

            return Response(serializer.validated_data, status=status.HTTP_200_OK)

        email = req.data.get('email')
        if email:
            try:
                user = User.objects.get(email=email)
                LoginHistory.objects.create(
                    user=user,
                    ip_address=get_client_ip(req),
                    user_agent=req.META.get('HTTP_USER_AGENT', 'Unknown'),
                    success=False
                )
            except User.DoesNotExist:
                pass

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, req):
        user = req.user
        user_data = UserSerializer(user).data
        return Response(user_data, status=status.HTTP_200_OK)


class LoginHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, req):
        history = LoginHistory.objects.filter(user=req.user)[:10]

        history_data = [
            {
                'ip_address': entry.ip_address,
                'user_agent': entry.user_agent,
                'login_time': entry.login_time,
                'success': entry.success
            }
            for entry in history
        ]

        return Response(history_data, status=status.HTTP_200_OK)
