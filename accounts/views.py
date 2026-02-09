from django.conf import settings
from django.core.mail import send_mail
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import User, LoginHistory, PasswordResetToken
from accounts.serializers import LoginSerializer, RegisterSerializer, UserSerializer, PasswordResetRequestSerializer, \
    PasswordResetConfirmationSerializer


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


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, req):
        serializer = PasswordResetRequestSerializer(data=req.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']

            try:
                user = User.objects.get(email=email)
                reset_token = PasswordResetToken.objects.create(user=user)
                reset_link = f"http://localhost:3000/reset-password?token={reset_token.token}"

                send_mail(
                    subject='Password Reset Request',
                    message=f'Click the link to reset your password: {reset_link}\n\nThis link expires in 1 hour.',
                    from_email=settings.DEFAULT_FROM_EMAIL if hasattr(settings,
                                                                      'DEFAULT_FROM_EMAIL') else 'noreply@example.com',
                    recipient_list=[email],
                )

            except User.DoesNotExist:
                pass

            return Response(
                {'message': 'If your email exists, you will receive a password reset link.'},
                status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmationView(APIView):
    permission_classes = [AllowAny]

    def post(self, req):
        serializer = PasswordResetConfirmationSerializer(data=req.data)

        if serializer.is_valid():
            token = serializer.validated_data['token']
            password = serializer.validated_data['password']

            try:
                reset_token = PasswordResetToken.objects.get(token=token)

                if not reset_token.is_valid():
                    return Response(
                        {'error': 'Token has expired or already been used'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                user = reset_token.user
                user.set_password(password)
                user.save()

                reset_token.used = True
                reset_token.save()

                return Response(
                    {'message': 'Password has been reset successfully'},
                    status=status.HTTP_200_OK
                )

            except PasswordResetToken.DoesNotExist:
                return Response(
                    {'error': 'Invalid token'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
