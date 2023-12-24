from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from userauth.enums import AuthEnums
from userauth.serializers import (
    RegistrationSerializer,
    LoginSerializer,
    ProfileSerializer,
    ChangePasswordSerializer,
    SendPasswordResetEmailSerializer,
    PasswordResetSerializer
)
from userauth.utility import Token


class RegisterView(GenericAPIView):
    serializer_class = RegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = Token(user).get_tokens_for_user()

            return Response(
                {"token": token, "msg": AuthEnums.REGISTRATION_SUCCESS.value},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get("email")
            password = serializer.data.get("password")
            user = authenticate(email=email, password=password)

            if user:
                token = Token(user).get_tokens_for_user()
                return Response(
                    {"token": token, "msg": AuthEnums.LOGIN_SUCCESS.value}, status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {"msg": AuthEnums.UNAUTHORISED_USER.value}, status=status.HTTP_401_UNAUTHORIZED
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={"user": request.user})
        if serializer.is_valid(raise_exception=True):
            return Response(
                {"msg": AuthEnums.PASSWORD_CHANGE_SUCCESS.value}, status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendPasswordResetEmailView(GenericAPIView):
    serializer_class = SendPasswordResetEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get("email")
            return Response({"msg": f"{AuthEnums.PASSWORD_RESET_LINK_MSG.value} {email}"}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        uid = request.query_params.get('uid', None)
        token = request.query_params.get('token', None)

        serializer = self.serializer_class(data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({"msg": AuthEnums.PASSWORD_RESET_SUCCESS.value}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(GenericAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
