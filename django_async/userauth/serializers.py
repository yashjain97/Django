from django.utils.encoding import DjangoUnicodeDecodeError
from rest_framework import serializers

from userauth.models import User
from userauth.utility import Encoding, Token


class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = ["email", "name", "password", "password2"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")
        if password != password2:
            raise serializers.ValidationError(
                "Password and Confirm Password Doesn't Match"
            )
        return super().validate(attrs)

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ["email", "password"]


class ChangePasswordSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")
        if password != password2:
            raise serializers.ValidationError(
                "Password and Confirm Password do not match"
            )
        user = self._context.get('user')
        user.set_password(password)
        user.save()
        return super().validate(attrs)


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate(self, attrs):
        email = attrs.get('email')

        user_queryset = User.objects.filter(email=email)

        if not user_queryset.exists():
            raise serializers.ValidationError("You are not a registered User")

        user = user_queryset.first()

        uid = Encoding(user.id).encode()
        print("Encoded UId", uid)
        token = Token(user).generate_token()
        link = f'http://localhost:8000/auth/password-reset?uid=' + uid + '&token=' + token
        print("Password reset Link", link)
        return attrs


class PasswordResetSerializer(serializers.Serializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)
    password = serializers.CharField(style={"input_type": "password"}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get("password")
            password2 = attrs.get("password2")

            if password != password2:
                raise serializers.ValidationError(
                    "Password and Confirm Password do not match"
                )
            uid = self._context.get('uid')
            token = self._context.get('token')
            id = Encoding(uid).decode()

            user = User.objects.filter(id=id).first()
            if not Token(user).check_user_token(token):
                raise serializers.ValidationError("Token is not valid or expired")

            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifiers:
            raise serializers.ValidationError("Token is not valid or expired")


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "name"]
