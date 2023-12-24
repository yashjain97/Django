import os

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes, smart_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework_simplejwt.tokens import RefreshToken


class Token:
    def __init__(self, user):
        self.user = user

    def get_tokens_for_user(self):
        refresh = RefreshToken.for_user(self.user)

        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }

    def generate_token(self):
        return PasswordResetTokenGenerator().make_token(self.user)

    def check_user_token(self, token):
        if not PasswordResetTokenGenerator().check_token(self.user, token):
            return False
        return True


class Encoding:
    def __init__(self, data):
        self.data = data

    def encode(self):
        return urlsafe_base64_encode(force_bytes(self.data))

    def decode(self):
        return smart_str(urlsafe_base64_decode(self.data))


class SendEmail:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email=os.getenv('EMAIL_FROM'),
            to=[data['to_email']]
        )
        email.send()
