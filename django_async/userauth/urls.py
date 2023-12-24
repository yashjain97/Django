from django.urls import path

from userauth.views import (
    LoginView,
    RegisterView,
    ResetPasswordView,
    UserProfileView,
    ChangePasswordView,
    SendPasswordResetEmailView
)

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("profile/", UserProfileView.as_view(), name="profile"),
    path("change-password/", ChangePasswordView.as_view(), name="change_password"),
    path("password-reset/email/", SendPasswordResetEmailView.as_view(), name="password_reset_email"),
    path("password-reset/", ResetPasswordView.as_view(), name="password_reset"),
]
