from enum import Enum


class AuthEnums(Enum):
    PASSWORD_DOES_NOT_MATCH = "Password and Confirm Password Doesn't Match"
    TOKEN_INVALID_EXPIRED = "Token is not valid or expired"
    NOT_REGISTERED = "You are not a registered user"
    EMAIL_ERROR = "Unable to send email"
    PASSWORD_RESET_MSG = "Click following link to reset your password"
    LOGIN_SUCCESS = "User successfully logged in!"
    UNAUTHORISED_USER = "Unauthorised User"
    REGISTRATION_SUCCESS = "Registration Successful"
    PASSWORD_RESET_SUCCESS = "Your password reset is successful"
    PASSWORD_CHANGE_SUCCESS = "Your password is successfully changed"
    PASSWORD_RESET_LINK_MSG = "Password reset link sent to"
