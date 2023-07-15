from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

User = get_user_model()

class CustomUserModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get(User.USERNAME_FIELD)
        
        try:
            user = User.objects.get(username=username)  # Check for username
        except User.DoesNotExist:
            try:
                user = User.objects.get(email=username)  # Check for email
            except User.DoesNotExist:
                return None

        if user.check_password(password):
            return user

        return None
