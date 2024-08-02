# backends.py
from django.contrib.auth.backends import BaseBackend
from django.db.models import Q
from .models import NewUser
from .utils import encrypt_password, decrypt_password

class MultiModelBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        print(f"Attempting to authenticate {username}")
        try:
            print("Welcome to new user !")
            user = NewUser.objects.get(Q(username=username) | Q(email=username))
            print("User : ", user)
            if decrypt_password(user.password) == password:
                print("Authenticated as NewUser")
                return user
        except NewUser.DoesNotExist:
            print("NewUser does not exist")

        print("Authentication failed")
        return None

    def get_user(self, user_id):
        try:
            return NewUser.objects.get(pk=user_id)
        except NewUser.DoesNotExist:
            return None
