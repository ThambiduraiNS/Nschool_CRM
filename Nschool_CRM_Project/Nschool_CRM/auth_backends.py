# backends.py
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.hashers import check_password
from django.db.models import Q
from .models import AdminLogin, NewUser

class MultiModelBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        print(f"Attempting to authenticate {username}")
        try:
            user = AdminLogin.objects.get(username=username)
            if user.check_password(password):
                print("Authenticated as AdminLogin user")
                return user
        except AdminLogin.DoesNotExist:
            print("AdminLogin user does not exist")

        try:
            print("Welcome to new user !")
            user = NewUser.objects.get(Q(name=username) | Q(email=username))
            print("User : ", user)
            if user.check_password(password):
                print("Authenticated as NewUser")
                return user
        except NewUser.DoesNotExist:
            print("NewUser does not exist")

        print("Authentication failed")
        return None

    def get_user(self, user_id):
        try:
            return AdminLogin.objects.get(pk=user_id)
        except AdminLogin.DoesNotExist:
            try:
                return NewUser.objects.get(pk=user_id)
            except NewUser.DoesNotExist:
                return None
