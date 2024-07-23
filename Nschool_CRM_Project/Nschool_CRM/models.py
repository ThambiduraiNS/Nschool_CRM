from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from phonenumber_field.modelfields import PhoneNumberField
from django.core.validators import MinLengthValidator

# Create your models here.

class AdminLoginManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        if not email:
            raise ValueError('Users must have an email address')
        if not username:
            raise ValueError('Users must have a username')

        user = self.model(
            email=self.normalize_email(email),
            username=username,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None):
        user = self.create_user(
            email=email,
            username=username,
            password=password,
        )
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class AdminLogin(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(max_length=150, unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    objects = AdminLoginManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username
    
class NewUser(models.Model):
    name = models.CharField(max_length=50)
    email = models.EmailField(max_length=200, unique=True)
    contact = PhoneNumberField(unique=True, blank=False)
    designation = models.CharField(max_length=255)
    enquiry = models.BooleanField(default=False)
    enrollment = models.BooleanField(default=False)
    attendance = models.BooleanField(default=False)
    staff = models.BooleanField(default=False)
    placement = models.BooleanField(default=False)
    report = models.BooleanField(default=False)
    password = models.CharField(max_length=15, validators=[MinLengthValidator(8)])
    
    def __str__(self):
    	return self.name