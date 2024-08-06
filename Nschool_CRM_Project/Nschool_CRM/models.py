from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import MinLengthValidator
from .utils import encrypt_password, decrypt_password

# Create your models here.

class AdminLoginManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        if not username:
            raise ValueError('Users must have a username')

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            **extra_fields
        )

        if password:
            encrypted_password = encrypt_password(password)
            user.password = encrypted_password.decode()
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(username, email, password, **extra_fields)
    
class NewUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=50, default=None)
    email = models.EmailField(max_length=200, unique=True)
    contact = models.CharField(max_length=10, unique=True)
    designation = models.CharField(max_length=255)
    enquiry = models.BooleanField(default=False)
    enrollment = models.BooleanField(default=False)
    attendance = models.BooleanField(default=False)
    staff = models.BooleanField(default=False)
    placement = models.BooleanField(default=False)
    report = models.BooleanField(default=False)
    password = models.CharField(max_length=128, validators=[MinLengthValidator(8)])  # Increased max_length for hashed password
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    
    objects = AdminLoginManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username