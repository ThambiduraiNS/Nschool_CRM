import os
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import MinLengthValidator
from .utils import encrypt_password, decrypt_password
from datetime import datetime

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
    
class Course(models.Model):
    course_name = models.CharField(max_length=150, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    created_by = models.IntegerField(null=True, blank=True)
    modified_by = models.IntegerField(null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.course_name

class Enquiry_Mode(models.Model):
    mode_of_enquiry = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    created_by = models.IntegerField(null=True, blank=True)
    modified_by = models.IntegerField(null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.mode_of_enquiry

def getFileName(request, filename):
    return os.path.join('Images/', filename)
 
class Enquiry(models.Model):
    enquiry_date = models.DateField()
    enquiry_no = models.CharField(unique=True, blank=True)

    # Student Details
    name = models.CharField(max_length=100)
    contact_no = models.CharField(max_length=10, unique=True)
    email_id = models.EmailField(max_length=255, unique=True)
    date_of_birth = models.DateField(null=True, blank=True)  # Removed invalid default
    fathers_name = models.CharField(max_length=100, null=True, blank=True)
    fathers_contact_no = models.CharField(max_length=10, unique=True)
    fathers_occupation = models.CharField(max_length=100, null=True, blank=True)
    address = models.TextField(null=True, blank=True)
    status = models.CharField(null=True, blank=True)

    # Course Name (Foreign Key)
    course_name = models.ForeignKey('Course', on_delete=models.CASCADE)
    inplant_technology = models.CharField(max_length=100, null=True, blank=True)
    inplant_no_of_days = models.CharField(null=True, blank=True)
    inplant_no_of_students = models.CharField(null=True, blank=True)
    internship_technology = models.CharField(max_length=100, null=True, blank=True)
    internship_no_of_days = models.CharField(null=True, blank=True)
    next_follow_up_date = models.DateField()

    # Educational Details
    degree = models.CharField(max_length=100, null=True)
    college = models.CharField(max_length=100)
    grade_percentage = models.CharField(blank=True, null=True)
    year_of_graduation = models.PositiveIntegerField()

    mode_of_enquiry = models.ForeignKey('Enquiry_Mode', on_delete=models.CASCADE)
    reference_name = models.CharField(max_length=100, null=True, blank=True)
    reference_contact_no = models.CharField(max_length=10, null=True, blank=True)
    other_enquiry_details = models.TextField(null=True, blank=True)
    lead_type = models.CharField(null=True, blank=True)
    
    enquiry_count = models.IntegerField(default=0)
    notes = models.CharField(blank=True, null=True)
    files = models.ImageField(upload_to=getFileName, blank=False, default='React.png')
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    created_by = models.IntegerField(null=True, blank=True)
    modified_by = models.IntegerField(null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.enquiry_no} - {self.name}"
    
    def save(self, *args, **kwargs):
        # Convert the date format from dd/mm/yyyy to yyyy-mm-dd before saving
        if isinstance(self.enquiry_date, str):
            self.enquiry_date = datetime.strptime(self.enquiry_date, '%d/%m/%Y').date()

        if not self.enquiry_no and self.pk is None:
            last_enquiry = Enquiry.objects.all().order_by("-pk").first()
            last_pk = 0
            if last_enquiry:
                last_pk = last_enquiry.pk
        
            self.enquiry_no = "EWT-" + str(last_pk + 1).zfill(4)

        super(Enquiry, self).save(*args, **kwargs)
        
class Notes(models.Model):
    notes = models.CharField(blank=True, null=True)
    files = models.ImageField(blank=True, null=True)
    user_id = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    created_by = models.IntegerField(null=True, blank=True)
    modified_by = models.IntegerField(null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    
    def __str__(self):
        return self.notes