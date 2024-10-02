from decimal import Decimal
import os
from django.db.models import Sum
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
    payment = models.BooleanField(default=False)
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
    S_no = models.PositiveIntegerField(default=0)
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
    internship_no_of_students = models.CharField(null=True, blank=True)
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
    
class Enrollment(models.Model):
    
    enquiry_no = models.ForeignKey('Enquiry', on_delete=models.CASCADE, to_field='enquiry_no', db_column='enquiry_no')
    registration_no = models.CharField(max_length=20, unique=True)
    registration_date = models.DateField()

    name = models.CharField(max_length=255)
    phonenumber = models.CharField(max_length=15)
    date_of_birth = models.DateField(blank=True, null=True)
    gender = models.CharField(null=True)
    email_id = models.EmailField()

    father_name = models.CharField(max_length=255, blank=True, null=True)
    fathers_contact_no = models.CharField(max_length=15)
    fathers_email_id = models.EmailField(null=True, blank=True)

    degree = models.CharField(max_length=255)
    institution = models.CharField(max_length=255)
    subject = models.CharField(max_length=255)
    grade_percentage = models.DecimalField(max_digits=5, decimal_places=2)
    place = models.CharField(max_length=255, blank=True, null=True)
    year_of_passed_out = models.PositiveIntegerField()
    
    designation = models.CharField(max_length=255, null=True, blank=True)
    company_name = models.CharField(max_length=255, null=True, blank=True)
    work_experience = models.CharField(null=True, blank=True)
    nature_of_work = models.CharField(max_length=255, null=True, blank=True)

    course_name = models.ForeignKey('Course', on_delete=models.CASCADE)
    inplant_technology = models.CharField(max_length=100, null=True, blank=True)
    inplant_no_of_days = models.CharField(null=True, blank=True)
    inplant_no_of_students = models.CharField(null=True, blank=True)
    internship_technology = models.CharField(max_length=100, null=True, blank=True)
    internship_no_of_days = models.CharField(null=True, blank=True)
    internship_no_of_students = models.CharField(null=True, blank=True)
    duration = models.CharField(max_length=50, null=True, blank=True)
    payment_type = models.CharField()
    total_fees_amount = models.DecimalField(max_digits=10, decimal_places=2)
    installment_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    created_by = models.IntegerField(null=True, blank=True)
    modified_by = models.IntegerField(null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.name} - {self.course_name}"

class PaymentInfo(models.Model):
    # Fees type choices
    REGULAR = 'Regular'
    INSTALLMENT = 'Installment'
    
    FEES_TYPE_CHOICES = [
        (REGULAR, 'Single Payment'),
        (INSTALLMENT, 'Installment'),
    ]
    
    PARTIAL_PAYMENT = 'Partial Payment'
    FULL_PAYMENT = 'Full Payment'
    
    MONTHLY_PAYMENT_CHOICES = [
        (PARTIAL_PAYMENT, 'Partial Payment'),
        (FULL_PAYMENT, 'Full Payment')
    ]

    registration_no = models.CharField(max_length=20, unique=True)
    joining_date = models.DateField()
    student_name = models.CharField(max_length=255)
    course_name = models.CharField(max_length=255)
    duration = models.CharField(max_length=50)
    fees_type = models.CharField(max_length=20, choices=FEES_TYPE_CHOICES)
    total_fees = models.DecimalField(max_digits=10, decimal_places=2)
    installment_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    excess_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    monthly_payment_type = models.CharField(max_length=20, choices=MONTHLY_PAYMENT_CHOICES, default='Full Payment')
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    created_by = models.IntegerField(null=True, blank=True)
    modified_by = models.IntegerField(null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.student_name}"

# Add Payment Mode Choices
class SinglePayment(models.Model):
    CASH = 'Cash'
    UPI = 'UPI'
    BANK_TRANSFER = 'Bank Transfer'

    PAYMENT_MODE_CHOICES = [
        (CASH, 'Cash'),
        (UPI, 'UPI'),
        (BANK_TRANSFER, 'Bank Transfer'),
    ]

    payment_info = models.OneToOneField(PaymentInfo, on_delete=models.CASCADE, related_name='single_payment')
    date = models.DateField()
    payment_mode = models.CharField(max_length=50, choices=PAYMENT_MODE_CHOICES)
    amount = models.DecimalField(max_digits=10, decimal_places=2)

    # UPI specific fields
    upi_transaction_id = models.CharField(max_length=100, blank=True, null=True)
    upi_app_name = models.CharField(max_length=100, blank=True, null=True)

    # Bank Transfer specific fields
    refference_no = models.CharField(max_length=100, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    created_by = models.IntegerField(null=True, blank=True)
    modified_by = models.IntegerField(null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

class BaseEMI(models.Model):
    CASH = 'Cash'
    UPI = 'UPI'
    BANK_TRANSFER = 'Bank Transfer'

    PAYMENT_MODE_CHOICES = [
        (CASH, 'Cash'),
        (UPI, 'UPI'),
        (BANK_TRANSFER, 'Bank Transfer'),
    ]
    
    PENDING = 'Pending'
    PAID = 'Paid'
    
    PAYMENT_MODE_STATUS = [
        (PENDING, 'Pending'),
        (PAID, 'Paid')
    ]

    payment_info = models.ForeignKey('PaymentInfo', on_delete=models.CASCADE, related_name='%(class)s_payments')
    registration_no = models.CharField(max_length=20)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField(null=True, blank=True)
    payment_mode = models.CharField(max_length=50, choices=PAYMENT_MODE_CHOICES)
    emi = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=PAYMENT_MODE_STATUS, default=PENDING)
    
    # UPI specific fields
    upi_transaction_id = models.CharField(max_length=100, blank=True, null=True)
    upi_app_name = models.CharField(max_length=100, blank=True, null=True)

    # Bank Transfer specific fields
    refference_no = models.CharField(max_length=100, blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    created_by = models.IntegerField(null=True, blank=True)
    modified_by = models.IntegerField(null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        abstract = True  # This makes the model abstract
        
    def __str__(self):
        return f"{self.__class__.__name__}"
    
    def save(self, *args, **kwargs):
        # Access the total EMI amount from the related PaymentInfo object
        total_emi_amount = self.payment_info.installment_amount
        
        # print(f"Total EMI Amount: {total_emi_amount}")

        # Calculate the sum of all previous active and non-deleted EMI payments
        previous_payments_sum = self.__class__.objects.filter(
            payment_info=self.payment_info,
            emi__startswith='EMI_',  # Match all EMI installments
            is_active=True,
            is_deleted=False
        ).exclude(id=self.id).aggregate(total_amount=Sum('amount'))['total_amount'] or Decimal('0.0')

        total_paid_with_current = Decimal(previous_payments_sum) + Decimal(self.amount)

        self.status = self.PAID if total_paid_with_current >= total_emi_amount else self.PENDING
        
        self.payment_info.save()

        # Call the original save method to ensure the object is saved
        super().save(*args, **kwargs)

# Subclasses inheriting from BaseEMI
class EMI_1(BaseEMI):
    pass

class EMI_2(BaseEMI):
    pass

class EMI_3(BaseEMI):
    pass

class EMI_4(BaseEMI):
    pass

class EMI_5(BaseEMI):
    pass

class EMI_6(BaseEMI):
    pass