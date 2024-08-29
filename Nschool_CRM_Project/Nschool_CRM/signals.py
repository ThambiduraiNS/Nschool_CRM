from django.db.models.signals import pre_save
from django.dispatch import receiver
from .models import Enrollment, Enquiry

@receiver(pre_save, sender=Enrollment)
def auto_populate_enrollment_fields(sender, instance, **kwargs):
    print("Signal")
    
