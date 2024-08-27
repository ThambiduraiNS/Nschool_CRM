from django.db.models.signals import pre_save
from django.dispatch import receiver
from .models import Enrollment, Enquiry

@receiver(pre_save, sender=Enrollment)
def auto_populate_enrollment_fields(sender, instance, **kwargs):
    print("Signal")
    if instance.enquiry_no:
        enquiry = instance.enquiry_no  # Get the related Enquiry instance

        # Auto-populate fields based on the Enquiry instance
        instance.name = enquiry.name
        
        print("Name : ", instance.name)
        instance.phonenumber = enquiry.contact_no
        instance.date_of_birth = enquiry.date_of_birth
        instance.email_id = enquiry.email_id
        instance.father_name = enquiry.fathers_name
        instance.fathers_contact_no = enquiry.fathers_contact_no
        instance.degree = enquiry.degree
        instance.institution = enquiry.college
        instance.course_name = enquiry.course_name
        # Add other fields as needed

        # Any other logic to set other fields or defaults
