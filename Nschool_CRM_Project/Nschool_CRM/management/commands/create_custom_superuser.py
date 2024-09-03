from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = 'Create a superuser with additional fields'

    def add_arguments(self, parser):
        parser.add_argument('--username', required=True, help='Username')
        parser.add_argument('--email', required=True, help='Email')
        parser.add_argument('--password', required=True, help='Password')
        parser.add_argument('--contact', type=str, help='Contact number for the superuser.')
        parser.add_argument('--enquiry', action='store_true', help='Enquiry permission')
        parser.add_argument('--enrollment', action='store_true', help='Enrollment permission')
        parser.add_argument('--payment', action='store_true', help='Payment permission')
        parser.add_argument('--attendance', action='store_true', help='Attendance permission')
        parser.add_argument('--staff', action='store_true', help='Staff permission')
        parser.add_argument('--placement', action='store_true', help='Placement permission')
        parser.add_argument('--report', action='store_true', help='Report permission')

    def handle(self, *args, **options):
        User = get_user_model()
        username = options['username']
        email = options['email']
        password = options['password']
        contact = options['contact']
        enquiry = options['enquiry']
        enrollment = options['enrollment']
        payment = options['payment']
        attendance = options['attendance']
        staff = options['staff']
        placement = options['placement']
        report = options['report']

        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.ERROR(f'User {username} already exists'))
        else:
            User.objects.create_superuser(
                username=username,
                email=email,
                password=password,
                contact=contact,
                enquiry=enquiry,
                enrollment=enrollment,
                payment=payment,
                attendance=attendance,
                staff=staff,
                placement=placement,
                report=report,
            )
            self.stdout.write(self.style.SUCCESS(f'Superuser {username} created successfully'))
