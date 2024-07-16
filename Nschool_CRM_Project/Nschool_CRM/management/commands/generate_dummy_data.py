import random
from django.core.management.base import BaseCommand
from faker import Faker
from Nschool_CRM.models import NewUser

class Command(BaseCommand):
    help = 'Generates dummy data for NewUser'

    def add_arguments(self, parser):
        parser.add_argument('--count', type=int, default=100, help='Number of dummy records to create')

    def handle(self, *args, **kwargs):
        count = kwargs['count']
        fake = Faker()

        for _ in range(count):
            NewUser.objects.create(
                name=fake.name(),
                email=fake.unique.email(),
                contact=fake.phone_number(),
                designation=random.choice(['Manager', 'Developer', 'Designer', 'QA', 'HR']),
                enquiry=random.choice([True, False]),
                enrollment=random.choice([True, False]),
                attendance=random.choice([True, False]),
                staff=random.choice([True, False]),
                placement=random.choice([True, False]),
                report=random.choice([True, False]),
                password=fake.password(length=10)
            )

        self.stdout.write(self.style.SUCCESS(f'Successfully created {count} dummy records'))
