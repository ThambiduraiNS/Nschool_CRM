# Generated by Django 4.2.13 on 2024-08-13 06:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0017_enquiry_inplant_no_of_students_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='enquiry',
            name='date_of_birth',
            field=models.DateField(blank=True, default=0, null=True),
        ),
    ]
