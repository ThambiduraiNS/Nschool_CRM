# Generated by Django 4.2.13 on 2024-08-12 04:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0013_enquiry'),
    ]

    operations = [
        migrations.AlterField(
            model_name='enquiry',
            name='enquiry_no',
            field=models.CharField(unique=True),
        ),
    ]
