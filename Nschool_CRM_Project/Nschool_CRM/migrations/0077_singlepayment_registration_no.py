# Generated by Django 4.2.13 on 2024-10-07 06:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0076_remove_paymentinfo_monthly_payment_type_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='singlepayment',
            name='registration_no',
            field=models.CharField(default=None, max_length=20, unique=True),
        ),
    ]
