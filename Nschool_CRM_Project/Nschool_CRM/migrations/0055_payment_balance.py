# Generated by Django 4.2.13 on 2024-09-08 15:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0054_payment_date_emi_1_payment_date_emi_2_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='payment',
            name='balance',
            field=models.CharField(blank=True, null=True),
        ),
    ]
