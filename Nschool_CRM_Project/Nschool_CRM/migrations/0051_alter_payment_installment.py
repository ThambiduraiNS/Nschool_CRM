# Generated by Django 4.2.13 on 2024-09-05 11:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0050_alter_payment_account_holder_name_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='payment',
            name='installment',
            field=models.CharField(blank=True, null=True),
        ),
    ]
