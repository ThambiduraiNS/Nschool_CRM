# Generated by Django 4.2.13 on 2024-09-06 06:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0051_alter_payment_installment'),
    ]

    operations = [
        migrations.RenameField(
            model_name='payment',
            old_name='date',
            new_name='bank_date',
        ),
        migrations.AddField(
            model_name='payment',
            name='bank_cash',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='upi_cash',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='upi_date',
            field=models.DateField(blank=True, null=True),
        ),
    ]
