# Generated by Django 4.2.13 on 2024-10-07 09:27

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0078_alter_singlepayment_registration_no'),
    ]

    operations = [
        migrations.AlterField(
            model_name='singlepayment',
            name='payment_info',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='single_payment', to='Nschool_CRM.paymentinfo'),
        ),
    ]
