# Generated by Django 4.2.13 on 2024-09-05 10:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0049_alter_payment_course_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='payment',
            name='account_holder_name',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='payment',
            name='account_no',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='payment',
            name='app_name',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='payment',
            name='bank_name',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='payment',
            name='branch_name',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='payment',
            name='cash',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='payment',
            name='date',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='payment',
            name='ifsc_code',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='payment',
            name='registration_no',
            field=models.CharField(max_length=20),
        ),
        migrations.AlterField(
            model_name='payment',
            name='transaction_id',
            field=models.CharField(blank=True, null=True),
        ),
    ]
