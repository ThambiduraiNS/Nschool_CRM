# Generated by Django 4.2.13 on 2024-09-09 08:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0055_payment_balance'),
    ]

    operations = [
        migrations.AddField(
            model_name='payment',
            name='bank_cash_EMI_1',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='bank_cash_EMI_2',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='bank_cash_EMI_3',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='bank_cash_EMI_4',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='bank_cash_EMI_5',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='bank_cash_EMI_6',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='cash_EMI_1',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='cash_EMI_2',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='cash_EMI_3',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='cash_EMI_4',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='cash_EMI_5',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='cash_EMI_6',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='upi_cash_EMI_1',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='upi_cash_EMI_2',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='upi_cash_EMI_3',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='upi_cash_EMI_4',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='upi_cash_EMI_5',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='payment',
            name='upi_cash_EMI_6',
            field=models.CharField(blank=True, null=True),
        ),
    ]
