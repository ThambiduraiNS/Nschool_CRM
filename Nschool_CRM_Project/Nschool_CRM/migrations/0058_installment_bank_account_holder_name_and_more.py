# Generated by Django 4.2.13 on 2024-09-12 17:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0057_paymentinfo_singlepayment_installment'),
    ]

    operations = [
        migrations.AddField(
            model_name='installment',
            name='bank_account_holder_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='installment',
            name='bank_account_no',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='installment',
            name='bank_branch_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='installment',
            name='bank_ifsc_code',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='installment',
            name='upi_app_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='installment',
            name='upi_bank_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='installment',
            name='upi_transaction_id',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='singlepayment',
            name='bank_account_holder_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='singlepayment',
            name='bank_account_no',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='singlepayment',
            name='bank_branch_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='singlepayment',
            name='bank_ifsc_code',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='singlepayment',
            name='upi_app_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='singlepayment',
            name='upi_bank_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='singlepayment',
            name='upi_transaction_id',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
