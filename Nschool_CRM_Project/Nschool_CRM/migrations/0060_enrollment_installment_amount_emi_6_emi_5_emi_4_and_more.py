# Generated by Django 4.2.13 on 2024-09-15 10:49

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0059_rename_bank_account_holder_name_installment_refference_no_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='enrollment',
            name='installment_amount',
            field=models.DecimalField(decimal_places=2, default=0.0, max_digits=10),
        ),
        migrations.CreateModel(
            name='EMI_6',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('registration_no', models.CharField(max_length=20)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('date', models.DateField(blank=True, null=True)),
                ('payment_mode', models.CharField(choices=[('Cash', 'Cash'), ('UPI', 'UPI'), ('Bank Transfer', 'Bank Transfer')], max_length=50)),
                ('emi', models.CharField(max_length=50)),
                ('status', models.CharField(choices=[('Pending', 'Pending'), ('Paid', 'Paid')], max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.IntegerField(blank=True, null=True)),
                ('modified_by', models.IntegerField(null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('payment_info', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='emi6_payments', to='Nschool_CRM.paymentinfo')),
            ],
        ),
        migrations.CreateModel(
            name='EMI_5',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('registration_no', models.CharField(max_length=20)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('date', models.DateField(blank=True, null=True)),
                ('payment_mode', models.CharField(choices=[('Cash', 'Cash'), ('UPI', 'UPI'), ('Bank Transfer', 'Bank Transfer')], max_length=50)),
                ('emi', models.CharField(max_length=50)),
                ('status', models.CharField(choices=[('Pending', 'Pending'), ('Paid', 'Paid')], max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.IntegerField(blank=True, null=True)),
                ('modified_by', models.IntegerField(null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('payment_info', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='emi5_payments', to='Nschool_CRM.paymentinfo')),
            ],
        ),
        migrations.CreateModel(
            name='EMI_4',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('registration_no', models.CharField(max_length=20)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('date', models.DateField(blank=True, null=True)),
                ('payment_mode', models.CharField(choices=[('Cash', 'Cash'), ('UPI', 'UPI'), ('Bank Transfer', 'Bank Transfer')], max_length=50)),
                ('emi', models.CharField(max_length=50)),
                ('status', models.CharField(choices=[('Pending', 'Pending'), ('Paid', 'Paid')], max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.IntegerField(blank=True, null=True)),
                ('modified_by', models.IntegerField(null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('payment_info', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='emi4_payments', to='Nschool_CRM.paymentinfo')),
            ],
        ),
        migrations.CreateModel(
            name='EMI_3',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('registration_no', models.CharField(max_length=20)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('date', models.DateField(blank=True, null=True)),
                ('payment_mode', models.CharField(choices=[('Cash', 'Cash'), ('UPI', 'UPI'), ('Bank Transfer', 'Bank Transfer')], max_length=50)),
                ('emi', models.CharField(max_length=50)),
                ('status', models.CharField(choices=[('Pending', 'Pending'), ('Paid', 'Paid')], max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.IntegerField(blank=True, null=True)),
                ('modified_by', models.IntegerField(null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('payment_info', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='emi3_payments', to='Nschool_CRM.paymentinfo')),
            ],
        ),
        migrations.CreateModel(
            name='EMI_2',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('registration_no', models.CharField(max_length=20)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('date', models.DateField(blank=True, null=True)),
                ('payment_mode', models.CharField(choices=[('Cash', 'Cash'), ('UPI', 'UPI'), ('Bank Transfer', 'Bank Transfer')], max_length=50)),
                ('emi', models.CharField(max_length=50)),
                ('status', models.CharField(choices=[('Pending', 'Pending'), ('Paid', 'Paid')], max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.IntegerField(blank=True, null=True)),
                ('modified_by', models.IntegerField(null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('payment_info', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='emi2_payments', to='Nschool_CRM.paymentinfo')),
            ],
        ),
        migrations.CreateModel(
            name='EMI_1',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('registration_no', models.CharField(max_length=20)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('date', models.DateField(blank=True, null=True)),
                ('payment_mode', models.CharField(choices=[('Cash', 'Cash'), ('UPI', 'UPI'), ('Bank Transfer', 'Bank Transfer')], max_length=50)),
                ('emi', models.CharField(max_length=50)),
                ('status', models.CharField(choices=[('Pending', 'Pending'), ('Paid', 'Paid')], max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('modified_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.IntegerField(blank=True, null=True)),
                ('modified_by', models.IntegerField(null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('payment_info', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='emi1_payments', to='Nschool_CRM.paymentinfo')),
            ],
        ),
    ]
