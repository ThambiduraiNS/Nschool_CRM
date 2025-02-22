# Generated by Django 4.2.13 on 2024-10-14 05:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0080_alter_enrollment_fathers_email_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='paymentinfo',
            name='balance',
        ),
        migrations.RemoveField(
            model_name='paymentinfo',
            name='excess_amount',
        ),
        migrations.AddField(
            model_name='emi_1',
            name='class_status',
            field=models.CharField(choices=[('Yet To Start', 'Yet To Start'), ('On Going', 'On Going'), ('Discontinue', 'Discontinue'), ('Completed', 'Completed')], default='On Going', max_length=20),
        ),
        migrations.AddField(
            model_name='emi_2',
            name='class_status',
            field=models.CharField(choices=[('Yet To Start', 'Yet To Start'), ('On Going', 'On Going'), ('Discontinue', 'Discontinue'), ('Completed', 'Completed')], default='On Going', max_length=20),
        ),
        migrations.AddField(
            model_name='emi_3',
            name='class_status',
            field=models.CharField(choices=[('Yet To Start', 'Yet To Start'), ('On Going', 'On Going'), ('Discontinue', 'Discontinue'), ('Completed', 'Completed')], default='On Going', max_length=20),
        ),
        migrations.AddField(
            model_name='emi_4',
            name='class_status',
            field=models.CharField(choices=[('Yet To Start', 'Yet To Start'), ('On Going', 'On Going'), ('Discontinue', 'Discontinue'), ('Completed', 'Completed')], default='On Going', max_length=20),
        ),
        migrations.AddField(
            model_name='emi_5',
            name='class_status',
            field=models.CharField(choices=[('Yet To Start', 'Yet To Start'), ('On Going', 'On Going'), ('Discontinue', 'Discontinue'), ('Completed', 'Completed')], default='On Going', max_length=20),
        ),
        migrations.AddField(
            model_name='emi_6',
            name='class_status',
            field=models.CharField(choices=[('Yet To Start', 'Yet To Start'), ('On Going', 'On Going'), ('Discontinue', 'Discontinue'), ('Completed', 'Completed')], default='On Going', max_length=20),
        ),
        migrations.AddField(
            model_name='singlepayment',
            name='class_status',
            field=models.CharField(choices=[('Yet To Start', 'Yet To Start'), ('On Going', 'On Going'), ('Discontinue', 'Discontinue'), ('Completed', 'Completed')], default='On Going', max_length=20),
        ),
        migrations.AlterField(
            model_name='singlepayment',
            name='date',
            field=models.DateField(blank=True, null=True),
        ),
    ]
