# Generated by Django 4.2.13 on 2024-08-26 07:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0041_alter_enrollment_course_name'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='enrollment',
            name='work_experience',
        ),
        migrations.AddField(
            model_name='enrollment',
            name='fathers_email_id',
            field=models.EmailField(blank=True, max_length=254, null=True),
        ),
        migrations.AddField(
            model_name='enrollment',
            name='nature_of_work',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='enrollment',
            name='place',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='enrollment',
            name='year_of_passed_out',
            field=models.PositiveIntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='enrollment',
            name='company_name',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='enrollment',
            name='date_of_birth',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='enrollment',
            name='designation',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='enrollment',
            name='father_name',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='enrollment',
            name='from_date',
            field=models.DateField(null=True),
        ),
        migrations.AlterField(
            model_name='enrollment',
            name='to_date',
            field=models.DateField(null=True),
        ),
    ]
