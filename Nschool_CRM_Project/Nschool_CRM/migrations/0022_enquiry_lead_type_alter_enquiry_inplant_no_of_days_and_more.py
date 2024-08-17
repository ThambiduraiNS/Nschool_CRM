# Generated by Django 4.2.13 on 2024-08-15 13:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0021_alter_enquiry_date_of_birth_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='enquiry',
            name='lead_type',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='enquiry',
            name='inplant_no_of_days',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='enquiry',
            name='inplant_no_of_students',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]
