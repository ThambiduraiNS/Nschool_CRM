# Generated by Django 4.2.13 on 2024-08-06 05:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Nschool_CRM', '0008_alter_newuser_contact'),
    ]

    operations = [
        migrations.AlterField(
            model_name='newuser',
            name='username',
            field=models.CharField(default=None, max_length=50),
        ),
    ]
