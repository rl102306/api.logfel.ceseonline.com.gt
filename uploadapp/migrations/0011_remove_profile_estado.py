# Generated by Django 3.2.4 on 2021-09-14 03:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('uploadapp', '0010_profile_estado'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='profile',
            name='estado',
        ),
    ]