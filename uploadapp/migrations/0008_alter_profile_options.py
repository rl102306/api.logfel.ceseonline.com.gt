# Generated by Django 3.2.4 on 2021-09-14 02:44

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('uploadapp', '0007_alter_profile_table'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='profile',
            options={'verbose_name': 'Profile', 'verbose_name_plural': 'Profiles'},
        ),
    ]
