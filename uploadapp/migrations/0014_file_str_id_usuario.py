# Generated by Django 3.2.4 on 2022-04-04 04:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('uploadapp', '0013_remove_profile_estado'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='Str_Id_Usuario',
            field=models.CharField(max_length=200, null=True),
        ),
    ]