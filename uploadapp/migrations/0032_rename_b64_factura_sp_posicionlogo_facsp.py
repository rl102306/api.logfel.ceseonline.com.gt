# Generated by Django 4.0.4 on 2023-06-22 11:55

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('uploadapp', '0031_rename_size_posicionlogo_size_logo_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='posicionlogo',
            old_name='B64_Factura_SP',
            new_name='facsp',
        ),
    ]