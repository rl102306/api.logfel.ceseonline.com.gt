# Generated by Django 4.0.4 on 2023-06-21 13:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('uploadapp', '0027_remove_file_file_file_b64_factura_sp_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='Str_Id_Usuario',
            field=models.IntegerField(null=True),
        ),
    ]
