# Generated by Django 4.0.4 on 2023-06-22 10:16

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('uploadapp', '0030_remove_file_int_id_usuario_file_str_usuario'),
    ]

    operations = [
        migrations.RenameField(
            model_name='posicionlogo',
            old_name='size',
            new_name='size_logo',
        ),
        migrations.RemoveField(
            model_name='posicionlogo',
            name='url',
        ),
        migrations.AddField(
            model_name='posicionlogo',
            name='B64_Factura_SP',
            field=models.TextField(default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='empresa',
            name='logo',
            field=models.TextField(default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
