# Generated by Django 3.2.4 on 2022-04-11 04:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('uploadapp', '0015_posicionlogo_size'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='empresa',
            name='cantidad_facturas_mensual',
        ),
        migrations.RemoveField(
            model_name='empresa',
            name='slogan',
        ),
        migrations.AlterField(
            model_name='empresa',
            name='estado',
            field=models.BooleanField(default=False),
        ),
    ]