# Generated by Django 4.0.4 on 2023-06-22 21:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('uploadapp', '0035_alter_posicionlogo_fecha_alter_posicionlogo_posicion_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='suscripcion_mensual_info_historico',
            name='fecha',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
