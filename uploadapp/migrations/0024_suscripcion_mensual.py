# Generated by Django 4.0.4 on 2023-06-12 22:36

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('uploadapp', '0023_alter_historia_suscripcion_user'),
    ]

    operations = [
        migrations.CreateModel(
            name='Suscripcion_Mensual',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('autorizacion', models.CharField(max_length=100, null=True)),
                ('fecha', models.DateField(null=True)),
                ('monto', models.CharField(max_length=100, null=True)),
                ('referencia', models.CharField(max_length=100, null=True)),
                ('codigo', models.CharField(max_length=100, null=True)),
                ('auditoria', models.CharField(max_length=100, null=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Suscripcion Mensual',
                'verbose_name_plural': 'Suscripciones Mensuales',
            },
        ),
    ]