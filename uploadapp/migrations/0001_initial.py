# Generated by Django 3.2.4 on 2021-09-13 19:52

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Empresa',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nombre', models.CharField(max_length=100, null=True)),
                ('nit', models.CharField(max_length=100, null=True)),
                ('direccion', models.CharField(max_length=100, null=True)),
                ('logo', models.FileField(blank=True, null=True, upload_to='')),
                ('slogan', models.CharField(max_length=500, null=True)),
                ('cantidad_facturas_mensual', models.CharField(max_length=500)),
                ('estado', models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name='File',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(upload_to='')),
            ],
        ),
        migrations.CreateModel(
            name='PosicionLogo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('posicion', models.CharField(max_length=100, null=True)),
                ('url', models.CharField(max_length=200, null=True)),
                ('usuario', models.CharField(max_length=200, null=True)),
                ('fecha', models.DateField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nombre', models.CharField(max_length=100, null=True)),
                ('correo', models.EmailField(max_length=255, unique=True, verbose_name='Email')),
                ('estado', models.BooleanField(default=True)),
                ('password', models.CharField(max_length=100)),
            ],
        ),
    ]
