# Generated by Django 4.0.4 on 2022-04-29 20:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('uploadapp', '0018_posicionlogo_slogan'),
    ]

    operations = [
        migrations.AlterField(
            model_name='posicionlogo',
            name='linkqrcod',
            field=models.CharField(max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='posicionlogo',
            name='slogan',
            field=models.CharField(max_length=500, null=True),
        ),
    ]
