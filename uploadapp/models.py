from django.db import models

from django.contrib.auth.models import User


#from django.core import serializers

class File(models.Model):

    file = models.FileField(blank=False, null=False)

    Str_Id_Usuario = models.CharField(max_length=200,null=True)

    def __str__(self):

        return self.file.name


class PosicionLogo(models.Model):

    id = models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')

    posicion = models.CharField(max_length=100, null=True)

    url = models.CharField(max_length=200,null=True)

    usuario = models.CharField(max_length=200,null=True)

    size =  models.CharField(max_length=200,null=True)

    fecha = models.DateField(null=True)

    def __str__(self):

        return self.posicion
    
class Empresa(models.Model):

    id = models.AutoField(auto_created=True, primary_key=True,serialize=False,verbose_name='ID')
    
    nombre = models.CharField(max_length=100, null=True)
    
    nit = models.CharField(max_length=100,null=True)
    
    direccion = models.CharField(max_length=100, null=True)
    
    logo = models.FileField(blank=True, null=True)

    estado = models.BooleanField(default=False)

    def __str__(self):

        return str(self.nombre)


class Profile(models.Model):

    id = models.AutoField(auto_created=True, primary_key=True,serialize=False,verbose_name='ID')

    user = models.ForeignKey(User,null=True,blank=True,on_delete=models.CASCADE)

    empresa = models.ForeignKey(Empresa,null=True,blank=True,on_delete=models.CASCADE)

    def __str__(self):

        return str(self.id)


    
    class Meta:

        verbose_name = 'Profile'

        verbose_name_plural = 'Profiles'





    




