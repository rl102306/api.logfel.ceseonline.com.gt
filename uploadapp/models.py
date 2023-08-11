from django.db import models

from django.contrib.auth.models import User

class File(models.Model):
    #file = models.FileField(blank=False, null=False)
    B64_Factura_SP = models.TextField()  
    #file = models.CharField(max_length=2500 , null = True)
    Str_Usuario = models.TextField()
    def __str__(self):
        return str(self.Str_Usuario) 

class PosicionLogo(models.Model):

    id = models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')
    posicion = models.CharField(max_length=75, null=True)
    facsp = models.TextField()
    usuario = models.CharField(max_length=50,null=True)
    size_logo =  models.CharField(max_length=75,null=True)
    linkqrcod = models.CharField(max_length=500,null=True)
    slogan = models.CharField(max_length=500,null=True)
    fecha = models.CharField(max_length=75,null=True)

    def __str__(self):

        return str(self.usuario)
    
class Empresa(models.Model):

    id = models.AutoField(auto_created=True, primary_key=True,serialize=False,verbose_name='ID')
    nombre = models.CharField(max_length=100, null=True)
    nit = models.CharField(max_length=100,null=True)
    direccion = models.CharField(max_length=100, null=True)
    logo = models.TextField()
    #estado = models.BooleanField(default=False)

    def __str__(self):

        return str(self.nombre) + " - " + str(self.nit) + " - "

class Profile(models.Model):
    id = models.AutoField(auto_created=True, primary_key=True,serialize=False,verbose_name='ID')
    user = models.ForeignKey(User,null=True,blank=True,on_delete=models.CASCADE)
    empresa = models.ForeignKey(Empresa,null=True,blank=True,on_delete=models.CASCADE)
    def __str__(self):
        return str(self.id) + " - " + str(self.user) + " - " + str(self.empresa)
    class Meta:
        verbose_name = 'Profile'
        verbose_name_plural = 'Profiles'

class Suscripcion(models.Model):

    id = models.AutoField(auto_created=True, primary_key=True,serialize=False,verbose_name='ID')
    user = models.ForeignKey(User,null=True,blank=True,on_delete=models.CASCADE)
    tipo = models.CharField(max_length=100, null=True)
    fecha = models.DateField(null=True)
    estado = models.BooleanField(null=True)

    def __str__(self):
        
        return str(self.id) + " - " + str(self.user) + " - " + str(self.tipo) + " - " + str(self.fecha) + " - " + str(self.estado)

    class Meta:

        verbose_name = 'Suscripcion'
        verbose_name_plural = 'Suscripciones'


class Historia_Suscripcion(models.Model):

    id = models.AutoField(auto_created=True, primary_key=True,serialize=False,verbose_name='ID')
    user = models.CharField(max_length=100, null=True)
    tipo = models.CharField(max_length=100, null=True)
    fecha = models.DateField(null=True)

    def __str__(self):
        
        return str(self.id) + " - " + str(self.user) + " - " + str(self.tipo) + " - " + str(self.fecha)

    class Meta:

        verbose_name = 'Historia Suscripcion'
        verbose_name_plural = 'Historia Suscripciones'

class Suscripcion_Mensual_Info_Historico(models.Model):

    id = models.AutoField(auto_created=True, primary_key=True,serialize=False,verbose_name='ID')
    user = models.ForeignKey(User,null=True,blank=True,on_delete=models.CASCADE)
    autorizacion = models.CharField(max_length=100, null=True)
    fecha = models.CharField(max_length=100, null=True)
    monto = models.CharField(max_length=100, null=True)
    referencia = models.CharField(max_length=100, null=True)
    codigo = models.CharField(max_length=100, null=True)
    auditoria = models.CharField(max_length=100, null=True)
    
    
    def __str__(self):
        
        return str(self.id) + " - " + str(self.user) + " - " + str(self.autorizacion) + " - " + str(self.fecha) + " - " + str(self.monto)

    class Meta:

        verbose_name = 'Suscripcion Mensual'
        verbose_name_plural = 'Suscripciones Mensuales'
