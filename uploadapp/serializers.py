from rest_framework import serializers
from rest_framework.utils import field_mapping

from .models import File, PosicionLogo , User , Empresa, Profile, Suscripcion,Historia_Suscripcion

class FileSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = File
        fields = "__all__"

    def last():
        rutalast = File.objects.order_by('id').last()
        return rutalast


class PosicionSerializer(serializers.ModelSerializer):

    class Meta:
        model = PosicionLogo
        fields = ('id','posicion','url','usuario','fecha','linkqrcod','slogan')

    def getlogourl(uid):
        idcompany = Profile.objects.get(user_id = uid).empresa_id
        logoc = Empresa.objects.get(id = idcompany)
        url = logoc.logo.url
        return url

    def idurllast(urlast):
        idurlast = PosicionLogo.objects.get(url = urlast).id
        return idurlast

class UserSerializar(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id','nombre','correo','estado',
        'password')


class EmpresaSerializer(serializers.ModelSerializer):

    class Meta:
        model = Empresa
        fields = ('id','nombre','nit','direccion',
        'logo', 'estado'
        )

class ProfileSeriaizer(serializers.ModelSerializer):

    class Meta:
        model = Profile
        fields = ('id','user','empresa')

    def Existe_Usuario_Empresa(UserId):
        try:
            Profile.objects.get(user_id = UserId).empresa_id
            EmpresaExiste = True
        except Profile.DoesNotExist:
            EmpresaExiste = False
        return EmpresaExiste

class GetUserCompany():

    def getuc(uid):
        from django.core import serializers
        userid = serializers.serialize('json', Profile.objects.filter(user_id=uid),
        fields = ('empresa'))
        test = Profile.objects.get(user_id = uid).empresa_id
        return userid


class SuscripcionSerializer(serializers.ModelSerializer):

    class Meta:
        model = Suscripcion
        fields = ('id','user','tipo','fecha','estado')

    def Existe_Suscripcion_Usuario(UserId):
        try:
            Suscripcion.objects.get(user_id = UserId)
            SuscripcionExiste = True
        except Suscripcion.DoesNotExist:
            SuscripcionExiste = False
        return SuscripcionExiste

    def Estado_Suscripcion(UserId):

        Estado_Sus = Suscripcion.objects.get(user_id = UserId).estado

        return Estado_Sus

    def Obtener_Informacion_Historia_Suscripcion(UserId):

        Usuario = Suscripcion.objects.get(user_id = UserId).user
        Str_Usuario = str(Usuario)
        Tipo = Suscripcion.objects.get(user_id = UserId).tipo
        Fecha = Suscripcion.objects.get(user_id = UserId).fecha

        
        Json_Historia_Suscripcion = {
            'user': Str_Usuario,
            'tipo' : Tipo,
            'fecha' : Fecha    
        }

        return Json_Historia_Suscripcion

class HistoriaSuscripcionSerializer(serializers.ModelSerializer):

    class Meta:
        model = Historia_Suscripcion
        fields = ('id','user','tipo','fecha')


        

