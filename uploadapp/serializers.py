from rest_framework import serializers
from rest_framework.utils import field_mapping

from .models import File, PosicionLogo , User , Empresa, Profile

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
        fields = ('id','posicion','url','usuario','fecha')

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
        fields = ('id','user_id','empresa_id')


class GetUserCompany():

    def getuc(uid):
        from django.core import serializers
        userid = serializers.serialize('json', Profile.objects.filter(user_id=uid),
        fields = ('empresa'))
        test = Profile.objects.get(user_id = uid).empresa_id
        return userid

        

