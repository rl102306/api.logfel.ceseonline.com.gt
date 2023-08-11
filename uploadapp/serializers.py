from rest_framework import serializers


from .models import File, PosicionLogo , User , Empresa, Profile, Suscripcion,Historia_Suscripcion,Suscripcion_Mensual_Info_Historico

class FileSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = File
        fields = ('B64_Factura_SP','Str_Usuario')

    def last():
        rutalast = File.objects.order_by('id').last()
        return rutalast


class PosicionSerializer(serializers.ModelSerializer):
    
    class Meta:
    
        model = PosicionLogo
    
        fields = ('id','posicion','facsp','usuario','size_logo','linkqrcod','slogan','fecha')

    def Get_Logo_Empresa(username):
        Id_Usuario = User.objects.get(username = username).id
        Id_Empresa = Profile.objects.get(user_id = Id_Usuario).empresa_id
        Logo_Empresa  = Empresa.objects.get(id = Id_Empresa).logo
        return Logo_Empresa

    def idurllast(urlast):
        idurlast = PosicionLogo.objects.get(url = urlast).id
        return idurlast

class UserSerializar(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id','username','email','first_name','last_name','is_active')

class EmpresaSerializer(serializers.ModelSerializer):

    class Meta:
        model = Empresa
        fields = ('id','nombre','nit','direccion','logo')

class ProfileSeriaizer(serializers.ModelSerializer):

    class Meta:
        model = Profile
        fields = ('id','user','empresa')

    def EM_Usuario_Empresa(UserId):
 
        try:
        
            Profile.objects.get(user_id = UserId)

            EmpresaUsuario = True
        
        except Profile.DoesNotExist:
        
            EmpresaUsuario = False

        except Profile.MultipleObjectsReturned:

            EmpresaUsuario = True
        
        return EmpresaUsuario

'''
class GetUserCompany():

    def getuc(uid):
        from django.core import serializers
        userid = serializers.serialize('json', Profile.objects.filter(user_id=uid),
        fields = ('empresa'))
        test = Profile.objects.get(user_id = uid).empresa_id
        return userid
'''

class SubMensualDataRegistrationSerializer(serializers.ModelSerializer):
     
    class Meta:
        model = Suscripcion_Mensual_Info_Historico
        fields = ('id','user','autorizacion','fecha','monto','referencia','codigo','auditoria')


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
    
    def Cancelar_Suscripcion_Usuario(UserId):

        Estado_Sus = Suscripcion.objects.get(user_id = UserId)
        Estado_Sus.estado = False
        Estado_Sus.save()
        return Estado_Sus

    
    def Fecha_Suscripcion_Usuario(UserId):
        Fecha_Sub = Suscripcion.objects.get(user_id = UserId).fecha
        return Fecha_Sub
    

    def Tipo_Suscripcion(UserId):
        Tipo_Sub = Suscripcion.objects.get(user_id = UserId).tipo
        return Tipo_Sub

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