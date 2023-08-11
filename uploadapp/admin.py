from uploadapp.models import Empresa, PosicionLogo, File, Profile, Suscripcion , Historia_Suscripcion , Suscripcion_Mensual_Info_Historico


from django.contrib import admin


# Register your models here.
admin.site.register(Empresa)
admin.site.register(PosicionLogo)
admin.site.register(File)
admin.site.register(Profile)
admin.site.register(Suscripcion)
admin.site.register(Historia_Suscripcion)
admin.site.register(Suscripcion_Mensual_Info_Historico)