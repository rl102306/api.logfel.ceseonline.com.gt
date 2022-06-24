from uploadapp.models import Empresa, PosicionLogo, File, Profile, Suscripcion , Historia_Suscripcion


from django.contrib import admin


# Register your models here.
admin.site.register(Empresa)
admin.site.register(PosicionLogo)
admin.site.register(File)
admin.site.register(Profile)
admin.site.register(Suscripcion)
admin.site.register(Historia_Suscripcion)
