from django.urls import path
from .views import *

from django.contrib.auth import views as auth_views

urlpatterns = [
    
    path('factura_sp', FileUploadView.as_view()),
    path('factura_yp', FileSend.as_view()),
    
    
    path('signup/post',UserRegistrationView.as_view()),
    
    
    
    path('login',LoginView.as_view()),
    path('logout',LogoutView.as_view()),
    path('refresh-token',UserToken.as_view()),

    
    path('empresa',CompanyRegistrationView.as_view()),
    
    path('user/post',UserRegistrationView.as_view()),
    path('guc/get',GUC.as_view()),
    
    
    
    path('codigoqr', CodigoQR.as_view()),
    path('login_ebi', LoginEbiPay.as_view(),),
    path('cod_red_social_ebi',CodRedSocialEbiPay.as_view(),),
    path('link_ebi_pay',LinkEbiPay.as_view()),
    path('empresa_existe',PerfilEmpresaUsuario.as_view()),
    
    path('ebi_exitoso', EBIExitosoView.as_view()),
    path('ebi_rechazo', EBIRechazoView.as_view()),
    
    #path('crear_perfil',CPUsuarioEmpresa.as_view()),
    
    

    path('suscripcion_existe',Existe_Suscripcion_Usuario.as_view()),
    path('registrar_suscripcion',SuscripcionRegistrationView.as_view()),
    path('estado_suscripcion',Estado_Suscripcion.as_view()),
    path('historia_suscripcion',Historia_Suscripcion.as_view()),
    path('renovar_suscripcion',SuscripcionUpdateView.as_view()),

    path('suscripcion_mensual_info',SubMensualDataRegistrationView.as_view()),
    
]