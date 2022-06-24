from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from .views import *

urlpatterns = [
    path('File_Upload_Fact_Ini/post', FileUploadView.as_view()),
    path('Posicion_Size/post', FileSend.as_view()),
    path('signup/post',UserRegistrationView.as_view()),
    path('login/post',UserLoginView.as_view()),
    path('company/post',CompanyRegistrationView.as_view()),
    path('user/post',UserRegistrationView.as_view()),
    path('guc/get',GUC.as_view()),
    path('token/auth', obtain_auth_token),
    path('codigoqr', CodigoQR.as_view()),
    path('login_ebi', LoginEbiPay.as_view(),),
    path('cod_red_social_ebi',CodRedSocialEbiPay.as_view(),),
    path('link_ebi_pay',LinkEbiPay.as_view()),
    path('empresa_existe/post',PerfilEmpresaUsuario.as_view()),
    path('suscripcion_existe',Existe_Suscripcion_Usuario.as_view()),
    path('registrar_suscripcion',SuscripcionRegistrationView.as_view()),
    path('crear_perfil',CPUsuarioEmpresa.as_view()),
    path('estado_suscripcion',Estado_Suscripcion.as_view()),
    path('historia_suscripcion',Historia_Suscripcion.as_view()),
    path('renovar_suscripcion',SuscripcionUpdateView.as_view()),
    
]