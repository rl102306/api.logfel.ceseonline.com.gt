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
]