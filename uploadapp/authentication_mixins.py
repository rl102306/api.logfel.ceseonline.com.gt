from rest_framework.authentication import get_authorization_header
from uploadapp.authentication import ExpiringTokenAuthentication
from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer
from rest_framework import status

class Authentication(object):


    user = None
    #user_token_expired = False

    def get_user(self,request):
        token = get_authorization_header(request).split()
        if token:
            try:
                token = token[1].decode()
            except:
                return None
            token_expire = ExpiringTokenAuthentication()
            user  = token_expire.authenticate_credentials(token)
            if user != None:
                self.user = user
                return user
        return None
    
    def dispatch(self,request,*args,**kwargs):
        user = self.get_user(request)
        if user is not None:
            return super().dispatch(request,*args, **kwargs)
            '''
            if type(user) == str:
                response =  Response({'error': user}, status=status.HTTP_401_UNAUTHORIZED )
                response.accepted_renderer = JSONRenderer()
                response.accepted_media_type = 'application/json'
                response.renderer_context = {}
                return response
            
            if not self.user_token_expired:
                return super().dispatch(request,*args, **kwargs)
            '''
        response =  Response({'error': 'No se han enviado las credenciales validas'}, status=status.HTTP_401_UNAUTHORIZED)
        response.accepted_renderer = JSONRenderer()
        response.accepted_media_type = 'application/json'
        response.renderer_context = {}
        return response