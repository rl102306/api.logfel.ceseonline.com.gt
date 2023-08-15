import base64
import datetime
import sqlite3
import io
import urllib.parse
import webbrowser
from django.shortcuts import redirect
import qrcode
import json
import requests
import os
from PIL import Image

from .serializers import FileSerializer,PosicionSerializer,EmpresaSerializer,ProfileSeriaizer, SuscripcionSerializer,HistoriaSuscripcionSerializer,UserSerializar,SubMensualDataRegistrationSerializer #,GetUserCompany,

from PyPDF2 import PdfFileReader, PdfFileWriter
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from rest_framework.views import APIView
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.parsers import FileUploadParser
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.sessions.models import Session
from django.contrib.auth.models import User 
from uploadapp.authentication_mixins import Authentication


class FileUploadView(Authentication,APIView):
    
    def post (self, request, *args, **kwargs):
 
        Request_Data = request.data
        Dict_Data_To_Json = json.dumps(Request_Data)
        Load_Json_Data = json.loads(Dict_Data_To_Json)
        B64_Factura_SP = Load_Json_Data['FAC_SP_B64']
        Str_Usuario = self.user

        data = {
            'B64_Factura_SP': B64_Factura_SP,
            'Str_Usuario': str(Str_Usuario)
        }
        file_serializer = FileSerializer(data = data)
        
        if file_serializer.is_valid():
            
            file_serializer.save()
                        
            return Response({'sucess': 'Archivo cargado con éxito.'}, status=status.HTTP_201_CREATED)
        
        else:

            return Response({'error': 'Ocurrio un error al cargar el archivo.'}, status=status.HTTP_400_BAD_REQUEST)
        

class UserRegistrationView(APIView):

    def post(self,request, *args, **kwargs):

            Request_Data = request.data
            Dict_Data_To_Json = json.dumps(Request_Data)
            Load_Json_Data = json.loads(Dict_Data_To_Json)
            nombre = Load_Json_Data['Name']
            password = Load_Json_Data['Pass']
            email = Load_Json_Data['Email']
            username = Load_Json_Data['User']
            apellido = Load_Json_Data['Apellido']    
            isactive = True

            if User.objects.filter(username=username).exists():

               return Response('190',status=status.HTTP_409_CONFLICT)

            else:
                usernew = User.objects.create_user(
                    username = username,
                    email = email,
                    password = password,
                    first_name = nombre,
                    last_name= apellido,
                    is_active = isactive
                )
                return Response(status=status.HTTP_201_CREATED)
           

class FileSend(Authentication,APIView):

    def post(self,request, *args, **kwargs):

        Request_Data = request.data
        Dict_Data_To_Json = json.dumps(Request_Data)
        Load_Json_Data = json.loads(Dict_Data_To_Json)
        
        username = str(self.user)
        posicion_logo = Load_Json_Data['posicion']
        B64_Factura_SP = Load_Json_Data['facsp']
        size_logo = Load_Json_Data['size_logo']
        link_qr_code = Load_Json_Data['linkqrcod']
        slogan = Load_Json_Data['slogan']
        fecha = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        #fields = ('id','posicion','url','usuario','fecha','linkqrcod','slogan')

        data = {

            'posicion' : posicion_logo,
            'facsp' : B64_Factura_SP,
            'usuario' : username,
            'size_logo' : size_logo,
            'linkqrcod' : link_qr_code,
            'slogan' : slogan,
            'fecha' : fecha
        }

        posicion_serializer = PosicionSerializer(data = data)
        
        if posicion_serializer.is_valid():

            Logo_Empresa = PosicionSerializer.Get_Logo_Empresa(str(self.user))
            base64_data = B64_Factura_SP.split(";base64,")[-1]

            B64_Logo_Data = Logo_Empresa.split(";base64,")[-1]
            
            pdf_base64 = base64_data
            imagen_base64 = B64_Logo_Data
            
            # Decodificar el PDF y la imagen en base64
            pdf_bytes = base64.b64decode(pdf_base64)
            imagen_bytes = base64.b64decode(imagen_base64)

            # Crear un objeto PDFFileReader para el PDF existente
            pdf_reader = PdfFileReader(io.BytesIO(pdf_bytes))

            # Crear un objeto PDFFileWriter para el PDF de salida
            pdf_writer = PdfFileWriter()

            # Crear un lienzo con la imagen
            lienzo = canvas.Canvas("temp.pdf", pagesize=letter)
            imagen = ImageReader(io.BytesIO(imagen_bytes))


            if link_qr_code :
                Img_Cod_QR = CodigoQR.Genera_Codigo_QR(link_qr_code)
                imagen_bytes_qr = base64.b64decode(Img_Cod_QR)
                imagen_qr = ImageReader(io.BytesIO(imagen_bytes_qr))
                lienzo.drawImage(imagen_qr,175,150,270,100,preserveAspectRatio=True)

            else:
                print("No tiene nada")
                    
            if slogan :
                radius=inch/3.0
                xcenter=4.2*inch
                ycenter=3.5*inch
                lienzo.drawCentredString(xcenter, ycenter+1.3*radius, slogan)

            else: 
                print("No tiene nada")
            
            if posicion_logo == 'derecha':

                if size_logo == 'grande':

                    x = (8.5 * 72) - 260
                    y = (11 * 72) - 85
                    lienzo.drawImage(imagen, x, y, 260, 85,preserveAspectRatio=True)
                    lienzo.showPage()
                    lienzo.save()

                if size_logo == 'medio':

                    x = (8.5 * 72) - 270
                    y = (10.1 * 72) - 12

                    lienzo.drawImage(imagen, x, y, 230, 70,preserveAspectRatio=True)
                    lienzo.showPage()
                    lienzo.save()

                if size_logo == 'peque':

                    x = (8.5 * 72) - 250
                    y = (10.1 * 72) - 5
                    lienzo.drawImage(imagen, x, y, 180, 40,preserveAspectRatio=True)
                    lienzo.showPage()
                    lienzo.save()

            elif posicion_logo  == 'izquierda':

                if size_logo == 'grande':
                    x = 0.10 * 72
                    y = 9.85 * 72

                    lienzo.drawImage(imagen, x, y, 230, 80,preserveAspectRatio=True)
                    lienzo.showPage()
                    lienzo.save()
                    #logo.drawImage(logfilecp, 29, 700, 260, 110,preserveAspectRatio=True)
                    #logo.save()

                if size_logo == 'medio':
                    x = 0.10 * 72
                    y = 8.00 * 72
                    lienzo.drawImage(imagen, 29, 710, 215, 70,preserveAspectRatio=True)
                    lienzo.showPage()
                    lienzo.save()
                    
                    #logo.drawImage(logfilecp, 29, 710, 230, 80,preserveAspectRatio=True)
                    #logo.save()

                if size_logo == 'peque':

                    x = 0.10 * 72
                    y = 10.10 * 72
                    lienzo.drawImage(imagen, x, y, 180, 40,preserveAspectRatio=True)
                    lienzo.showPage()
                    lienzo.save()
                    
            # Obtener la primera página del PDF existente
            pagina = pdf_reader.getPage(0)

            # Leer el PDF temporal y agregar la página con la imagen al PDF de salida
            
            temp_pdf = open("temp.pdf", "rb")
            
            temp_pdf_reader = PdfFileReader(temp_pdf)
            
            pagina_con_imagen = temp_pdf_reader.getPage(0)

            pagina.mergePage(pagina_con_imagen)

            pdf_writer.addPage(pagina)

            #pdf_writer.addPage(pagina_con_imagen)

            paginas = pdf_reader.numPages

            reales = paginas - 1

            # Agregar las páginas restantes del PDF existente al PDF de salida
            for i in range(1, reales ):
                print(i)
                #pagina_r = pdf_reader.getPage(i)
                #pagina.mergePage(pagina_r)
                #pdf_writer.addPage(pagina)
                
                #Archivo Original    
                pagina = pdf_reader.getPage(i)
                #Archivo Temporal
                pagina_con_imagen = temp_pdf_reader.getPage(0)

                #Union Pagina            
                pagina.mergePage(pagina_con_imagen)

                #Escribir
                pdf_writer.addPage(pagina)

            # Crear un archivo de salida en memoria
            output_pdf = io.BytesIO()

            # Guardar el PDF de salida en el archivo de salida
            pdf_writer.write(output_pdf)

            # Cerrar los archivos temporales
            temp_pdf.close()

            # Obtener el contenido del PDF de salida en base64
            output_pdf_base64 = base64.b64encode(output_pdf.getvalue()).decode("utf-8")

            # Imprimir el PDF de salida en base64
            #print(output_pdf_base64)

            #print(output_pdf_base64)

            posicion_serializer.save()

            return Response({'facyp': output_pdf_base64}, status=status.HTTP_200_OK)
        
        else:

            return Response({'error' : "Ocurrio un error al validar la informacion"} , status=status.HTTP_400_BAD_REQUEST)
        
            
class UserToken (Authentication,APIView):
    def get (self,request,*args , **kwargs):
        try: 
            user_token,_ = Token.objects.get_or_create(user = self.user)
            user = UserSerializar(self.user)
            return Response({
                'token' : user_token.key,
                'user' :  user.data
            })
        except:
            return Response({
                'error': 'credenciales enviadas incorrectas'
            } , status=status.HTTP_400_BAD_REQUEST)
        
class LoginView(ObtainAuthToken):
    def post(self,request,*args,**kwargs):
        
        login_serializer = self.serializer_class(data = request.data , context = {'request': request})
        if login_serializer.is_valid():
            user = login_serializer.validated_data['user']
            if user.is_active:
                token,created = Token.objects.get_or_create(user = user)
                user_serializer = UserSerializar(user)
                if created:

                    Id_Usuario = user_serializer.data['id']
                    BUSP = UserSuscripcion.UserSub(Id_Usuario)
                    print(BUSP)
                    return Response({
                        'token' : token.key,
                        'user' : user_serializer.data,
                        'message' : 'Inicio de Sesión Exitoso.',
                        'busp' : BUSP

                    },status=status.HTTP_201_CREATED)
                else:
                    all_sessions = Session.objects.filter(expire_date__gte =datetime.datetime.now())
                    if all_sessions.exists():
                        for session in all_sessions:
                            session_data = session.get_decoded()
                            if session_data.get('_auth_user_id') is None:
                                print("None")
                            elif user.id == int(session_data.get('_auth_user_id')):
                                session.delete()
                    token.delete()
                    token = Token.objects.create(user = user)

                    Id_Usuario = user_serializer.data['id']

                    BUSP = UserSuscripcion.UserSub(Id_Usuario)                    
                    print(BUSP)
                           
                    return Response(
                        {
                        'token' : token.key,
                        'user' : user_serializer.data,
                        'message' : 'Inicio de Sesión Exitoso.',
                        'busp' : BUSP
                        },status=status.HTTP_201_CREATED)
            else:
                return Response({'error': 'Este usuario no puede iniciar sesion'} , status= status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'error' : 'Nombre de usuario o contraseña incorrecto.'} , status = status.HTTP_400_BAD_REQUEST)


class UserSuscripcion:
                
    def UserSub(Id_Usuario):
        Suscripcion_Existe = SuscripcionSerializer.Existe_Suscripcion_Usuario(Id_Usuario)
        Perfil_S = ProfileSeriaizer.EM_Usuario_Empresa(Id_Usuario)                       
        if Suscripcion_Existe:
            print("Existe Suscripcion")
            Estado_Suscripcion = SuscripcionSerializer.Estado_Suscripcion(Id_Usuario)
            if Estado_Suscripcion:
                print("Estado de suscription activa")
                Tipo_Suscripcion = SuscripcionSerializer.Tipo_Suscripcion(Id_Usuario)
                if Tipo_Suscripcion == 'Mensual':
                    print("Mensual")
                    Fecha_Suscripcion = SuscripcionSerializer.Fecha_Suscripcion_Usuario(Id_Usuario)
                    Fecha_Actual = datetime.datetime.today().date()
                    Diferencia = Fecha_Suscripcion - Fecha_Actual
                    Diferencia_Dias = Diferencia.days
                    if Diferencia_Dias > 30:
                        print("La fecha es mayor a 30 días respecto a la fecha actual")
                        print("La fecha está dentro del rango de 30 días respecto a la fecha actual")
                        if Perfil_S:
                            BUSP = "PYACTMENSUALEMP"
                        else:
                            BUSP = "PYACTMENSUAL"
                    elif Diferencia_Dias < -30:
                        print("La fecha es menor a 30 días respecto a la fecha actual")
                        SuscripcionSerializer.Cancelar_Suscripcion_Usuario(Id_Usuario)
                        BUSP = "PYVENMENSUAL"
                    else:
                        print("La fecha está dentro del rango de 30 días respecto a la fecha actual")
                        #Existe_Empresa = ProfileSeriaizer.Existe_Usuario_Empresa(Id_Usuario)
                        print("Ahora valido si hay empresa creada")
                        if Perfil_S:
                            BUSP = "PYACTMENSUALEMP"
                        else:
                            BUSP = "PYACTMENSUAL"

                elif Tipo_Suscripcion == 'Free':
                    Fecha_Suscripcion = SuscripcionSerializer.Fecha_Suscripcion_Usuario(Id_Usuario)
                    Fecha_Actual = datetime.datetime.today().date()
                    Diferencia = Fecha_Suscripcion - Fecha_Actual
                    Diferencia_Dias = Diferencia.days

                    if Diferencia_Dias > 15:
                        print("La fecha es mayor a 15 días respecto a la fecha actual")
                        #Existe_Empresa = ProfileSeriaizer.Existe_Usuario_Empresa(user.id)
                        print("Ahora valido si hay empresa creada")

                        if Perfil_S:
                            BUSP = "PYACTFREEEMP"
                        else:
                            BUSP = "PYACTFREE"

                    elif Diferencia_Dias < -15:
                        print("La fecha es menor a 15 días respecto a la fecha actual")
                        print("El plan free ya vencio debe renovar de nuevo")
                        SuscripcionSerializer.Cancelar_Suscripcion_Usuario(Id_Usuario)
                        BUSP = "PYVENFREE"

                    else:
                        print("La fecha está dentro del rango de 15 días respecto a la fecha actual")
                        print("Ahora valido si hay empresa creada")
                        if Perfil_S:
                            BUSP = "PYACTFREEEMP"
                        else:
                            BUSP = "PYACTFREE"
            else:
                print("Estado de suscripcion inactiva")
                BUSP = "PYEXS0"
        else:
            print("No existe Suscripcion")
            BUSP = "PYNEXS1"
        
        return BUSP
        
class LogoutView(APIView):

    def get(self,request,*args,**kwargs):
            try:
                token = request.GET.get('token')
                token = Token.objects.filter(key = token).first()
                if token:
                    user = token.user
                    all_sessions = Session.objects.filter(expire_date__gte =datetime.datetime.now())
                    if all_sessions.exists():
                        for session in all_sessions:
                            session_data = session.get_decoded()
                            if session_data.get('_auth_user_id') is None:
                                print("None")
                            elif user.id == int(session_data.get('_auth_user_id')):
                                session.delete()
                    token.delete()
                    session_message = 'Sesiones de usuario eliminadas'
                    token_message = 'Token eliminado'
                    return Response(
                        {
                            'token_message' : token_message , 
                            'session_message': session_message
                        },
                            status=status.HTTP_200_OK
                        )
                return Response(
                        {
                            'error' : 'No se ha encontrado un usuario con estas credenciales'
                        },
                             status=status.HTTP_400_BAD_REQUEST
                        )
            except:

                return Response(
                        {
                            'error' : 'No se ha encontrado token en la peticion.'
                        },
                            status=status.HTTP_409_CONFLICT
                        )
            


class CompanyRegistrationView(Authentication,APIView): 

    def post(self,request, *args, **kwargs):
        
        company_serializer = EmpresaSerializer(data = request.data)

        user = UserSerializar(self.user)

        Id_User = user.data['id']

        Perfil_S = ProfileSeriaizer.EM_Usuario_Empresa(Id_User)

        if Perfil_S :

            return Response({'error': 'El usuario no puede tener mas de dos empresas asignadas'} , status=status.HTTP_400_BAD_REQUEST)

        else:
        
            if company_serializer.is_valid():
            
                company_serializer.save()

                if company_serializer.data:

                
                    data = {
                        'user' : Id_User,
                        'empresa' : company_serializer.data['id']
                    }     

                    Perfil_S = ProfileSeriaizer(data = data)

                    if Perfil_S.is_valid():
                            Perfil_S.save()
                    else:
                        return Response({'error': 'Ocurrió un error al crear el perfil'} , status=status.HTTP_400_BAD_REQUEST)

                return Response(company_serializer.data,status=status.HTTP_201_CREATED)
            else:
                return Response(company_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GUC(APIView): 
    def get(self, request, *args, **kwargs):
        if request.method == 'GET':
            data = request.data
            iduid=request.POST['uid']
            guc_serializer = GetUserCompany.getuc(iduid)
            data = json.loads(guc_serializer)
            for key, value in data[0].items():
                print(key+":"+str(value))
            json_string = json.dumps(guc_serializer)
        return Response(guc_serializer)


class CodigoQR(APIView):

    def Genera_Codigo_QR(Link_QR_Cod):
        qr = qrcode.QRCode(
            version = 1,
            error_correction = qrcode.constants.ERROR_CORRECT_H,
            box_size = 10,
            border = 4
        )
        # Podemos crear la informacion que queremos 
        # en el codigo de manera separada
        info = Link_QR_Cod
        # Agregamos la informacion
        qr.add_data(info)
        qr.make(fit=True)
        # Creamos una imagen para el objeto código QR
        imagen = qr.make_image()


        # Convertir la imagen en un objeto de bytes
        buffer = io.BytesIO()
        imagen.save(buffer, format='PNG')
        buffer.seek(0)
        # Codificar el objeto de bytes en base64
        base64_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
        # Imprimir el código QR en base64
        print(base64_image)
        #Str_Nombre_Img_Cod_QR = 'Codigo' + str(idulast) + '.png'
        # Guardemos la imagen con la extension que queramos
        #imagen.save('./media/'+Str_Nombre_Img_Cod_QR)
        #Ruta_File_Img_Cod_QR = './media/'+Str_Nombre_Img_Cod_QR
        return base64_image

class LoginEbiPay(APIView):

    def post(self, request):
        data = request.data
        URL = 'https://admlink.ebi.com.gt/api/login'
        data = requests.post(URL,data) 
        Json_Data = data.json()
        if (Json_Data['result'] == "success"):
            return Response(Json_Data,status=200,content_type="application/json")
        else:
            return Response(Json_Data,status=400,content_type="application/json")


class CodRedSocialEbiPay(APIView):

    def post(self, request):
        data = request.data
        print(data)
        URL = 'https://admlink.ebi.com.gt/api/network/all'
        data = requests.post(URL,data) 
        Json_Data = data.json()
        print(Json_Data)
        
        if (Json_Data['result'] == "success"):
            return Response(Json_Data,status=200,content_type="application/json")
        else:
            return Response(Json_Data,status=400,content_type="application/json")


class LinkEbiPay(APIView):

    def post(self, request):
        data = request.data
        URL = 'https://admlink.ebi.com.gt/api/link/maintenance'
        print(data)
        data = requests.post(URL,data) 
        Json_Data = data.json()
        print(Json_Data)
        if (Json_Data['result'] == "success"):
            return Response(Json_Data,status=200,content_type="application/json")
        else:
            return Response(Json_Data,status=400,content_type="application/json")

class PerfilEmpresaUsuario(APIView):
    def post(self, request, *args, **kwargs):
        if request.method == 'POST':
            Request_Data = request.data
            Dict_Data_To_Json = json.dumps(Request_Data)
            Load_Json_Data = json.loads(Dict_Data_To_Json)
            Id_Usuario = Load_Json_Data['usuario']
            Empresa_Existe = ProfileSeriaizer.Existe_Usuario_Empresa(Id_Usuario)
            Json_Empresa_Existe = {
                'Existe' : Empresa_Existe
            }
            return Response(Json_Empresa_Existe,status=200,content_type="application/json")
        else:
            return Response("Error",status=400,content_type="text/plain")


class Existe_Suscripcion_Usuario(APIView):
    def post(self, request, *args, **kwargs):
        if request.method == 'POST':
            Request_Data = request.data
            Dict_Data_To_Json = json.dumps(Request_Data)
            Load_Json_Data = json.loads(Dict_Data_To_Json)
            Id_Usuario = Load_Json_Data['usuario']
            Suscripcion_Existe = SuscripcionSerializer.Existe_Suscripcion_Usuario(Id_Usuario)
            Json_Suscripcion_Existe = {
                'Existe' : Suscripcion_Existe
            }
            return Response(Json_Suscripcion_Existe,status=200,content_type="application/json")
        else:
            return Response(Json_Suscripcion_Existe,status=400,content_type="application/json")

class EBIExitosoView(APIView):
    
    def post(self,request, *args, **kwargs):
        
        def decrypt(ciphertext, key, iv):
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            return decrypted.rstrip(b"\0").decode("utf-8")

        Request_Data = request.data
        Dict_Data_To_Json = json.dumps(Request_Data)
        Load_Json_Data = json.loads(Dict_Data_To_Json)
        token = Load_Json_Data['token']
        authorization = Load_Json_Data['authorization']
        amount = Load_Json_Data['amount']
        code = Load_Json_Data['code']
        audit = Load_Json_Data['audit']
        reference = Load_Json_Data['reference']
        key = b"1e63b2f7a01ddea85782dea27b46a04d"
        method = "aes-256-cbc"
        iv = base64.b64decode("ziwVz5mWmPp7qse7s1Uy/A==")
        # Ajustar la clave a la longitud adecuada
        key = key.ljust(32, b'\0')
        d_authorization = decrypt(base64.b64decode(authorization), key, iv)
        d_amount = decrypt(base64.b64decode(amount), key, iv)
        d_audit = decrypt(base64.b64decode(audit), key, iv)
        d_reference = decrypt(base64.b64decode(reference), key, iv)
        # Eliminar caracteres no imprimibles y caracteres de relleno de d_reference
        d_reference = ''.join(c for c in d_reference if ord(c) >= 32 and ord(c) <= 126)
        d_authorization = ''.join(c for c in d_authorization if ord(c) >= 32 and ord(c) <= 126)
        d_audit = ''.join(c for c in d_audit if ord(c) >= 32 and ord(c) <= 126)
        d_amount = ''.join(c for c in d_amount if ord(c) >= 32 and ord(c) <= 126)
        print("Si llego aca")

        data = {
            "autorizacion": d_authorization,
            "monto": d_amount,
            "codigo": code,
            "auditoria": d_audit,
            "referencia": d_reference,
            "token": token
        }

        data_ = {
            "autorizacion": d_authorization,
            "monto": d_amount,
            "codigo": code,
            "auditoria": d_audit,
            "referencia": d_reference,
            "token": token,
            "user" : ""
        }

        SubMensualDataRegistrationSerializer(data = data_).save()
        
        encoded_data = urllib.parse.quote(json.dumps(data))
        url = f'https://logfel.ceseonline.com.gt/pex?data={encoded_data}'
        webbrowser.open(url)
        print(url)
        return redirect(url)

class EBIRechazoView(APIView): 

    def post(self,request, *args, **kwargs):

        data = request.data

        return redirect('https://logfel.ceseonline.com.gt/pre')
    
        #return Response(data, status = status.HTTP_400_BAD_REQUEST)
    
    '''    suscripcion_serializer = SuscripcionSerializer(data = request.data)
        if suscripcion_serializer.is_valid():
            suscripcion_serializer.save()
            return Response(suscripcion_serializer.data,status=status.HTTP_201_CREATED)
        else:
            return Response(suscripcion_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    '''

class SuscripcionRegistrationView(APIView): 
    def post(self,request, *args, **kwargs):
        suscripcion_serializer = SuscripcionSerializer(data = request.data)
        if suscripcion_serializer.is_valid():
            suscripcion_serializer.save()
            return Response(suscripcion_serializer.data,status=status.HTTP_201_CREATED)
        else:
            return Response(suscripcion_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SubMensualDataRegistrationView(APIView): 

    def post(self,request, *args, **kwargs):

        submensualdata_serializer = SubMensualDataRegistrationSerializer(data = request.data)
        if SubMensualDataRegistrationSerializer.is_valid():
            submensualdata_serializer.save()
            return Response(submensualdata_serializer.data,status=status.HTTP_201_CREATED)
        else:
            return Response(submensualdata_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

'''
class CPUsuarioEmpresa(APIView):
    def post(self,request, *args, **kwargs):
        perfil_serializer = ProfileSeriaizer(data = request.data)
        if perfil_serializer.is_valid():
            perfil_serializer.save()
            return Response(perfil_serializer.data,status=status.HTTP_201_CREATED)
        else:
            return Response(perfil_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
'''
class Estado_Suscripcion(APIView):
    def post(self, request, *args, **kwargs):
        if request.method == 'POST':
            Request_Data = request.data
            Dict_Data_To_Json = json.dumps(Request_Data)
            Load_Json_Data = json.loads(Dict_Data_To_Json)
            Id_Usuario = Load_Json_Data['usuario']
            Estado_Suscripcion = SuscripcionSerializer.Estado_Suscripcion(Id_Usuario)
            Json_Estado_Suscripcion = {
                'Estado' : Estado_Suscripcion
            }
            return Response(Json_Estado_Suscripcion,status=200,content_type="application/json")
        else:
            return Response("Error",status=400,content_type="text/plain")


class Historia_Suscripcion(APIView):
    def post(self, request, *args, **kwargs):
        if request.method == 'POST':
            Request_Data = request.data
            Dict_Data_To_Json = json.dumps(Request_Data)
            Load_Json_Data = json.loads(Dict_Data_To_Json)
            Id_Usuario = Load_Json_Data['usuario']
            Historia_Suscripcion = SuscripcionSerializer.Obtener_Informacion_Historia_Suscripcion(Id_Usuario)
            Registrar_Historia_Serializer = HistoriaSuscripcionSerializer(data = Historia_Suscripcion)
            if Registrar_Historia_Serializer.is_valid():
                Registrar_Historia_Serializer.save()
            return Response(Registrar_Historia_Serializer.data,status=200,content_type="application/json")
        else:
            return Response("Ocurrio un error al renovar la suscripcion.",status=400,content_type="text/plain")

class SuscripcionUpdateView(APIView): 
    def post(self,request, *args, **kwargs):
        try:
            sqliteConnection = sqlite3.connect('db.sqlite3')
            cursor = sqliteConnection.cursor()
            Request_Data = request.data
            Dict_Data_To_Json = json.dumps(Request_Data)
            Load_Json_Data = json.loads(Dict_Data_To_Json)
            user = Load_Json_Data['user']
            tipo = Load_Json_Data['tipo']
            fecha = Load_Json_Data['fecha']
            estado = Load_Json_Data['estado']
            sql_update_query = """Update uploadapp_suscripcion set tipo = ?, fecha = ?,estado=? where user_id = ?"""
            data = (tipo,fecha,estado,user)
            cursor.execute(sql_update_query,data)
            sqliteConnection.commit()
            cursor.close()
            Json_Respuesta_Renovacion = {
                "estado" : "Exito",
                "codigo" : 200,
                "msj" : "La suscripcion se ha renovado exitosamente."
            }
            return Response(Json_Respuesta_Renovacion,status=status.HTTP_201_CREATED)
        except sqlite3.Error as error:
            return Response(error, status=status.HTTP_400_BAD_REQUEST)
        finally:
            if sqliteConnection:
                sqliteConnection.close()