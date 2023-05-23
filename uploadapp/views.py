import base64
import sqlite3
from urllib import response
from django.shortcuts import redirect
from rest_framework.parsers import FileUploadParser
from rest_framework.response import Response
from rest_framework import status
from uploadapp.models import Empresa
from .serializers import FileSerializer,PosicionSerializer,EmpresaSerializer, GetUserCompany,ProfileSeriaizer, SuscripcionSerializer,HistoriaSuscripcionSerializer
from reportlab.pdfgen import canvas
from PyPDF2 import PdfFileReader,PdfFileWriter
from django.contrib.auth.models import User
from django.contrib import auth
# from rest_framework.response import Response
from reportlab.lib.units import inch
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
import qrcode
import json
import requests
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend




class FileUploadView(APIView):
    permission_classes = [IsAuthenticated,]
    parser_class = (FileUploadParser,)

    def post (self, request, *args, **kwargs):
      file_serializer = FileSerializer(data=request.data)
      if file_serializer.is_valid():
          file_serializer.save()
          print(file_serializer.data)
          return Response(file_serializer.data, status=status.HTTP_201_CREATED)
      else:
          return Response(file_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 

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
           

class FileSend(APIView):

    permission_classes = [IsAuthenticated,]
   
    def post(self,request, *args, **kwargs):
        Request_Data = request.data
        Dict_Data_To_Json = json.dumps(Request_Data)
        Load_Json_Data = json.loads(Dict_Data_To_Json)
        useridjson= Load_Json_Data['usuario']
        posicionlogo = Load_Json_Data['posicion']
        urlfile = Load_Json_Data['url']
        SizeLogo = Load_Json_Data['size']
        Link_QR_Code = Load_Json_Data['linkqrcod']
        Slogan = Load_Json_Data['slogan']

        posicion_serializer = PosicionSerializer(data=request.data)

        if posicion_serializer.is_valid():
            posicion_serializer.save()
            idulast = PosicionSerializer.idurllast(urlfile)
            filepdfini = 'fileini' + str(idulast) + '.pdf'
            filepdfiniruta = './media/'+ filepdfini
            logo = canvas.Canvas(filepdfiniruta)
            logofile = PosicionSerializer.getlogourl(useridjson)
            logfilecp = '.' + logofile
            if(Link_QR_Code != "N"):
                Img_Cod_QR = CodigoQR.Genera_Codigo_QR(Link_QR_Code,idulast)
                logo.drawImage(Img_Cod_QR,175,150,270,100,preserveAspectRatio=True)
            if(Slogan != "N"):
                radius=inch/3.0
                xcenter=4.2*inch
                ycenter=3.5*inch
                logo.drawCentredString(xcenter, ycenter+1.3*radius, Slogan)
            if posicionlogo == 'derecha':
                if SizeLogo == 'grande':
                    logo.drawImage(logfilecp, 380, 700, 260, 110,preserveAspectRatio=True)
                    logo.save()
                if SizeLogo == 'medio':
                    logo.drawImage(logfilecp, 380, 710, 230, 80,preserveAspectRatio=True)
                    logo.save()
                if SizeLogo == 'peque':
                    logo.drawImage(logfilecp, 380, 710, 180, 40,preserveAspectRatio=True)
                    logo.save()
            elif posicionlogo  == 'izquierda':
                if SizeLogo == 'grande':
                    logo.drawImage(logfilecp, 29, 700, 260, 110,preserveAspectRatio=True)
                    logo.save()
                if SizeLogo == 'medio':
                    logo.drawImage(logfilecp, 29, 710, 230, 80,preserveAspectRatio=True)
                    logo.save()
                if SizeLogo == 'peque':
                    logo.drawImage(logfilecp, 29, 710, 180, 40,preserveAspectRatio=True)
                    logo.save()
            
            
            logopdf = PdfFileReader(open(filepdfiniruta,"rb"))
            fsatandlogo = PdfFileWriter()
            '''ETDJ = En tiempo de ejecucion.'''
            Str_File_Name_ETDJ = "." + str(urlfile)
            fsatpdf = PdfFileReader(open(Str_File_Name_ETDJ,"rb"))
            cantidad_pag = fsatpdf.getNumPages()

            for num_pagina in range(cantidad_pag):
                fsatpdf_page = fsatpdf.getPage(num_pagina)
                fsatpdf_page.mergePage(logopdf.getPage(0))
                fsatandlogo.addPage(fsatpdf_page)

            filepdffin = 'filefin' + str(idulast) + '.pdf'
            filepdffinruta = './media/'+ filepdffin

            with open(filepdffinruta,"wb") as outputStream:
                fsatandlogo.write(outputStream)
                file_fact_url = "./media/"+filepdffin

            with open(file_fact_url, "rb") as pdf_file:

                encoded_string = base64.b64encode(pdf_file.read()) 
            
            return Response(encoded_string, status=status.HTTP_200_OK)
         
            
            #return Response(file_fact_url, status=status.HTTP_200_OK)
        
        else:


            return Response(posicion_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):

    def post(self,request, *args, **kwargs):
        if request.method == 'POST':
            Request_Data = request.data
            Dict_Data_To_Json = json.dumps(Request_Data)
            Load_Json_Data = json.loads(Dict_Data_To_Json)
            user = auth.authenticate(
            username= Load_Json_Data['username'],
            password = Load_Json_Data['password'])

            if user is not None:
                auth.login(request,user)
                id_usuario = request.user.id
                UserResponse = {'userId': id_usuario}
                
                return Response(UserResponse,
                    status=200,
                    content_type='application/json')
            else:
                
                return Response('1900',status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)


class UserLogoutView(APIView):

    def post(self,request, *args, **kwargs):
        if request.method == 'POST':
            Request_Data = request.data
            Dict_Data_To_Json = json.dumps(Request_Data)
            Load_Json_Data = json.loads(Dict_Data_To_Json)
            username = Load_Json_Data['username']
            if username is not None:
                auth.logout(request,username)
                UserLogout = {'Logout': 'Exitoso'}
                return Response(UserLogout,
                    status=200,
                    content_type='application/json')
            else:
                return Response('1900',status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)


#CODIGO NUEVO

class CompanyRegistrationView(APIView): 

    parser_class = (FileUploadParser,)

    def post(self,request, *args, **kwargs):

        company_serializer = EmpresaSerializer(data = request.data)
        if company_serializer.is_valid():
            company_serializer.save()
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

    def Genera_Codigo_QR(Link_QR_Cod,idulast):
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

        Str_Nombre_Img_Cod_QR = 'Codigo' + str(idulast) + '.png'
        # Guardemos la imagen con la extension que queramos
        imagen.save('./media/'+Str_Nombre_Img_Cod_QR)

        Ruta_File_Img_Cod_QR = './media/'+Str_Nombre_Img_Cod_QR
        
        return Ruta_File_Img_Cod_QR

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


        def decrypt(value, key, iv):
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(base64.b64decode(value)) + decryptor.finalize()
            return decrypted.decode()


        '''def decrypt(value, method, key, iv):
        
            cipher = AES.new(key, AES.MODE_CBC, iv)
        
            decrypted = cipher.decrypt(base64.b64decode(value))
        
            return decrypted.decode()'''

        Request_Data = request.data
        Dict_Data_To_Json = json.dumps(Request_Data)
        Load_Json_Data = json.loads(Dict_Data_To_Json)
        token = Load_Json_Data['token']
        authorization = Load_Json_Data['authorization']
        amount = Load_Json_Data['amount']
        code = Load_Json_Data['code']
        audit = Load_Json_Data['audit']
        reference = Load_Json_Data['reference']

        method = 'aes-256-cbc'
        key = bytes.fromhex('1e63b2f7a01ddea85782dea27b46a04da699dae0ff5c58cf93')[:32]
        iv = base64.b64decode("ziwVz5mWmPp7qse7s1Uy/A==")

        '''
        key_size = [16, 24, 32]
        if len(key) not in key_size:
            print( ValueError("Incorrect AES key length (%d bytes)" % len(key)))
            return Response(ValueError("Incorrect AES key length (%d bytes)" % len(key)))
        '''

        print("Autorización:", decrypt(authorization, method, key, iv))
        print("Monto:", decrypt(amount, method, key, iv))
        print("Codigo:", code)
        print("Audit:", decrypt(audit, method, key, iv))
        print("Referencia:", decrypt(reference, method, key, iv))
        

        return Response(decrypt(authorization, method, key, iv), status = status.HTTP_201_CREATED)

            
        #return redirect('https://logfel.ceseonline.com.gt/pex')

        '''
        #return Response(data, status = status.HTTP_201_CREATED)
        #else:
            #return Response(suscripcion_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        '''
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


class CPUsuarioEmpresa(APIView):
    def post(self,request, *args, **kwargs):
        perfil_serializer = ProfileSeriaizer(data = request.data)
        if perfil_serializer.is_valid():
            perfil_serializer.save()
            return Response(perfil_serializer.data,status=status.HTTP_201_CREATED)
        else:
            return Response(perfil_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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