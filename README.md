# Ramsonware Mechanism

A simple Python script that explodes the mechanisms of ransomware

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install cryptography.

```bash
pip install cryptography
```

## Usage

```shell
#Encriptado de ficheros
$ python3 cripto.py ./ficheros

# Desencriptado de ficheros (suponiendo que genera los directorios c&c y encriptado
$ python3 d_cripto.py ../"c&c" ../encriptado ../desencriptado
```

## Explicación del módulo 'cripto.py'

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

## Explicación del módulo 'd_cripto.py'

Módulo encargado del descifrado de los ficheros marcados en el directorio objetivo.
1. Con la clave publica maestra (master.key) enviada desde C&C y el fichero de exponente local_private_key.enc se obtiene el exponente de la clave privada local. (dado que las opciones de recomposicion de la clave privada local en base al exponente no son triviales, trabajamos con local.key, proporcionada por el C&C)
2. De cada fichero codificado en el directorio (*.iv.key.enc) extraemos el vector de inicializacion binario, la clave simetrica cifrada por la clave publica local y el fichero codificado en AES-CTR-128
3. Desciframos la clave simetrica con la clave privada local (local.key). Si hemos regenerado esta a partir del exponente, genial! se usa en su sustitución.
4. Teniendo el vector de inicializacion y la clave de encriptado en formato binario, decodificamos el fichero correspondiente. Se repite paso 2 y 4 tantos ficheros existan.
5. Eliminamos ficheros de trabajo intermedios.

Modo de uso:

d_cripto.py ../"c&c" ../encriptado ../desencriptado

Siendo: 

- **../c&c** : Ficheros cargados desde el servidor de comando y control
- **../encriptado** : Ficheros encriptados del sistema
- **../desencriptado** : Ficheros resultantes de aplicar las operaciones de desencriptado

Argumentos necesarios para el modulo: **3**

El resultado es la creación de la carpeta ../deencriptado con los archivos desencriptados.

## License

[GNU GPL 2.0](https://choosealicense.com/licenses/gpl-2.0/)
