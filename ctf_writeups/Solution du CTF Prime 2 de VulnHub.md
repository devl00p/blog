# Solution du CTF Prime #2 de VulnHub

Faux départ
-----------

[Prime #2](https://www.vulnhub.com/entry/prime-2021-2,696/) est un CTF créé par [Suraj](https://twitter.com/hackerctf) et disponible sur VulnHub.  

Un premier scan de ports renvoi des réponses ICMP bizarres comme quoi le protocole n'est pas supporté. Hmmm.  

Pour savoir quels protocoles sont supportés par une machine distante on peut utiliser [un vieux code C que j'ai écrit il y a plus de 10 ans](http://devloop.users.sourceforge.net/index.php?article63/protoscan) ou plus facilement avec l'option *-sO* de Nmap.  

```plain
$ sudo nmap -sO 192.168.56.2 
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.56.2
Host is up (0.000024s latency).
Not shown: 254 closed n/a protocols (proto-unreach)
PROTOCOL STATE SERVICE
1        open  icmp
17       open  udp
MAC Address: 08:00:27:86:EA:5C (Oracle VirtualBox virtual NIC)
```

Etant donné qu'aucun port ne ressort non plus d'un scan UDP il est à parier que la VM ne fonctionne pas sous VirtualBox.  

Un import dans VMWare et un scan de port plus tard valident cette hypothèse :  

```plain
Nmap scan report for 192.168.101.128
Host is up (0.0014s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.4p1 Ubuntu 5ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0a:16:3f:c8:1a:7d:ff:f5:7a:66:05:63:76:7c:5a:95 (RSA)
|   256 7f:47:44:cc:d1:c4:b7:54:de:4f:27:f2:39:38:ff:6e (ECDSA)
|_  256 f5:d3:36:44:43:40:3d:11:9b:d1:a6:24:9f:99:93:f7 (ED25519)
80/tcp    open  http        Apache httpd 2.4.46 ((Ubuntu))
|_http-server-header: Apache/2.4.46 (Ubuntu)
|_http-title: HackerCTF
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
10123/tcp open  http        SimpleHTTPServer 0.6 (Python 3.9.4)
|_http-server-header: SimpleHTTP/0.6 Python/3.9.4
|_http-title: Directory listing for /
MAC Address: 00:0C:29:0C:F0:56 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Essayons de voir ce qui est disponible sur le Samba avec SMBmap :  

```plain
$ python smbmap.py -H 192.168.101.128

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com   
                     https://github.com/ShawnDEvans/smbmap

[!] Authentication error on 192.168.101.128
```

J'ai le bon réflexe d'essayer avec smbclient qui lui fonctionne correctement :  

```plain
$ smbclient -U "" -N -L //192.168.101.128

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        welcome         Disk      Welcome to Hackerctf LAB
        IPC$            IPC       IPC Service (hackerctflab server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

Une tentative d'accès au partage $print renvoie une erreur NT\_STATUS\_ACCESS\_DENIED mais le disque *welcome* est (évidemment) plus accueillant :  

```plain
smb: \> ls
  .                                   D        0  Sat May  8 09:42:49 2021
  ..                                  D        0  Fri May  7 20:38:58 2021
  .mysql_history                      H       18  Sat May  8 09:05:03 2021
  .profile                            H      807  Fri Mar 19 17:02:58 2021
  upload                              D        0  Sun May  9 13:19:02 2021
  .sudo_as_admin_successful           H        0  Sat May  8 07:34:48 2021
  .bash_logout                        H      220  Fri Mar 19 17:02:58 2021
  .cache                             DH        0  Fri May  7 20:39:15 2021
  something                           N       82  Fri May  7 18:18:09 2021
  secrets                             N        0  Fri May  7 18:15:17 2021
  .bash_history                       H       72  Sun May  9 13:23:26 2021
  .bashrc                             H     3771  Fri Mar 19 17:02:58 2021
```

Avec, en ordre d'apparition, dans l'historique bash :  

```plain
sudo su -
ifconfig
ls
cd upload/
ls
ls -l
cd ..
ls -l
chmod 755 jarves/
```

et dans le fichier *something* :  


*Published December 13 2021 at 18 11*