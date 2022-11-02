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

La technique que j'ai utiliser à la place de la simple injection dans le fichier de log semble avoir été d'abord publiée [sur Gist par un certain loknop](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d) sans tambours ni trompettes ce qui semble bien dommage.  

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
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'/pre>
```


*Published October 27 2022 at 23:24*