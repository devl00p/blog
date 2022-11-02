# Solution du CTF Ethereal de HackTheBox

Between a rock and a hard place
-------------------------------

Il est de ces CTFs qui sont capables de vous pourrir la vie et vous font vous arracher les cheveux... *Ethereal* est l'un de deux là :)   

Il est très frustrant car toute tentative de se libérer des restrictions présentes semble aboutir systématiquement à un échec et il vous faut une demi heure pour copier un simple fichier.  

Abandonnez tout espoir vous qui entrez ici
------------------------------------------

Un Nmap remonte des ports plutôt standard et pauvres fous que nous sommes, impossible de deviner la galère dans laquelle on est en train de se mettre :D   

```plain
Nmap scan report for 10.10.10.106
Host is up (0.15s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
8080/tcp open  http-proxy
```

Le FTP accepte les connexions anonymes en lecture seule. On peut récupérer son contenu de cette façon :  


*Published March 09 2019 at 17 26*