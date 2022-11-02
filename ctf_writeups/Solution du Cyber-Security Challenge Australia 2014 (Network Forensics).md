# Solution du Cyber-Security Challenge Australia 2014 (Network Forensics)

Après avoir résolu [la partie web du CySCA 2014](http://devloop.users.sourceforge.net/index.php?article111/solution-du-cyber-security-challenge-australia-2014-partie-web) j'avais le choix quand au domaine sur lequel jeter mon dévolu.  

Assez rapidement j'ai choisi de passer à la partie inforensique (baptisée ici *Network Forensics* mais comme vous verrez il n'est pas uniquement question de réseau) :)  

Let's go !  

Not Enough Magic (120 points)
-----------------------------

On doit retrouver un flag passablement caché dans un fichier pcap.  

J'ai ouvert la capture dans un premier temps avec Wireshark pour remarquer qu'il ne s'agit que de requêtes et réponses HTTP.  

Du coup je suis passé immédiatement à [Chaosreader](http://chaosreader.sourceforge.net/) qui n'est sans doute pas l'outil le plus sexy (en plus il est écrit en *Perl*)... mais il fait le job (promis, un jour j'utiliserais [Xplico](http://www.xplico.org/)).  

Il faut d'abord créer un dossier (ici *outdir*) où seront stockés les données extraites pour le spécifier à *Chaosreader* :  

```plain
$ ./chaosreader -D outdir 86590ed37efccf55b78f404ae6be09f0-net01.pcap 
$* is no longer supported at ./chaosreader line 265.
Chaosreader ver 0.94

Opening, 86590ed37efccf55b78f404ae6be09f0-net01.pcap

Reading file contents,
 100% (1074826/1074826)
Reassembling packets,
 100% (518/698)

Creating files...
   Num  Session (host:port <=> host:port)              Service
  0005  10.0.0.103:53470,172.16.1.80:80                www-http
  0003  10.0.0.103:53468,172.16.1.80:80                www-http
  0002  10.0.0.103:53467,172.16.1.80:80                www-http
  0001  10.0.0.103:53466,172.16.1.80:80                www-http
  0004  10.0.0.103:53469,172.16.1.80:80                www-http

index.html created.
```

Et en faisant un simple "file" sur les fichiers de session générés... on trouve la solution dans un tag *EXIF* d'une image :  

```plain
$ file session_0001.*
session_0001.part_01.gz:    gzip compressed data, from Unix
session_0001.part_02.gz:    gzip compressed data, was "43c20729bb03986ca09dc18974c994ec", last modified: Mon Feb 24 01:26:52 2014, from Unix
session_0001.part_03.jpeg:  JPEG image data, JFIF standard 1.01, comment: "CreamRainySpecify702"
session_0001.part_04.jpeg:  JPEG image data, JFIF standard 1.01
session_0001.part_05.data:  PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows
session_0001.part_06.data:  Standard MIDI data (format 1) using 21 tracks at 1/144
session_0001.part_07.data:  data
session_0001.www-http.html: HTML document, ASCII text, with very long lines, with CRLF, CR, LF line terminators
```

Encore plus simple que prévu :p  

Notwork Forensics (200 points)
------------------------------

On nous indique que la capture fournie est celle d'un échange entre deux criminels suspectés.  

Un survol du pcap permet d'y discerner une communication IRC sur le port 6667 ainsi qu'un gros échange de données sur des ports hauts qui semble être une connexion peer2peer.  

La conversation IRC est la suivante :  

```plain
CAP LS
NICK otherbadguy
USER dishadmin dishadmin 172.16.1.80 :dishadmin
:irc.localhost 020 * :Please wait while we process your connection.
:irc.localhost 001 otherbadguy :Welcome to the Internet Relay Network otherbadguy!~dishadmin@10.0.0.104
:irc.localhost 002 otherbadguy :Your host is irc.localhost, running version 2.11.2p2
--- snip ---
:irc.localhost 376 otherbadguy :End of MOTD command.
PING LAG1393413991419450
:irc.localhost PONG irc.localhost :LAG1393413991419450
:badguy!~root@10.0.0.103 PRIVMSG otherbadguy :The goose chased the fallen cloud.
PRIVMSG badguy :what wait? O_o
PRIVMSG badguy :did you follow my instructions?
:badguy!~root@10.0.0.103 PRIVMSG otherbadguy :i've encrypted the file
PRIVMSG badguy :what about the password?
PING LAG1393414021454751
:irc.localhost PONG irc.localhost :LAG1393414021454751
:badguy!~root@10.0.0.103 PRIVMSG otherbadguy :i've overwritten the password file like you said and deleted it
PRIVMSG badguy :just to be safe, send me a copy
:badguy!~root@10.0.0.103 PRIVMSG otherbadguy :one sec
:badguy!~root@10.0.0.103 PRIVMSG otherbadguy :.DCC SEND diskimage.gz 199 0 3230287 55.
PRIVMSG badguy :.DCC SEND diskimage.gz 167772264 37376 3230287 55.
PING LAG1393414051488468
:irc.localhost PONG irc.localhost :LAG1393414051488468
PRIVMSG badguy :i'll let you know... same time tomorrow
QUIT :Leaving
ERROR :Closing Link: otherbadguy[~dishadmin@10.0.0.104] ("Leaving")
```

Le fichier transféré via DCC (à exporter depuis *Wirewark* après un *Follow stream*) est un fichier de 32Mo identifié comme *"DOS/MBR boot sector"* après décompression.  

Un hexdump rapide permet de déterminer qu'il s'agit bien d'une image disque (d'où le nom de fichier transféré) avec une partition NTFS.  

Les distributions Linux modernes disposent d'un outil baptisé *kpartx* qui rend vraiment simple le montage de disques :  

```plain
# kpartx -av diskimage 
add map loop0p1 (254:2): 0 59392 linear /dev/loop0 128
```

Ici une seule partition détectée dans l'image. Le périphérique *loop0p1* a été ajouté au système, il suffit de le monter et d'explorer avec le gestionnaire de fichiers de son choix.  

```plain
# mount /dev/mapper/loop0p1 /mnt/
```

Dans la corbeille (*/mnt/$RECYCLE.BIN/*) on trouve une référence à un fichier *F:\files\My Secret Passwords.txt*. Toutefois on ne trouve rien de plus intéressant.  

Le démontage se fait de cette façon :  

```plain
# umount /mnt
# kpartx -d diskimage
loop deleted : /dev/loop0
```

J'ai décidé de passer à l'étape suivante en utilisant *Sleuthkit* à la recherche de fichiers effacés.  

```plain
# fdisk -l diskimage

Disk diskimage: 32 MiB, 33554432 bytes, 65536 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xa54645b7

Device     Boot Start   End Sectors Size Id Type
diskimage1        128 59519   59392  29M  7 HPFS/NTFS/exFAT
```

La partition commence au secteur 128. On doit l'indiquer à *fls* pour travailler :  

```plain
# fls -f ntfs -o 128 diskimage 
r/r 4-128-4:    $AttrDef
r/r 8-128-2:    $BadClus
r/r 8-128-1:    $BadClus:$Bad
r/r 6-128-4:    $Bitmap
r/r 7-128-1:    $Boot
d/d 11-144-4:   $Extend
r/r 2-128-1:    $LogFile
r/r 0-128-1:    $MFT
r/r 1-128-1:    $MFTMirr
d/d 35-144-1:   $RECYCLE.BIN
r/r 9-128-8:    $Secure:$SDS
r/r 9-144-11:   $Secure:$SDH
r/r 9-144-14:   $Secure:$SII
r/r 10-128-1:   $UpCase
r/r 3-128-3:    $Volume
d/d 38-144-8:   files
r/r 74-128-1:   How NTFS Works Local File Systems.htm
d/d 42-144-6:   How NTFS Works Local File Systems_files
r/r 39-128-1:   New Technology File System (NTFS) - Forensics Wiki.htm
r/r 40-128-1:   NTFS - SleuthKitWiki.htm
r/r 41-128-1:   NTFS - Wikipedia, the free encyclopedia.htm
d/d 58-144-6:   NTFS - Wikipedia, the free encyclopedia_files
d/d 17-144-4:   System Volume Information
d/d 768:        $OrphanFiles
```

On fouille dans le dossier *files* :  

```plain
$ fls -f ntfs -o 128 diskimage 38-144-8
```

Et on trouve une bonne quantité de fichiers dont voici les derniers :  

```plain
-/r * 589-128-1:        secret.7z
-/r * 591-128-1:        secret.db
-/r * 592-128-1:        secret.png
```

La récupération d'un fichier se fait à l'aide d'*icat* :  

```plain
$ icat -f ntfs -i raw -o 128 diskimage 589-128-1 > secret.7z
```

Seulement l'archive 7z est protégée par mot de passe... shit !  

```plain
Path = secret.7z
Type = 7z
Method = LZMA 7zAES
Solid = -
Blocks = 1
Physical Size = 167
Headers Size = 135

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2014-02-25 01:20:49 ....A           20           32  secret.txt
------------------- ----- ------------ ------------  ------------------------
```

J'ai généré une timeline de l'activité du disque avec mactime dans l'espoir de découvrir d'autres informations :  

```plain
$ fls -f ntfs -r -p -m C: -o 128 diskimage > body.txt
$ mactime -b body.txt > mactime.txt
```

Malheureusement je n'ai pas vu de très intéressant.  

Obtenir des infos concernant un fichier sur la partition se fait à l'aide de *istat* :  

```plain
$ istat -f ntfs -i raw -o 128 diskimage 589
MFT Entry Header Values:
Entry: 589        Sequence: 2
$LogFile Sequence Number: 1666744
Not Allocated File
Links: 1

$STANDARD_INFORMATION Attribute Values:
Flags: Archive
Owner ID: 0
Security ID: 265  (S-1-5-21-2229788878-2747424913-2242611199-1000)
Created:        2014-02-27 01:08:08 (CET)
File Modified:  2014-02-25 01:36:15 (CET)
MFT Modified:   2014-02-27 01:08:08 (CET)
Accessed:       2014-02-27 01:08:08 (CET)

$FILE_NAME Attribute Values:
Flags: Archive
Name: secret.7z
Parent MFT Entry: 38    Sequence: 1
Allocated Size: 0       Actual Size: 0
Created:        2014-02-27 01:08:08 (CET)
File Modified:  2014-02-27 01:08:08 (CET)
MFT Modified:   2014-02-27 01:08:08 (CET)
Accessed:       2014-02-27 01:08:08 (CET)

Attributes: 
Type: $STANDARD_INFORMATION (16-0)   Name: N/A   Resident   size: 72
Type: $FILE_NAME (48-2)   Name: N/A   Resident   size: 84
Type: $DATA (128-1)   Name: N/A   Resident   size: 167
```

Pour la petite info, 589 est le numéro du fichier *secret.7z* dans la *Master File Table* (qui est une sorte d'annuaire des fichiers sous NTFS).  

Ensuite sur l'entrée de la MFT viennent s'ajouter différents attributs numérotés eux aussi comme le nom du fichier ($FILE\_NAME, numéroté 48-2 qui contient le nom long et le nom DOS), $STANDARD\_INFORMATION qui contient les droits d'accès et $DATA qui comme son nom l'indique contient le contenu du fichier.  

Ici le fichier est de petite taille (167 octets) et est résident, son contenu est stocké dans la MFT (j'y reviens plus tard).  

Avec les Alternate Data Stream un fichier peut avoir plusieurs attributs $DATA, ce qui n'est pas le cas ici.  

En explorant via fls le dossier *$RECYCLE.BIN* on apperçoit un fichier *$ISH2ZGB.txt* d'index 76 dans la MFT.  

Les données de ce fichier contiennent la référence au fichier de mots de passes vu plus tôt.  

```plain
$ icat -f ntfs -i raw -o 128 -s diskimage 76-128-1 |hexdump -C
00000000  01 00 00 00 00 00 00 00  f0 03 00 00 00 00 00 00  |................|
00000010  80 b2 38 db 50 33 cf 01  46 00 3a 00 5c 00 66 00  |..8.P3..F.:.\.f.|
00000020  69 00 6c 00 65 00 73 00  5c 00 4d 00 79 00 20 00  |i.l.e.s.\.M.y. .|
00000030  53 00 65 00 63 00 72 00  65 00 74 00 20 00 50 00  |S.e.c.r.e.t. .P.|
00000040  61 00 73 00 73 00 77 00  6f 00 72 00 64 00 73 00  |a.s.s.w.o.r.d.s.|
00000050  2e 00 74 00 78 00 74 00  00 00 00 00 00 00 00 00  |..t.x.t.........|
00000060  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

C'est un fichier spécial de la corbeille dont le format est le suivant :  

* Octets 0 à 7 : header
* Octets 8 à 15 : taille du fichier en litlle endian donc 0x03f0 soit 1008 octets.

Or le fichier *$RSH2ZGB.txt* lui aussi dans la corbeille fait 1008 octets mais commence par un *lorem ipsum*... Ce n'est donc pas la liste de mots de passe que l'on espérait.  

On peut en déduire le le fichier *"My Secret Passwords.txt"* a été écrasé par un fichier contenant le *lorem ipsum* avant d'être placé dans la corbeille.  

Toutefois on suppose que le fichier contenant les mots de passe est de très petite taille.  

Or le système de fichier NTFS peut, dans un souci de performance, stocker directement le contenu de fichiers dans la Master File Table s'ils sont de petite taille comme indiqué sur [NTFS.com](http://ntfs.com/ntfs-mft.htm).  

Par conséquent, l'écrasement effectué par l'un des suspects n'a pas réellement eu lieu : les nouvelles données sensées écraser les précédentes ont été placées ailleurs sur le disque car la MFT ne peut pas inclure un fichier de 1008 octets. L'ancien fichier a quand à lui du être seulement désindexé de la MFT.  

On a vu que les fichiers qui nous concernent sont à la fin de l'index (numéros de MFT 589, 590, 591...).  

Il suffit alors d'extraire la MFT via *icat* (la MFT a l'index 0), d'appeler dessus *srch\_strings* (l'outil fournit par *Sleuthkit* qui remplace agréablement le programme strings de base) pour extraire les chaines de caractères et commencer à lire par la fin puis remonter l'output généré.  

Après une longue série de FILE0 on fini par tomber sur ça :  

```plain
FILE0
j9Bb
FILE0
skype
1~^bK6dA0>1rHX5j
instagram
M_8!58/;Wklng:h0
phone pin
902485
7z file
nRkmrtp2("u8~/ph
bank login
r0wvh1
FILE0
FILE0
FILE0
```

Il s'agit en fait d'une suite de lignes avec tour à tour la description du password (ex: instagram) et le password lui-même.  

La décompression du fichier 7z s'effectue ainsi avec succès en utilisant le mot de pase *nRkmrtp2("u8~/ph*.  

Pour plus de détails les données se trouvaient dans le cluster 2621 entre les entrée de MFT 588 et 589 mais je n'ai pas trouvé de manière directe d'obtenir ces coordonnées...  

Une fois le fichier décompressé on obtient le flag *WhiteBelatedBlind439*.  

AYBABTU (280 points)
--------------------

La description de l'exercice est la suivante :  

> RL Forensics Inc. has supplied a network capture from one of their customers that was infected with trojan malware. The customer was able to capture a command and control session of the trojan communicating with the criminals server. They would like to know what data was stolen by criminals. Analyse the communications, determine the custom protocol and extract the stolen information to reveal the flag

Pour faire court le pcap contient des requêtes et réponses DNS qui exfiltrent des données en utilisant différents encodages. On remarque rapidement un encodage propre du base64 qui est en réalité du base32. Cet encodage est justement utilisé par des outils existants de tunnel DNS comme *Ozyman* et *Iodine*.  

J'ai écrit le parseur suivant qui simplifie la lecture du pcap en réduisant la quantité d'information. J'ai utilisé à la fois *Impacket* et *dpkt* ce qui n'est probablement pas la solution la plus élégante mais je n'ai pas pris la peine de mettre au propre.  

```python
import pcapy
from impacket import ImpactDecoder, ImpactPacket
import fcntl
import dpkt

sniff = pcapy.open_offline("74db9d6b62579fea4525d40e6848433f-net03.pcap")
decoder = ImpactDecoder.EthDecoder()

while True:
    try:
        (header, packet) = sniff.next()
        ethernet = decoder.decode(packet)

        if ethernet.get_ether_type() == ImpactPacket.IP.ethertype: # IP
            ip = ethernet.child()
            if ip.get_ip_p() == ImpactPacket.UDP.protocol:
                udp = ip.child()
                dns_data = udp.child().get_buffer_as_string()
                dns = dpkt.dns.DNS(dns_data)
                if dns.qr == dpkt.dns.DNS_Q:
                    if dns.opcode == dpkt.dns.DNS_QUERY:
                        if len(dns.qd) == 1:
                            if dns.qd[0].type == dpkt.dns.DNS_TXT:
                                print "> ID {0:0>4X} {1}".format(dns.id, dns.qd[0].name)
                else:
                    if len(dns.qd) == 1 and len(dns.an) == 1:
                        if dns.qd[0].type == dpkt.dns.DNS_TXT:
                            print "< ID {0:0>4X} {1}".format(dns.id, dns.an[0].rdata[1:])
                continue
            if ip.get_ip_p() == ImpactPacket.TCP.protocol:
                continue
            if ip.get_ip_p() == ImpactPacket.ICMP.protocol:
                continue
    except pcapy.PcapError:
        break
```

On obtient des lignes comme celles-ci avec la direction du flux, l'ID de la requête DNS et le nom de domaine demandé.  

```plain
> ID AACE aaaaabqaaaaaaaaaaaaaaaaa-0ba3b5e1a2890d89.badguy.com
> ID C101 aaaaabyaaaaaaaaaaaaaaaaa-3c54c28c7e41d37f.badguy.com
> ID CBC5 aaaaacaaaaaaaaaaaaaaaaaa-2262036a89a89375.badguy.com
> ID 77BE aaaaaciaaaaaaaaaaaaaaaaa-3e1b5aad07715a93.badguy.com
> ID 0107 aaaaacqaaaaaaaaaaaaaaaaa-4b13e4a194124c21.badguy.com
> ID 34D9 aaaaacyaaaaaaaaaaaaaaaaa-dbd8b82da7db86f7.badguy.com
```

Evidemment on remarque tout de suite des données hexadécimales. La première partie du nom de domaine semble s'incrémenter et je me suis dis que le seul objectif est d’empêcher une mise en cache, je ne suis donc pas allé plus loin. Quand aux ID DNS j'ai estimé qu'ils étaient générés automatiquement par une librairie utilisée et n'avaient donc pas d'importance.  

A ces requêtes il y a parfois un retour sous la forme d'un enregistrement TXT en base64 :  

```plain
< ID 042D AAAADAAAAAwAAAN4nGNgYEgBAABoAGU=
< ID BEAB AAAAWAAAABQAAAV4nEu2iinPzEvJLy+OSQQAHhAEwg==
< ID BEAB AAAAWAAAABQAAAV4nEu2iinPzEvJLy+OSQQAHhAEwg==
```

dans beaucoup de cas la réponse a une taille fixe et est sans doute une sort d'ACK.  

```plain
< ID 0C38 AAAADwAAAAAAAAA=
< ID 5B6E AAAAEAAAAAAAAAA=
```

Enfin on trouve des requêtes DNS en base32 de très longue taille :  

```plain
> ID 169B aaaacjiaaaammaaaaz4jzdopjvv4eqaqy3yxwig74e4svrbyxnexyq54eqgxrm.auqwp---snip---q4c.vd6wykuiuti4a34bao3wlimtzh2pcu5wrdz4f6punu3skkcedlyk5x4nawlx-c8.badguy.com
```

J'ai commencé par extraire les données hexadécimales du premier type de requêtes. En modifiant quelque peu le script précédent ou peut dumper les données qui nous intéressent :  

```python
if dns.opcode == dpkt.dns.DNS_QUERY:
    if len(dns.qd) == 1:
        if dns.qd[0].type == dpkt.dns.DNS_TXT:
            server = dns.qd[0].name
            if len(server) == 52:
                raw = server[25:41].decode("hex_codec")
                fd.write(raw)
```

Mais à regarder de plus près ces données ne semblent pas donner d'informations utiles...  

J'ai testé de casser un éventuel chiffrement XOR avec [xor-analyse](https://github.com/ThomasHabets/xor-analyze) sans succès :(  

J'ai préféré m'en remettre à l'indice donné pour ce level :  

> Hrmm... 78 9C seems like a header of some kind?

Après recherche ce header correspond effectivement [à une compression zlib](https://stackoverflow.com/questions/9050260/what-does-a-zlib-header-look-like).  

Le header *789c* apparaît à deux reprises dans le dump... Mais là encore les tentatives d'obtenir une information utile sont vaines.  

Je me suis alors attaqué au second type de requêtes que l'on trouve : les réponses DNS encodées en base64.  

Une fois décodées on s’aperçoit que le début de chaque réponse est quasiment toujours le même (\x00\x00\x01...).  

```plain
>>> s = "AAAAMQAAABwAAAF4nMvNTsksUki2iokpz8xLyS8vjolJBABPkwex"
>>> base64.b64decode(s)
'\x00\x00\x001\x00\x00\x00\x1c\x00\x00\x01x\x9c\xcb\xcdN\xc9,RH\xb6\x8a\x89)\xcf\xccK\xc9//\x8e\x89I\x04\x00O\x93\x07\xb1'
>>> zlib.decompress(base64.b64decode(s)[11:])
'mkdir c:\\\\windows\\\\a'
>>> 0x1c
28
>>> len(base64.b64decode(s)[11:])
28
```

On a donc une forme d'entête applicatif qui correspond aux 10 premiers octets.  

Au 11ème octet on trouve l'entête zlib (x\x9c).  

Selon moi l'entête se coupe en 3 : 4 octets pour le type de communication (que j'ai baptisé bêtement x), 4 octets pour la longueur du corps (length, la taille des données compressées) et 2 octets qui marquent un numéro de paquet (s'il est à 0 on sait qu'on à affaire à un nouveau flux) que j'ai nommé blk.  

Voici le code pour dumper ces réponses DNS :  

```python
import pcapy
from impacket import ImpactDecoder, ImpactPacket
import fcntl
import dpkt
import base64
import zlib
import struct

sniff = pcapy.open_offline("74db9d6b62579fea4525d40e6848433f-net03.pcap")
decoder = ImpactDecoder.EthDecoder()

i = 0
data = ""

while True:
    try:
        (header, packet) = sniff.next()
        ethernet = decoder.decode(packet)

        if ethernet.get_ether_type() == ImpactPacket.IP.ethertype: # IP
            ip = ethernet.child()
            if ip.get_ip_p() == ImpactPacket.UDP.protocol:
                udp = ip.child()
                dns_data = udp.child().get_buffer_as_string()
                dns = dpkt.dns.DNS(dns_data)
                if dns.qr != dpkt.dns.DNS_Q:
                    if len(dns.qd) == 1 and len(dns.an) == 1:
                        if dns.qd[0].type == dpkt.dns.DNS_TXT:
                            buff = base64.b64decode(dns.an[0].rdata[1:])
                            header = buff[:10]
                            body = buff[11:]
                            x, length, blk = struct.unpack(">IIH", header)

                            # beginning of a new stream, dump the existing data
                            if blk == 0 and data:
                                fd = open("file{0:02}".format(i), "w")
                                fd.write(zlib.decompress(data))
                                fd.close()
                                i += 1
                                data = ""

                            data += body

                continue
    except pcapy.PcapError:
        break

if data:
    fd = open("file{0:02}".format(i+1), "w")
    fd.write(zlib.decompress(data))
    fd.close()
```

Cela génère des fichiers 0 à 10 dont voici le contenu :  

```plain
mkdir c:\\windows\\a
c:\windows\a
@echo off 
echo %computername% >> c:\windows\a\%computername%_base.dat 
qwinsta >> c:\windows\a\%computername%_base.dat 
date /t >> c:\windows\a\%computername%_base.dat 
time /t >> c:\windows\a\%computername%_base.dat 
ipconfig /all >> c:\windows\a\%computername%_base.dat 
nbtstat -n >> c:\windows\a\%computername%_base.dat 
systeminfo >> c:\windows\a\%computername%_base.dat 
set >> c:\windows\a\%computername%_base.dat 
net share >> c:\windows\a\%computername%_base.dat 
net start >> c:\windows\a\%computername%_base.dat 
tasklist /v >> c:\windows\a\%computername%_base.dat 
netstat -ano >> c:\windows\a\%computername%_base.dat 
dir c:\ /a >> c:\windows\a\%computername%_base.dat 
dir d:\ /a >> c:\windows\a\%computername%_base.dat 
dir c:\progra~1 >> c:\windows\a\%computername%_base.dat 
dir c:\docume~1 >> c:\windows\a\%computername%_base.dat 
net view /domain >> c:\windows\a\%computername%_base.dat 
dir
rename e76a523f1b.dat 1.bat
dir
1.bat
dir
VICTIM_base.dat
@echo off 
cd c:\users && for /r %%i in (*.pdf) do copy "%%i" c:\windows\a\
cd c:\windows\a && a.exe a -hpqazWSXedc567 o.dat *.pdf
```

Le fichier 11 extrait par le dump est un exécutable Windows 32bits.  

A regarder de plus près avec *srch\_strings*, il s'agit de l'utilitaire winrar en ligne de commande.  

Une recherche DDG sur le hash MD5 du fichier (070d15cd95c14784606ecaa88657551e) confirme cette supposition.  

Après l'envoi de l'exécutable d'autres flux sont envoyés :  

```plain
dir
rename 070d15cd95.dat a.exe
rename 31c9a36cdb.dat 2.bat
o.dat
```

De toute évidence le fichier *a.exe* est l'exécutable *Winrar*. Il reçoit ici la commande "a" pour créer une archive avec l'option -hp qui spécifie le mot de passe de chiffrement *qazWSXedc567*.  

On est sur la bonne direction mais toujours pas de flag en vue. Cette fois je m'attaque aux requêtes en base32 allant vers le serveur DNS (donc des données exfiltrées).  

Ce type de requêtes se trouve environ au milieu de l'ensemble des communication et le header applicatif (une fois le base32 décodé) fait apparaître une valeur de x = 467.  

Je ne met pas le code du dump en entier, il suffit d'adapter le précédent pour extraire le base32 :  

```python
b32 = server[:-14].replace(".","").split("-")[0]
raw = base64.b32decode(b32, True)
header = raw[:10]
body = raw[11:]
x, length, blk = struct.unpack(">IIH", header)

if x != 467:
    continue

if blk == 0 and data:
    fd = open("file-{0:02}".format(i), "w")
    fd.write(zlib.decompress(data))
    fd.close()
    i += 1
    data = ""

data += body
```

Le dump permet d'obtenir le résultat des commandes vues précédemment :  

```plain
VICTIM
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
 console                                     1  Conn
>rdp-tcp#0         Administrator             2  Active  rdpwd
 rdp-tcp                                 65536  Listen
Tue 04/02/2014
03:52 PM

Windows IP Configuration

   Host Name . . . . . . . . . . . . : victim
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-97-14-DB
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.150(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.1
   DNS Servers . . . . . . . . . . . : 10.10.10.10
   NetBIOS over Tcpip. . . . . . . . : Enabled
---snip---
Host Name:                 VICTIM
OS Name:                   Microsoft Windows 7 Enterprise
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          sburns
---snip---
Host Name:                 VICTIM
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          sburns
-- snip---
```

On trouve aussi les partages réseau, services et processus en cour parmi lesquels *dumpcap.exe* (utilisé pour générer l'export pcap).  

Il y a aussi une connexion RDP établie avec la machine attaquante (10.0.0.103).  

```plain
  TCP    10.10.10.150:3389      10.0.0.103:52350       ESTABLISHED     1080
```

Et dans les variables d'environnement on note ce qui est probablement le pseudo du pirate :  

```plain
CLIENTNAME=ZERF-LAPTOP
```

A la fin de la capture on retrouve des requêtes DNS du même type mais avec une valeur de x différente (2210).  

Et bingo ! Cette fois le dump nous sort une archive rar protégée par le mot de passe vu tout à l'heure qui contient deux fichiers :  

```plain
Details: RAR 4, encrypted headers

 Attributes      Size    Date   Time   Name
----------- ---------  -------- -----  ----
*   ..A....     91183  04-02-14 13:15  secret document.pdf
*   ..A....    104736  04-02-14 13:15  sudo.pdf    
----------- ---------  -------- -----  ----
               195919                  2
```

Le PDF *"secret document"* ne contient que le flag : *HoardDirectCrumb136*  

*sudo.pdf* contient une planche XKCD (Sudo make me a sandwich)  

Victory

*Published December 09 2014 at 22:30*