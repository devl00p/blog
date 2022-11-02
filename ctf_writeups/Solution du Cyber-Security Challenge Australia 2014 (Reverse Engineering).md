# Solution du Cyber-Security Challenge Australia 2014 (Reverse Engineering)

Après avoir solutionné [la partie Network Forensics du CySCA 2014]( http://devloop.users.sourceforge.net/index.php?article112/solution-du-cyber-security-challenge-australia-2014-network-forensics) l'envie m'est venu de casser du binaire. Je me suis donc lancé sur la partie reverse-engineering.  

Le problème du RE c'est que c'est très time-consuming, en particulier quand on n'en fait pas tous les jours :p  

Mais comme toujours la satisfaction d'arriver à ses fins, ça n'a pas de prix.  

U JAD BRO? (120 points)
-----------------------

> Staff from Terribad Corp have forgotten the password for their propriety data protection Java application. They need you to retrieve the data stored in the application and submit it.

Ce premier exécutable à analyser et une application Java (archive .jar). Une fois lancé on se retrouve face à une mire de connexion très basique qui affiche un message d'erreur lorsque l'on rentre des identifiants incorrects.  

![cysca reverse level 1](https://raw.githubusercontent.com/devl00p/blog/master/images/cysca/jar_gui.png)

Plutôt que de sortir un vieux *JAD* du placard j'ai décidé de fouiller sur le web pour trouver une application plus agréable me doutant que des progrès avaient du être fait depuis. Et effectivement je suis rapidement tombé sur *JD-GUI* ([Java Decompiler](http://jd.benow.ca/) ) qui fonctionne à merveille.  

![cysca java decompiler](https://raw.githubusercontent.com/devl00p/blog/master/images/cysca/jar_hash.png)

Dans la classe *PRAuthService* on trouve un nom d'utilisateur (*Hero33*) ainsi qu'un hash SHA-256 (f483ad5dea697e7e75ebc791028502da183258cd23aeff0327957dc56f703af3) sous la forme d'un tableau d'octets signés.  

Brute-forcer du SHA-256 ne me dit rien qui vaille donc la solution est probablement ailleurs.  

Dans la classe principale (*PRMain*) on trouve une méthode *loginSuccessful* qui défini le contenu à afficher si l'authentification réussit :  

```plain
    String content = this.contentService.getContent(session);
    this.frame.getContentPanel().setProtectedContent(content);
```

La solution est en fait située dans la classe *PRContentService* :  

```c
public class PRContentService
{
  private static final byte[] CIPHERED_BYTES = { 30, 0, 21, 8, 90, 86, 4, 0, 10, 6, 80, 92, 38, 53, 30, 26, 80, 88, 113, 87, 67 };

  private String cipherString(String text, String key)
  {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < text.length(); i++) {
      sb.append((char)(text.charAt(i) ^ key.charAt(i % key.length())));
    }

    return sb.toString();
  }

  public String getContent(AuthenticatedSession session)
  {
    String result = cipherString(new String(CIPHERED_BYTES), session.getUsername());

    return result;
  }
}
```

Ici on voit que le nom d'utilisateur est utilisé comme clé pour effectuer un XOR sur une suite d'octets prédéfinis.  

Il suffit de reproduire l'opération en Python :  

```plain
>>> l = [30, 0, 21, 8, 90, 86, 4, 0, 10, 6, 80, 92, 38, 53, 30, 26, 80, 88, 113, 87, 67]
>>> key = "Hero33"
>>> "".join([chr(x ^ ord(key[i%6])) for i, x in enumerate(l)])
'VeggieLexiconPluck921'
```

Knock Knock (200 points)
------------------------

> Terribad Corp has provided a binary which they think is the "next big thing" in security. They would like to get it certified as a secure product. We need you to reverse engineer the algorithm to understand what it does. Once you have done this, a test server is running at 192.168.1.64:3422 to allow you to prove you completely recovered the algorithm.

On a ici affaire à un petit binaire ELF 32bits de 9.6Ko lié dynamiquement et strippé.  

Une analyse rapide des chaines présentes dans l'exécutable indique que le programme effectue un setuid / setguid puis un chroot avec des droits hardcodés.  

On remarque aussi des messages d'erreur en rapport avec du port-knocking et enfin le saint graal : une référence à un fichier */flag.txt*.  

L'analyse du code assembleur avec [radare2](http://radare.org/y/) se révèle agréable : le code est simple et il n'y a pas d'obfuscation.  

Le *main()* se décompose en deux fonctions. La première à *0x80489f4* permet de changer d'utilisateur, chrooter puis fork().  

La seconde fonction (à l'adresse *0x08048f9a*) se charge de mettre en écoute une socket et fork() après chaque accept().  

Cette dernière fonction en appelle une autre (*0x080491f4*) lors de la connexion d'un client. C'est à partir d'ici que ça devient intéressant.  

Après avoir affiché un message *"portknockd: New Client. Waiting for knocks"*, le programme saute vers *0x08049218* après avoir initialisé un compteur à 0 (*ebp - 0x18*).  

S'ensuit une grosse boucle qui itère 5 fois (*cmp dword [ebp - 0x18], 4 ; jbe 0x08049218*).  

Mais que fait cette boucle ?  

D'abord il y a la mise en place d'une protection anti-debug :  

```plain
0x080491cb    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
0x080491ce    a390b00408   mov dword [0x804b090], eax ; [:4]=0xffffff00
0x080491d3    c74424049c9. mov dword [esp + 4], 0x804919c ; [:4]=0x10100
0x080491db    c704240e000. mov dword [esp], 0xe
0x080491e2    e899f5ffff   call sym.imp.signal
sym.imp.signal(unk)
0x080491e7    8b450c       mov eax, dword [ebp + 0xc] ; [:4]=0
0x080491ea    890424       mov dword [esp], eax
0x080491ed    e8aef5ffff   call sym.imp.alarm
```

Ici une fonction callback est définie dans le cas où un signal *SIGALARM* est reçu. Ce callback ferme la connexion et quitte le programme.  

Juste en dessous alarm() est appelé pour justement envoyer le signal après un certain laps de temps.  

Ainsi si le code met trop de temps à s'exécuter (typiquement le code est débogué), le programme quittera prématurément.  

La fonction appelée ensuite est assez parlante :  

```plain
|          ; CALL XREF from 0x08049239 (fcn.08049218)
/ (fcn) sub.fclose_616 150
|          0x08049616    55           push ebp
|          0x08049617    89e5         mov ebp, esp
|          0x08049619    83ec28       sub esp, 0x28
|          0x0804961c    baba9b0408   mov edx, 0x8049bba
|          0x08049621    b8bd9b0408   mov eax, str._dev_urandom ; "/dev/urandom" @ 0x8049bbd
|          0x08049626    89542404     mov dword [esp + 4], edx ; [:4]=0x10100
|          0x0804962a    890424       mov dword [esp], eax
|          0x0804962d    e87ef2ffff   call sym.imp.fopen
|             sym.imp.fopen(unk)
|          0x08049632    8945f4       mov dword [ebp - 0xc], eax
|          0x08049635    837df400     cmp dword [ebp - 0xc], 0
|      ,=< 0x08049639    751f         jne 0x804965a
|      |   0x0804963b    c7442404cc9. mov dword [esp + 4], str.ERROR__Unable_to_open_urandom_n ; [:4]=0x10100
|      |   0x08049643    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|      |   0x08049646    890424       mov dword [esp], eax
|      |   0x08049649    e885f7ffff   call sub.vsnprintf_dd3
|      |      sub.vsnprintf_dd3()
|      |   0x0804964e    c70424fffff. mov dword [esp], 0xffffffff
|      |   0x08049655    e806f2ffff   call sym.imp.exit
|      |      sym.imp.exit()
|      |   ; JMP XREF from 0x08049639 (sub.fclose_616)
|      `-> 0x0804965a    8d45f0       lea eax, dword [ebp - 0x10]
|          0x0804965d    8b55f4       mov edx, dword [ebp - 0xc]
|          0x08049660    8954240c     mov dword [esp + 0xc], edx ; [:4]=0
|          0x08049664    c7442408010. mov dword [esp + 8], 1 ; [:4]=0
|          0x0804966c    c7442404040. mov dword [esp + 4], 4 ; [:4]=0x10100
|          0x08049674    890424       mov dword [esp], eax
|          0x08049677    e894f1ffff   call sym.imp.fread
|             sym.imp.fread()
|          0x0804967c    8b45f4       mov eax, dword [ebp - 0xc]
|          0x0804967f    890424       mov dword [esp], eax
|          0x08049682    e8d9f0ffff   call sym.imp.fclose
|             sym.imp.fclose()
|          0x08049687    8b4df0       mov ecx, dword [ebp - 0x10]
|          0x0804968a    ba993d60f6   mov edx, 0xf6603d99
|          0x0804968f    89c8         mov eax, ecx
|          0x08049691    f7e2         mul edx
|          0x08049693    89d0         mov eax, edx
|          0x08049695    c1e807       shr eax, 7
|          0x08049698    69c085000000 imull 0x85, eax
|          0x0804969e    89ca         mov edx, ecx
|          0x080496a0    29c2         sub edx, eax
|          0x080496a2    89d0         mov eax, edx
|          0x080496a4    8945f0       mov dword [ebp - 0x10], eax
|          0x080496a7    8b45f0       mov eax, dword [ebp - 0x10]
|          0x080496aa    c9           leave
\          0x080496ab    c3           ret
```

*/dev/urandom* est ouvert et 4 octets sont lus. Des calculs supplémentaires (décalage de bits, multiplication, soustraction) sont effectués avant de retourner le résultat mais les détails sont sans importance pour nous car le résultat final est envoyé au client (donc à nous).  

L'étape suivante consiste pour le programme à lire 4 octets sur la socket.  

Le cœur de notre problème se concentre sur ces quelques lignes avec les fonctions appelées :  

```plain
|  |   |    ; JMP XREF from 0x080492af (fcn.08049218)
|  |   `--> 0x080492d4    8b45e4       mov eax, dword [ebp - 0x1c]
|  |        0x080492d7    8b55e8       mov edx, dword [ebp - 0x18]
|  |        0x080492da    89542404     mov dword [esp + 4], edx ; [:4]=0x10100
|  |        0x080492de    890424       mov dword [esp], eax
|  |        0x080492e1    e8fe020000   call fcn.080495e4
|  |           fcn.080495e4()
|  |        0x080492e6    8945f4       mov dword [ebp - 0xc], eax
|  |        0x080492e9    8b55f4       mov edx, dword [ebp - 0xc]
|  |        0x080492ec    8b45e0       mov eax, dword [ebp - 0x20]
|  |        0x080492ef    39c2         cmp edx, eax
|  |  ,===< 0x080492f1    7547         jne 0x804933a
|  |  |     0x080492f3    837de804     cmp dword [ebp - 0x18], 4
|  | ,====< 0x080492f7    7522         jne 0x804931b
|  | ||     0x080492f9    8b45ec       mov eax, dword [ebp - 0x14]
|  | ||     0x080492fc    890424       mov dword [esp], eax
|  | ||     0x080492ff    e859000000   call 0x804935d ; (fcn.08049351)
|  | ||        fcn.08049218() ; sub.puts_1f4+361
|  | ||     0x08049304    8b45ec       mov eax, dword [ebp - 0x14]
|  | ||     0x08049307    890424       mov dword [esp], eax
|  | ||     0x0804930a    e811f6ffff   call sym.imp.close
|  | ||        sym.imp.close()
|  | ||     0x0804930f    c7042401000. mov dword [esp], 1
|  | ||     0x08049316    e845f5ffff   call sym.imp.exit
|  | ||        sym.imp.exit()
|  | `----> 0x0804931b    8b45ec       mov eax, dword [ebp - 0x14]
|  |  |     0x0804931e    890424       mov dword [esp], eax
|  |  |     0x08049321    e8faf5ffff   call sym.imp.close
|  |  |        sym.imp.close()
|  |  |     0x08049326    8b45e8       mov eax, dword [ebp - 0x18]
|  |  |     0x08049329    890424       mov dword [esp], eax
|  |  |     0x0804932c    e80f010000   call fcn.08049440
|  |  |        fcn.08049440() ; sub.puts_1f4+588
|  |  |     0x08049331    8945ec       mov dword [ebp - 0x14], eax
|  |  |     0x08049334    8345e801     add dword [ebp - 0x18], 1
|  |,=====< 0x08049338    eb17         jmp fcn.08049351
|  || |     ; JMP XREF from 0x080492f1 (fcn.08049218)
|  || `---> 0x0804933a    8b45ec       mov eax, dword [ebp - 0x14]
|  ||       0x0804933d    890424       mov dword [esp], eax
|  ||       0x08049340    e8dbf5ffff   call sym.imp.close
|  ||          sym.imp.close()
|  ||       0x08049345    c7042401000. mov dword [esp], 1
|  ||       0x0804934c    e80ff5ffff   call sym.imp.exit
|  ||          sym.imp.exit()
|  ||       ; JMP XREF from 0x08049213 (sub.puts_1f4)
|  ||       ; JMP XREF from 0x08049338 (fcn.08049218)
|- fcn.08049351 239
|  |`-----> 0x08049351    837de804     cmp dword [ebp - 0x18], 4
|  `======< 0x08049355    0f86bdfeffff jbe fcn.08049218
```

Dans ce code on a les variables locales suivantes :  

* ebp-0x14 : la socket client
* ebp-0x18 : le compteur qui monte jusqu'à 4
* ebp-0x1c : les 4 octets envoyés au client
* ebp-0x20 : les 4 octets en provenance du client
* ebp-0xc : le retour de la fonction fcn.080495e4

La fonction *fcn.080495e4* qui prend en paramètre les 4 octets envoyés plus tôt au client et le compteur a le code suivant :  

```plain
|          0x080495e4    55           push ebp
|          0x080495e5    89e5         mov ebp, esp
|          0x080495e7    83ec10       sub esp, 0x10
|          0x080495ea    8b450c       mov eax, dword [ebp + 0xc] ; [:4]=0
|          0x080495ed    83e001       and eax, 1
|          0x080495f0    85c0         test eax, eax
|      ,=< 0x080495f2    750f         jne 0x8049603
|      |   0x080495f4    8b450c       mov eax, dword [ebp + 0xc] ; [:4]=0
|      |   0x080495f7    83c002       add eax, 2
|      |   0x080495fa    0faf4508     imul eax, dword [ebp + 8]
|      |   0x080495fe    8945fc       mov dword [ebp - 4], eax
|     ,==< 0x08049601    eb0e         jmp 0x8049611 ; (fcn.080495e4)
|     ||   ; JMP XREF from 0x080495f2 (fcn.080495e4)
|     |`-> 0x08049603    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|     |    0x08049606    8b550c       mov edx, dword [ebp + 0xc] ; [:4]=0
|     |    0x08049609    01d0         add eax, edx
|     |    0x0804960b    83c002       add eax, 2
|     |    0x0804960e    8945fc       mov dword [ebp - 4], eax
|     `--> 0x08049611    8b45fc       mov eax, dword [ebp - 4]
|          0x08049614    c9           leave
\          0x08049615    c3           ret
```

On peut l'écrire comme ceci en Python :  

```python
def calc(x, cpt):
    if cpt & 1:
        return x + cpt + 2
    return (cpt + 2) * x
```

Si le résultat de la fonction ne correspond pas à ce que le serveur a reçu, la socket est fermée et le programme quitte (c'est une sorte de handshake).  

Par contre si le test réussit on a deux cas de figure :  

* le compteur est à 4 : le flag est envoyé.
* le compteur est inférieur à 4 : on appelle *fcn.08049440* en lui passant le compteur. Le résultat de cette fonction vient écraser le descripteur de la socket.

La fonction *fcn.08049440* est donc bien mystérieuse mais quand on y jette un œil elle appelle juste socket(), htons(), setsockopt(), bind(), listen() puis accept(), bref elle récupère un nouveau client sur un nouveau port d'écoute.  

Tout se joue sur l'appel à htons() :  

```plain

0x080494ef    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
0x080494f2    8b0485c49a0. mov eax, dword [eax*4 + 0x8049ac4] ; [:4]=0xd5e
0x080494f9    0fb7c0       movzx eax, ax
0x080494fc    890424       mov dword [esp], eax
0x080494ff    e8ccf2ffff   call sym.imp.htons
```

On voit que le compteur passé en argument sert d'index pour un tableau d'entiers.  

Ce tableau est hardcodé et on peut l'afficher avec la commande *px* depuis *radare* :  

```plain
[0x0804a340]> px @ 0x8049ac4
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x08049ac4  5e0d 0000 b411 0000 2317 0000 2609 0000  ^.......#...&...
0x08049ad4  9c15 0000 706f 7274 6b6e 6f63 6b64 3a20  ....portknockd:
```

Les ports utilisés pour le port knocking sont donc les suivants (dans l'ordre) :  

0x0d5e : 3422  

0x11b4 : 4532  

0x1723 : 5923  

0x0926 : 2342  

0x159c : 5532  

Le code suivant permet d'obtenir le flag :  

```python
import socket
import struct
import time

ports = [3422, 4532, 5923, 2342, 5532]

def calc(x, cpt):
    if cpt & 1:
        return x + cpt + 2
    return (cpt + 2) * x

for i, port in enumerate(ports):
    s = socket.socket()
    print "Connexion sur le port", port
    s.connect(('192.168.1.64', port))

    buff = s.recv(4)
    x, = struct.unpack("i", buff)
    print "recu", x
    y = calc(x, i)
    buff = struct.pack("i", y)
    print "envoi", y
    s.send(buff)
    if i == 4:
        print s.recv(32)
    s.close()
    time.sleep(0.1)
```

Exécution :  

```python
Connexion sur le port 3422
recu 99
envoi 198
Connexion sur le port 4532
recu 79
envoi 82
Connexion sur le port 5923
recu 120
envoi 480
Connexion sur le port 2342
recu 68
envoi 73
Connexion sur le port 5532
recu 103
envoi 618
DemonViolatePride346
```

Forever Alone (280 points)
--------------------------

> Terribad Corp has lost the client component of a legacy application that they no longer have the source code for. They want you to reverse engineer the provided server binary and build a client to interact with the server. Once you have done this, the server binary is running on 192.168.1.64 to test your client implementation against.

Ah c'est boulets chez *Terribad Corp* ! :p Ce troisème binaire a les même caractéristiques que le précédent si ce n'est qu'en plus il est linké avec libcrypto (openssl) et libstdc++.  

D'après un *srch\_strings* le binaire a aussi du code en commun avec le binaire précédent (le principe de changement d'utilisateur et de chroot).  

On trouve quelques chaines intéressantes :  

```plain
Connection Timeout
<Not Authenticated>
LUK_MURPHY
!!!Zer0IsTheCoolest!!!
RE03: Authentication failed for user '
RE03: User '
' Authenticated
RE03: Scrambling Key
Test12345678
RE03: Encryption setup failed for authenticated user
' encryption setup
7CClient
RE03: Unknown Command Type:
 SeqID:
        Arg(
) = 
vector::_M_insert_aux
8CCommand
```

Pour permettre l'exécution du programme il faut :  

* créer un dossier /chroots/2013 dans lequel le binaire va chrooter
* créer un groupe sur le système avec le GID 1014
* créer un utilisateur sur le système avec l'ID 2013 et le groupe précédent

On lance alors le programme avec *ltrace* pour voir ce qu'il fait dans le ventre :  

```plain
__libc_start_main(0x804c01f, 1, 0xbfb5dbc4, 0x804c7c0, 0x804c830 <unfinished ...>
_ZNSt8ios_base4InitC1Ev(0x8050234, 0x200246, 0xbfb5dbc4, 1, 0x5c2ff4)              = 0x3c7990
__cxa_atexit(0x80497a0, 0x8050234, 0x8050158, 1, 0x5c2ff4)                         = 0
_ZNSt8ios_base4InitC1Ev(0x8050238, 0x8050234, 0x8050158, 1, 0x5c2ff4)              = 2
__cxa_atexit(0x80497a0, 0x8050238, 0x8050158, 1, 0x5c2ff4)                         = 0
_ZNSt8ios_base4InitC1Ev(0x805023c, 0x8050238, 0x8050158, 1, 0x5c2ff4)              = 3
__cxa_atexit(0x80497a0, 0x805023c, 0x8050158, 1, 0x5c2ff4)                         = 0
getuid()                                                                           = 0
getgid()                                                                           = 0
printf("Currently running as user 0 and group 0")                        = 40
printf("Moving into chroot jail for user 2013. Path = '/chroots/2013')        = 62
chroot(0x804ca83, 2013, 0x804ca83, 0x804c6cf, 1)                                   = 0                                                                                                          
chdir("/")                                                               = 0
printf("Changing group from 0 to 1014")                                  = 30
setgid(1014)                                                                       = 0
printf("Changing user from 0 to 2013")                                   = 29
setuid(2013)                                                                       = 0
puts("Forking...."Forking....)                                           = 12
fork()                                                                             = 6379
printf("Child process 6379 spawned. Original process quitting")          = 54
exit(1 <unfinished ...>
_ZNSt8ios_base4InitD1Ev(0x805023c, 1, 0xbfb5dad8, 0, 0x8048798)                    = 4
_ZNSt8ios_base4InitD1Ev(0x8050238, 1, 0xbfb5dad8, 0, 0x8048798)                    = 3
_ZNSt8ios_base4InitD1Ev(0x8050234, 1, 0xbfb5dad8, 0, 0x8048798)                    = 0x3c74a0
+++ exited (status 1) +++
RE03: Waiting for connections on port 7821
RE03: Connection recieved on port 7821 from client 192.168.151.1
```

L'output généré a été réduit dans un souci de clarté. On voit ici des noms de fonctions bizarres qui correspondent en réalité à du C++.  

ltrace dispose d'une option -C qui fait un demangle de ces noms et les converti en quelque chose de plus parlant :)  

L'option -i nous sera aussi utile car elle affiche l'adresse de l'instruction pour chaque appel de librairie.  

On va devoir aussi utiliser l'option -f pour suivre les processus fils sinon on va rester bloqués au fork().  

On reprend le traçage :  

```plain
[pid 7536] memset(0xbf958a4c, '\000', 16)                                                         = 0xbf958a4c
[pid 7536] htons(7821, 0, 16, 0x804c37e, 3)                                                       = 36126
[pid 7536] bind(3, 0xbf958a4c, 16, 0x804c37e, 3)                                                  = 0
[pid 7536] listen(3, 10, 16, 0x804c37e, 3)                                                        = 0
[pid 7536] std::basic_ostream<char, std::char_traits<char> >& std::operator<< ---snip---
[pid 7536] std::ostream::operator<<(int)(0x80501a0, 7821, 16, 0x804c37e, 3)                       = 0x80501a0
[pid 7536] std::ostream::operator<<(std::ostream& (*)(std::ostream&))(0x80501a0, 0x8049360, 16, 0x804c37e, 3 <unfinished ...>
[pid 7536] std::basic_ostream<char, std::char_traits<char> >& std::endl<char, ---snip--- RE03: Waiting for connections on port 7821) = 0x80501a0
[pid 7536] <... std::ostream::operator<<(std::ostream& (*)(std::ostream&)) resumed> )             = 0x80501a0
[pid 7536] signal(17, 0x00000001)                                                                 = NULL
[pid 7536] accept(3, 0xbf958a4c, 0xbf958a44, 0x70382f, 0xbf958628)                                = 4
[pid 7536] inet_ntoa(0x0197a8c0)                                                                  = "192.168.151.1"
[pid 7536] std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> ---snip---
[pid 7536] std::ostream::operator<<(int)(0x80501a0, 7821, 0xbf958a44, 0x70382f, 0xbf958628)       = 0x80501a0
[pid 7536] std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> ---snip---
[pid 7536] std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> ---snip---
[pid 7536] std::ostream::operator<<(std::ostream& (*)(std::ostream&))(0x80501a0, 0x8049360, 0xbf958a44, 0x70382f, 0xbf958628 <unfinished ...>
[pid 7536] std::basic_ostream<char, std::char_traits<char> ---snip--- RE03: Connection recieved on port 7821 from client 192.168.151.1) = 0x80501a0
[pid 7536] <... std::ostream::operator<<(std::ostream& (*)(std::ostream&)) resumed> )             = 0x80501a0
[pid 7536] fork()                                                                                 = 7540
[pid 7536] close(4)                                                                               = 0
[pid 7536] accept(3, 0xbf958a4c, 0xbf958a44, 0x70382f, 0xbf958628 <unfinished ...>
[pid 7540] <... fork resumed> )                                                             = 0
[pid 7540] close(3)                                                                               = 0
[pid 7540] std::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string()(0xbf958a40, 0x70a6b0, 1331, 0x519fc0, 3) = 0xbf958a40
[pid 7540] std::string::operator=(char const*)(0xbf958a40, 0x804c8a4, 1331, 0x519fc0, 3)          = 0xbf958a40
[pid 7540] signal(14, 0x08049874)                                                                 = NULL
[pid 7540] alarm(30)                                                                              = 0
[pid 7540] recv(4, 0xbf958564, 64, 0, 0)                                                          = 2
[pid 7540] alarm(30)                                                                              = 30
[pid 7540] send(4, 0x804c8b8, 1, 0, 4)                                                            = 1
[pid 7540] close(4)                                                                               = 0
[pid 7540] exit(1 <unfinished ...>
[pid 7540] std::ios_base::Init::~Init()(0x805023c, 1, 0x717ad0, 0, 0x8048798)                     = 4
[pid 7540] std::ios_base::Init::~Init()(0x8050238, 1, 0x717ad0, 0, 0x8048798)                     = 3
[pid 7540] std::ios_base::Init::~Init()(0x8050234, 1, 0x717ad0, 0, 0x8048798)                     = 0x4344a0
[pid 7540] +++ exited (status 1) +++
```

J'ai du couper l'output une fois de plus en raison des noms C++ à rallonge mais on dispose ici de plus d'informations.  

On retrouve un signal+alarm pour compliquer le débogage. Ensuite le programme s'attend à recevoir 64 octets puis en retourne 1 (un code de status vraisemblablement).  

L'analyse se fait donc de la façon suivante : on trace le programme, on regarde ce qu'il attend, on adapte, on retrace, etc.  

Ainsi si on lui envoie 64 octets on a un appel de fonction supplémentaire :  

```plain
[pid 8208] strcasecmp("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., "LUK_MURPHY")
```

En python on lui envoie ce qu'il demande :  

```python
import socket

s = socket.socket()
s.connect(('192.168.151.128', 7821))
buff = "LUK_MURPHY"
buff += "\0" * (64 * len(buff))
s.send(buff)
buff = s.recv(200)
print buff.encode("hex_codec")
s.close()
```

On a cette fois un retour différent :  

```plain
[pid 8644] send(4, 0xbfc7d12c, 4, 0, 0)                                                           = 4
[pid 8644] recv(4, 0xbfc7d174, 20, 0, 0)                                                          = 20
[pid 8644] SHA1_Init(0xbfc7d0cc, 0xbfc7d174, 20, 0, 0)                                            = 1
[pid 8644] SHA1_Update(0xbfc7d0cc, 0xbfc7d12c, 4, 0, 0)                                           = 1
[pid 8644] SHA1_Update(0xbfc7d0cc, 0x804c8c5, 22, 0, 0)                                           = 1
[pid 8644] SHA1_Update(0xbfc7d0cc, 0xbfc7d12c, 4, 0, 0)                                           = 1
[pid 8644] SHA1_Final(0xbfc7d188, 0xbfc7d0cc, 4, 0, 0)                                            = 1
[pid 8644] memcmp(0xbfc7d188, 0xbfc7d174, 20, 0, 0)                                               = 1
[pid 8644] std::basic_ostream<char, std::char_traits<char> >&---snip---) = 0x80501a0
[pid 8644] std::basic_ostream<char, std::char_traits<char> >&---snip---) = 0x80501a0
[pid 8644] std::ostream::operator<<(std::ostream& (*)(std::ostream&))(0x80501a0, 0x8049360, 20, 0, 0 <unfinished ...>
[pid 8644] std::basic_ostream<char, std::char_traits ---snip--- RE03: Authentication failed for user '<Not Authenticated>
```

Ici les méthodes de hashage *d'OpenSSL* sont appelées. Toutefois ltrace ne les reconnait pas et reprend le nombre d'arguments de la précédente fonction sans se poser de question.  

D'après [la documentation d'OpenSSL](https://www.openssl.org/docs/crypto/sha.html) le second argument de *SHA1\_Update* correspond aux données à hasher et le 3ème argument à la taille.  

Ainsi le code fait sha1(données envoyées + 22 octets à 0x804c8c5 + données envoyées).  

Les 22 octets en question sont l'une des chaines vu plus tôt :  

```plain
[0x080499c0]> px @ 0x804c8c5
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0804c8c5  2121 215a 6572 3049 7354 6865 436f 6f6c  !!!Zer0IsTheCool
0x0804c8d5  6573 7421 2121 0052 4530 333a 2041 7574  est!!!.RE03: Aut
```

Mais avant d'aller plus loin on va ajouter des profils *openssl* pour ltrace.  

La page de manuel pour *ltrace.conf* nous renseigne sur la syntaxe à utiliser.  

Sous *openSUSE* j'ai créé le fichier */usr/share/ltrace/libcrypto.so.con*f avec le contenu suivant :  

```plain
addr SHA1(string(array(char, arg2)*), ulong, addr);
int SHA1_Init(addr);
int SHA1_Update(addr, string(array(char, arg3)*), ulong);
int SHA1_Final(addr, addr);

void RC4_set_key(addr, int, string(array(char, arg2)*));
void RC4(addr, ulong, string(array(char, arg2)*), addr);
```

Comme ça lors des prochains appels de ltrace ce dernier connaîtra le nombre d'arguments à afficher ainsi que comment les afficher.  

Dans le code, la partie concernant le hashage se retrouve à *0x08049f31*.  

Il s'avère que les 4 octets envoyés sont un nonce généré aléatoirement.  

```plain
|    `----> 0x0804a040    8d85e8feffff lea eax, dword [ebp - 0x118]
|           0x0804a046    89442404     mov dword [esp + 4], eax ; [:4]=0x10100 ; SHA_CTX struct
|           0x0804a04a    8d45d0       lea eax, dword [ebp - 0x30]
|           0x0804a04d    890424       mov dword [esp], eax                    ; hash (out)
|           0x0804a050    e82bf4ffff   call sym.imp.SHA1_Final  ; <--- fin du calcul du hash
|              sym.imp.SHA1_Final()
|           0x0804a055    85c0         test eax, eax
|           0x0804a057    0f94c0       sete al
|           0x0804a05a    84c0         test al, al
|   ,=====< 0x0804a05c    740e         je 0x804a06c
|   |       0x0804a05e    8b85e4feffff mov eax, dword [ebp - 0x11c]
|   |       0x0804a064    890424       mov dword [esp], eax
|   |       0x0804a067    e86cf9ffff   call 0x80499d8 ; (sub.send_9d7)
|   |          sub.send_9d7()
|   |       ; JMP XREF from 0x0804a05c (sub.send_f31)
|   `-----> 0x0804a06c    8b8548ffffff mov eax, dword [ebp - 0xb8]
|           0x0804a072    8d55d0       lea edx, dword [ebp - 0x30]
|           0x0804a075    89542408     mov dword [esp + 8], edx ; [:4]=0        ; hash
|           0x0804a079    89442404     mov dword [esp + 4], eax ; [:4]=0x10100  ; nonce
|           0x0804a07d    8b85e4feffff mov eax, dword [ebp - 0x11c]             ; SHA_CTX struct
|           0x0804a083    890424       mov dword [esp], eax
|           0x0804a086    e8c9fcffff   call sub._ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_d54
|              sub._ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_d54()
|           0x0804a08b    8b85e4feffff mov eax, dword [ebp - 0x11c]
|           0x0804a091    8d500c       lea edx, dword [eax + 0xc]
|           0x0804a094    8d45d0       lea eax, dword [ebp - 0x30]
|           0x0804a097    89442408     mov dword [esp + 8], eax ; [:4]=0        ; data
|           0x0804a09b    c7442404140. mov dword [esp + 4], 0x14 ; [:4]=0x10100 ; len = 20
|           0x0804a0a3    891424       mov dword [esp], edx                     ; RC4_KEY struct
|           0x0804a0a6    e895f2ffff   call sym.imp.RC4_set_key
```

Jusque là tout allait bien malheureusement à l'adresse *0x0804a086* une fonction s'occupe de mélanger le hash SHA1 généré (comme indiqué dans l'output du programme : *"RE03: Scrambling Key"*).  

Je n'ai pas souhaité analyser cette fonction qui est composée d'environ 150 instructions assembleur pour faire des opérations mathématiques en tout genre.  

A ce stade j'ai préféré hooker la fonction *RC4\_set\_key* et récupérer la clé une fois mélangée. J'en ai profité pour hooker alarm et l'empècher de mettre un timer.  

Pour cela j'ai écrit la librairie suivante (*hook.c*) :  

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

static void (*real_RC4_set_key)(void *key, int len, const unsigned char *data) = NULL ;
static void (*real_alarm)(unsigned int seconds) = NULL ;

void RC4_set_key(void *key, int len, const unsigned char *data)
{
  if (real_RC4_set_key == NULL) {
    unsigned int i;
    FILE * f = NULL;

    real_RC4_set_key = dlsym(RTLD_NEXT, "RC4_set_key");
    if (dlerror() != NULL) {
      printf("Le hook a echoue\n");
      exit(1);
    }
    f = fopen("/rc4_key.txt", "w+");
    if (f == NULL) perror("Erreur ouverture fichier");
    for (i=0; i<len; i++) {
      fprintf(f, "%02X", data[i]);
    }
    fclose(f);
  }
  return real_RC4_set_key(key, len, data);
}

void alarm(unsigned int seconds)
{
  if (real_alarm == NULL) {
    real_alarm = dlsym(RTLD_NEXT, "alarm");
  }
  return real_alarm(0);
}
```

On compile ça de cette façon (j'utilise m32 car le binaire du challenge est en 32bits) :  

```bash
gcc -Wall -fPIC -c -o hook.o hook.c -m32
gcc -shared -fPIC -Wl,-soname -Wl,libhook.so -o libhook.so hook.o -m32
```

Il suffit alors de tracer à nouveau le programme en utilisant *LD\_PRELOAD* :  

```bash
LD_PRELOAD=libhook.so ltrace -i -f -C ./binary3
```

*LD\_PRELOAD* permet de spécifier une librairie prioritaire pour la recherche des fonctions. Dans le code la constante *RTLD\_NEXT* passée à *dlsym* indique qu'il faut passer la main à la prochaine fonction correspondant au symbole (soit la fonction légitime).  

Ici le hook de *RC4\_set\_key* dumpe la clé dans un fichier texte tandis que le hook de *alarm* modifie l'argument passé (annulant ainsi l'alarme).  

Mais revenons à nos moutons : la hash SHA1 mélangé sert de clé pour des échanges chiffrés RC4.  

*RC4* est un *"stream cipher"*, il garde un "état" d'où il est en dans le chiffrement. Ainsi si vous chiffrez A puis ensuite B alors le chiffrement de B ne donnera pas le même résultat que vous si aviez chiffré directement B sans passer par A et ce même si vous avez utilisé la même clé !  

Ca veut dire que dans une communication *RC4* entre deux pairs, les deux protagonistes doivent avoir chiffré les même données pour être dans le même état et se comprendre.  

Après avoir pris cela en compte et quelques ltrace plus tard on a le client suivant (ici je me connecte à ma copie locale du binaire en raison du dump) :  

```python
s = socket.socket()
s.connect(('192.168.1.3', 7821))
print "[*] Connecting to server"
buff = "LUK_MURPHY\0"
buff += "\0" * (64 - len(buff))
s.send(buff)
nonce = s.recv(4)
print "[i] AUTH nonce = {0}".format(nonce.encode("hex_codec"))
s.send(hashlib.sha1(nonce + key + nonce).digest())
status = ord(s.recv(1)[0])

if status:
    print "[!] AUTH: failure"
    sys.exit()
print "[i] AUTH: success"

nonce = s.recv(4)
print "[i] RC4 nonce = {0}".format(nonce.encode("hex_codec"))

rc4_key = hashlib.sha1(key + nonce).digest()
print "[i] rc4_key = {0}".format(rc4_key.encode("hex_codec"))

print "[*] Launching gdb session"
create_command_file(struct.unpack("I", nonce)[0], rc4_key)

data = s.recv(16)
print "[*] received {0}".format(data.encode("hex_codec"))

# lecture du dump
fd = open("/chroots/2013/rc4_key.txt")
scrambled_key = fd.read(40).decode("hex_codec")
fd.close()

print "[i] scrambled RC4 key =", scrambled_key.encode("hex_codec")
cipher = ARC4.new(scrambled_key)
enc_data = cipher.encrypt("Test12345678\0\0\0\0")
if data != enc_data:
    print "[!] Encryption mismatch!"
    sys.exit()
m = cipher.encrypt("Test12345678\0\0\0\0")
s.send(m)
s.recv(1)
# Here everything should be fine.
```

Pour vérifier que le *RC4* a été correctement mis en place chez le client, le serveur suit les opérations suivantes :  

```plain
[pid 16149] [0x804a0ab] RC4_set_key(0xffaf1a98, 20, "\027EC&d\227g\016\270\031W\300\330\232\370Z\a\225r\034")                   = <void>
[pid 16149] [0x804a0c6] strncpy(0xffaf1a1c, "Test12345678", 16)                                                                 = 0xffaf1a1c
[pid 16149] [0x804a2c7] RC4(0xffaf1a98, 16, "Test12345678\0\0\0\0", 0xffaf1988)                                                 = <void>
[pid 16149] [0x804a11f] send(4, 0xffaf1988, 16, 0)                                                                              = 16
[pid 16149] [0x804a167] recv(4, 0xffaf1988, 16, 0)                                                                              = 16
[pid 16149] [0x804a2c7] RC4(0xffaf1a98, 16, "\227\200\255\342\227\235\033W\313\354G\033\031\202\207\334", 0xffaf1a1c)           = <void>
[pid 16149] [0x804a1be] strcmp("Test12345678", "Test12345678")                                                                  = 0
```

Il chiffre *"Test12345678"* avec la clé et envoie le résultat au client. Ensuite il reçoit une réponse du client en *RC4*, la déchiffre et regarde s'il s'agit de *"Test12345678"*.  

En raison de la notion d'état, le client ne peut pas se contenter de renvoyer ce qu'il a reçu : il faut qu'il chiffre deux fois la chaine et envoie le résultat, d'où le code Python précédent.  

A ce stade on a fait une bonne partie. Ensuite le serveur attend 5 octets (chiffrés en *RC4*) qui après plusieurs tests se révèlent être un numéro de commande (premier octet) et une taille (deux derniers octets).  

La lecture qui suit semble se faire via des blocks de 256 octets (256 \* la taille spécifiée) . Ainsi si on envoie *"\x04\x00\x00\x00\x01"* chiffré en *RC4* :  

```plain
[pid 16149] [0x804a341] recv(4, 0xffaf1a27, 5, 0)                                      = 5
[pid 16149] [0x804a361] alarm(30)                                                      = 0
[pid 16149] [0x804a2c7] RC4(0xffaf1a98, 5, "1\026R\314\177", 0xffaf1a03)     = <void>
[pid 16149] [0x804a396] operator new[](unsigned int)(257, 0xffaf1a27, 0xffaf1a03, 5)   = 0x88d32b8
[pid 16149] [0x804a3c4] operator new[](unsigned int)(256, 0xffaf1a27, 0xffaf1a03, 5)   = 0x88d33c0
[pid 16149] [0x804a41e] recv(4, 0x88d33c0, 256, 0)                                     = 256
```

Une fois qu'il a lu ses 256 octets ils les déchiffre via *RC4* puis il procède un découpage de la chaîne obtenue via *strtok* (avec le séparateur ';').  

Je me suis aussi rendu compte assez vite que si le premier des 5 octets précédent vaut 0 alors on semble entrer dans un mode de débogage :  

```plain
RE03: Unknown Command Type: SeqID:0
Arg(0) = chaine_avant_point_virgule
Arg(1) = chaine_apres_point_virgule
```

On sait donc à quoi correspond les paquets que l'on envoie :)  

Le parseur de ces 5 octets se trouve à l'adresse *0x0804aadb* où l'on trouve un switch/case sur le premier octet :  

```plain
|    0x0804aa0b    0fb6c0       movzx eax, al
|    0x0804aa0e    83f805       cmp eax, 5
|,=< 0x0804aa11    0f87a4000000 ja 0x804aabb
||   0x0804aa17    8b0485c0c90. mov eax, dword [eax*4 + 0x804c9c0] ; [:4]=0x804aa00
`==< 0x0804aa1e    ffe0         jmp eax
```

L'adresse de saut pour chacun des cas s'obtient facilement avec *radare2* ou *gdb* :  

```plain
(gdb) x/6wx 0x804c9c0
0x804c9c0:      0x0804aabb      0x0804aa5c      0x0804aa20      0x0804aa3e
0x804c9d0:      0x0804aa7e      0x0804aaa0
```

En jetant un œil à chaque case on en tire deux du lots :  

* case 3 : permet de lister le contenu d'un dossier, l'argument est alors le nom du dossier
* case 4 : permet de récupérer le contenu d'un fichier. Les opérations sont faites en C++ via *ifstream*.

A ce stade on comprend que le flag n'est pas sous forme chiffrée dans le binaire et donc qu'il va vraiment falloir s'occuper de la fonction de mélange de la clé car on ne peut pas tracer le binaire sur le serveur du challenge :p  

Mais n'ayant toujours pas envie de lire ce code assembleur j'ai choisi de le réutiliser en l'appelant directement depuis gdb.  

Le prototype de la fonction est le suivant : *scramble\_key(CTX, nonce, sha1)*.  

L'idée est donc de placer dans la mémoire du processus local une nonce et un hash sha1 de notre choix puis de forcer EIP à l'adresse de la fonction. On peut ensuite lire le résultat dans la mémoire du processus.  

Mais on ne peut pas le faire n'importe comment : le programme a besoin de s'initialiser. On va donc commencer par mettre un breakpoint sur l'adresse de la fonction principale du programme (celle qui commence par *getuid* soit *0x0804be54*) avant de forcer le saut vers les instructions que voici qui mettent sur la pile les arguments pour notre fonction cible :  

```plain
0x0804a075    89542408     mov dword [esp + 8], edx ; [:4]=0
0x0804a079    89442404     mov dword [esp + 4], eax ; [:4]=0x10100
0x0804a07d    8b85e4feffff mov eax, dword [ebp - 0x11c]
0x0804a083    890424       mov dword [esp], eax
0x0804a086    e8c9fcffff   call scramble_key
0x0804a08b    8b85e4feffff mov eax, dword [ebp - 0x11c]
0x0804a091    8d500c       lea edx, dword [eax + 0xc]
0x0804a094    8d45d0       lea eax, dword [ebp - 0x30]
0x0804a097    89442408     mov dword [esp + 8], eax ; [:4]=0
0x0804a09b    c7442404140. mov dword [esp + 4], 0x14 ; [:4]=0x10100
0x0804a0a3    891424       mov dword [esp], edx
0x0804a0a6    e895f2ffff   call sym.imp.RC4_set_key
```

Donc il faut que l'on break sur le début, que l'on place le hash SHA1 en mémoire (on utilisera pour cela la pile, en particulier les adresses les plus basses car non-utilisées), que l'on fixe edx et eax (3ème et second argument), que l'on step 3 fois (pour arriver sur *0x0804a083*) et que l'on refixe eax (premier argument).  

Ensuite on break après l'appel de *scramble\_key()* (par exemple à *0x0804a097*) et on dumpe la zone mémoire de notre hash modifié... ouf.  

Mettons que la nonce soit *0xc0aa44f7*, que la hash soit 2f510f61f09285f01f59b4816ced908b4fb1a0c7 et que l'on souhaite écrire en mémoire à partir de l'adresse *0xfffdd000* alors on aura le fichier de commandes GDB suivant :  

```plain
b *0x0804be54
b *0x0804a075
r
set $eip=0x0804a075
c
set {int}0xfffdd000 = 0x610f512f
set {int}0xfffdd004 = 0xf08592f0
set {int}0xfffdd008 = 0x81b4591f
set {int}0xfffdd00c = 0x8b90ed6c
set {int}0xfffdd010 = 0xc7a0b14f
set $edx=0xfffdd000
set $eax=0xf744aac0
si
si
si
set $eax=0xfffdd014
b *0x0804a097
c
dump binary memory /tmp/result.bin 0xfffdd000 0xfffdd014
```

Ce qui nous donne le client Python suivant :  

```python
import socket
import hashlib
import sys
from Crypto.Cipher import ARC4
import time
import struct
import os

key = "!!!Zer0IsTheCoolest!!!"

def create_command_file(nonce, key):
    fd = open("/tmp/gdb_commands.txt", "w")
    fd.write("b *0x0804be54\n")
    fd.write("b *0x0804a075\n")
    fd.write("r\n")
    fd.write("set $eip=0x0804a075\n")
    fd.write("c\n")
    start_addr = 0xfffdd000
    hex_values = [hex(x) for x in struct.unpack("IIIII", key)]
    for i, hex_val in enumerate(hex_values):
        fd.write("set {{int}}{0} = {1}\n".format(hex(start_addr + (4 * i)), hex_val))
    fd.write("set $edx={0}\n".format(hex(start_addr)))
    fd.write("set $eax={0}\n".format(hex(nonce)))
    fd.write("si\n" * 3)
    fd.write("set $eax=0xfffdd014\n")
    fd.write("b *0x0804a097\n")
    fd.write("c\n")
    fd.write("dump binary memory /tmp/result.bin 0xfffdd000 0xfffdd014\n")
    fd.close()

s = socket.socket()
s.connect(('192.168.1.64', 7821))
print "[*] Connecting to server"
buff = "LUK_MURPHY\0"
buff += "\0" * (64 - len(buff))
s.send(buff)
nonce = s.recv(4)
print "[i] AUTH nonce = {0}".format(nonce.encode("hex_codec"))
s.send(hashlib.sha1(nonce + key + nonce).digest())
status = ord(s.recv(1)[0])

if status:
    print "[!] AUTH: failure"
    sys.exit()
print "[i] AUTH: success"

nonce = s.recv(4)
print "[i] RC4 nonce = {0}".format(nonce.encode("hex_codec"))

rc4_key = hashlib.sha1(key + nonce).digest()
print "[i] rc4_key = {0}".format(rc4_key.encode("hex_codec"))

print "[*] Launching gdb session"
create_command_file(struct.unpack("I", nonce)[0], rc4_key)

data = s.recv(16)
print "[*] received {0}".format(data.encode("hex_codec"))

if os.path.isfile("/tmp/result.bin"):
    os.unlink("/tmp/result.bin")
os.system("gdb -q -batch -x /tmp/gdb_commands.txt /tmp/binary3")
scrambled_key = open("/tmp/result.bin").read()

print "[i] scrambled RC4 key =", scrambled_key.encode("hex_codec")
cipher = ARC4.new(scrambled_key)
enc_data = cipher.encrypt("Test12345678\0\0\0\0")
if data != enc_data:
    print "[!] Encryption mismatch!"
    sys.exit()
m = cipher.encrypt("Test12345678\0\0\0\0")
s.send(m)
s.recv(1)

time.sleep(1)
arg = "."
m = cipher.encrypt("\x03\x00\x00\x00\x01")
s.send(m)
m = cipher.encrypt(arg + "\0" * (256 - len(arg)))
s.send(m)
buff = s.recv(100)
m = cipher.decrypt(buff)
print repr(m)
s.close()
```

Résultat :  

```plain
[*] Connecting to server
[i] AUTH nonce = c41433df
[i] AUTH: success
[i] RC4 nonce = c69b84d1
[i] rc4_key = 3cb8a2e721b7d9fcdf9e389764453727d6c30483
[*] Launching gdb session
[*] received 04675f49391c58eb88d17365f68ab3d7

Breakpoint 1 at 0x804be54
Breakpoint 2 at 0x804a075

Breakpoint 1, 0x0804be54 in ?? ()

Breakpoint 2, 0x0804a075 in ?? ()
0x0804a079 in ?? ()
0x0804a07d in ?? ()
0x0804a083 in ?? ()
Breakpoint 3 at 0x804a097
RE03: Scrambling Key

Breakpoint 3, 0x0804a097 in ?? ()
[i] scrambled RC4 key = 64c9f0ccbfd2f17a4f46b5a437f60790ae52ed4b
'\x03\x00\x00\x00&\x00lib;.;dev;bin;..;etc;thisistheflag.txt'
```

Yes ! On change ensuite l'argument pour *thisistheflag.txt* et l'octet de commande de 3 à 4 :  

```plain
[*] Connecting to server
[i] AUTH nonce = 4161302f
[i] AUTH: success
[i] RC4 nonce = bf2b7c69
[i] rc4_key = 3908370f4dade34761a2dc81dfc784c02fd78df3
[*] Launching gdb session
[*] received 854d3873689865b3a63e3fc49611f580

Breakpoint 1 at 0x804be54
Breakpoint 2 at 0x804a075

Breakpoint 1, 0x0804be54 in ?? ()

Breakpoint 2, 0x0804a075 in ?? ()
0x0804a079 in ?? ()
0x0804a07d in ?? ()
0x0804a083 in ?? ()
Breakpoint 3 at 0x804a097
RE03: Scrambling Key

Breakpoint 3, 0x0804a097 in ?? ()
[i] scrambled RC4 key = 3452e8b6ae6fa9b9be279a5061f26624c4542e08
'\x04\x00\x00\x00\x1d\x00HandleLoganNepenthes415\n\x99\xdft\xc81'
```

ROOT DANCE !!!

*Published December 26 2014 at 11:46*