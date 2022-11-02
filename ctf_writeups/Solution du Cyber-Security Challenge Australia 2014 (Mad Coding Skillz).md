# Solution du Cyber-Security Challenge Australia 2014 (Mad Coding Skillz)

Après avoir solutionné [la partie reverse-engineering du CySCA 2014](http://devloop.users.sourceforge.net/index.php?article113/solution-du-cyber-security-challenge-australia-2014-reverse-engineering), quoi de plus naturel que d’enchaîner sur les épreuves de programmation ?  

Bien qu'étant développeur ça n'a pas été de tout repos :)  

Jeremy's Iron (120 points)
--------------------------

Ce premier exercice est très simple, à tel point que c'est la première épreuve que j'ai résolu sur le *CySCA* : c'était sur mon chemin :p  

La description du level est la suivante :  

> FortCerts needs you to write a program to test the functionality of a customers anagram program. Write a program that will unscramble the given word from a list of words and return it to the server. To be sure that the testing is reliable you will need to do this multiple times before the flag is revealed. The customer program is running at 192.168.1.64:5050

On a donc un serveur qui nous demande de retrouver des anagrammes. Voici un aperçu ce qu'on obtient à la connexion :  

```plain
                Welcome to the jumbled word server.
                ==============================
[+] Unjumble 50 words sequentially within 60 seconds.
Wordlist: ['psychologically', 'ineffectiveness', 'appropriateness', 'unceremoniously', 'anthropological', 'revolutionaries',
'psychotherapies', 'interpretations', 'procrastination', 'substantiations', 'acclimatization', 'servomechanisms', 'recommendations',
'instrumentation', 'representatives', 'psychoanalyzing', 'lackadaisically', 'acknowledgments', 'decontaminating', 'interdependence',
'temperamentally', 'conglomerations', 'tonsillectomies', 'unimplementable', 'implementations']
Jumbled word: niisseeftnvecef
Enter unjumbled word:
```

La méthode que j'ai utilisé est très basique : pour chaque mot donné je réordonne les lettres en ordre alphabétique. Je fais de même avec le "jumbled word" ce qui me permet au final de faire une simple comparaison pour retrouver l'anagramme.  

Ma solution peut vraisemblablement être optimisée mais elle permet tout de même de répondre aux 50 questions dans le délai imparti :  

```python
import socket
import json

sock = socket.socket()
sock.connect(('192.168.1.64', 5050))
sock.recv(2048) # Instructions

for __ in xrange(0, 50):
    buff = sock.recv(2048)[10:].strip().replace(chr(39), chr(34))# wordlist
    words = json.loads(buff)
    jumbled = sock.recv(1024).strip().split(": ", 1)[1] # Jumbled word
    sorted_jumbled = "".join(sorted([c for c in jumbled]))
    sock.recv(1024) # Unjumbled word prompt

    for word in words:
        sorted_word = "".join(sorted([c for c in word]))
        if sorted_jumbled == sorted_word:
            print jumbled, "=>", word
            sock.send(word + "\n")
            break
buff = sock.recv(2048)
print buff
```

Output du programme :  

```plain
dstoaniucnition => discontinuation
iuhillcytmeapes => euphemistically
ticsosatntnolui => constitutionals
txaensetsitiisl => existentialists
--- snip ---
smaapsrsbohisda => ambassadorships
iuonsleanatynts => instantaneously
oarizmdncoeitta => democratization
ueoncsiscoesssn => consciousnesses
IndianAttemptGermany771
```

Autobalanced (200 points)
-------------------------

Les exercices de la partie programmation sont très inégaux et les points de récompense sont mal proportionnés par rapport à leur difficulté.  

Ainsi dès ce second level on fait un énorme saut dans la difficulté.  

Voici les instructions reçues lors de la connexion au serveur :  

```plain
Welcome to the Fortcerts secure server. This server is protected by a challenge response authentication method.
At Fortcerts we do not believe in security by obscurity: the response must sum to zero.
Possible responses are a list of integers separated by spaces or the string 'no solution' (because the server is ultra-secure sometimes there may not be a solution).
Generating challenge...

Round: 1
Required response length: 15
Challenge: 914 842 1096 622 -480 330 202 908 -781 571 974 -56 -118 29 637 647 400 -505 -360 -438 -192 956 764 378 517 -123 442 657
```

On a donc plusieurs rounds à passer. A chaque round on reçoit une série de 28 entiers positifs ou négatifs ainsi qu'un nombre d'entiers N à utiliser parmi ces 28.  

On doit choisir nos N entiers parmi la liste de telle façon que leur somme donne 0.  

Ainsi pour l'exemple précédent on peut trouver au moins 3 solutions :  

```plain
[-781, -505, -480, -438, -360, -192, -123, -56, 29, 202, 330, 378, 400, 622, 974]
[-781, -505, -480, -438, -360, -192, -123, -118, -56, 29, 202, 442, 637, 647, 1096]
[-781, -505, -480, -438, -360, -192, -123, -118, -56, 29, 202, 330, 622, 914, 956]
```

Si on ne saisi pas de réponses on fini par recevoir le message suivant :  

> Timeout. Challenge-Response handshake must complete in 8 seconds

Or il s'avère (une fois que l'on a solutionné l'exercice) qu'il y a 10 rounds à passer.  

Toute la difficulté se base par conséquence sur notre faculté à résoudre chaque round en un temps record, sachant que certains rounds n'ont pas de solutions ce qui implique d'avoir testé toutes les combinaisons possibles pour s'en assurer !  

On peut utiliser la méthode *combinations* du module Python *itertools* qui générera pour nous les combinaisons possible. Il ne nous reste plus qu'à faire à chaque fois la somme et regarder si le résultat est nul ce qui nous donne l'implémentation naïve suivante :  

```python
from itertools import combinations
from time import time

numbers = [914, 842, 1096, 622, -480, 330, 202, 908, -781, 571, 974, -56, -118, 29,
        637, 647, 400, -505, -360, -438, -192, 956, 764, 378, 517, -123, 442, 657]

start = time()
for l in combinations(numbers, 15):
    if sum(l) == 0:
        print l
        break
end = time()
print end - start
```

Pour ce cas concret sur ma machine équipée d'un quad-core *i3* une solution est trouvée... en plus de 5 secondes ce qui est inacceptable (on se fait éjecter dès le second round).  

Ma première idée fut de réaliser un tri des 28 entiers avant de tester les différentes combinaisons possibles.  

J'ai écrit un programme de benchmark qui teste pour 17 cas (dont 3 sans solutions) la recherche d'une solution avec la liste dans 4 configurations possibles :  

* telle qu'envoyée par le serveur (désordonnée)
* triée par valeur absolue croissante
* triée par valeur absolue décroissante
* triée par valeur absolue croissante, les entiers du milieu étant ensuite replacés au début

J'obtiens les moyennes de temps suivantes :  

```plain
Original: 4.3500373644
Sorted: 1.45088425805
Sorted and reversed: 5.99907659082
Sorted then middle first: 1.9514651579
```

On obtient donc les meilleurs résultats pour un tri croissant par valeur absolue malheureusement on est encore au dessus de la seconde alors qu'il faudrait être à 0.8 secondes.  

Le problème de notre système de combinaisons c'est que l'on ré-effectue l'ensemble de l'addition à chaque fois. Par conséquent pour les combinaisons A+B+C+D et A+B+C+E on recalcule A+B+C alors qu'on aurait pu stocker son résultat.  

Heureusement [la page du module *itertools*](https://docs.python.org/2/library/itertools.html#itertools.combinations) contient l'équivalent Python de la méthode *combinations*.  

On peut donc écrire la méthode de cassage suivante :  

```python
def crack(iterable, r):
    pool = tuple(iterable)
    n = len(pool)
    if r > n:
        return
    indices = range(r)
    total = reduce(add, (pool[i] for i in indices))
    if total == 0:
        return [pool[i] for i in indices]
    while True:
        for i in reversed(range(r)):
            if indices[i] != i + n - r:
                break
        else:
            return
        total -= pool[indices[i]]
        indices[i] += 1
        total += pool[indices[i]]
        for j in range(i+1, r):
            total -= pool[indices[j]]
            indices[j] = indices[j-1] + 1
            total += pool[indices[j]]
        if total == 0:
            return [pool[i] for i in indices]
```

Cette méthode est à double-tranchants : on obtient des résultats satisfaisants (de l'ordre des dixièmes de seconde) avec une liste triée mais le durée de traitement s'affole (quasiment 1 minute) quand aucune solution n'est possible.  

La solution finale a consisté en plusieurs points :  

* distribuer le calcul et distribuer l'ordre d'une même liste pour augmenter les chances de réussite
* considérer qu'aucune solution n'existe après un certain nombre de combinaisons testées
* répondre systématiquement "no solution" sur les questions impliquant 18 entiers ou plus (après plusieurs tests ils semblent qu'il n'y ait jamais ou très peu de solutions dans ces cas... c'est un peu de la triche mais ça marche)

Pour le calcul distribué je me suis orienté vers deux solutions possibles :  

* [dispy](http://dispy.sourceforge.net/)
* [RPyC](http://rpyc.readthedocs.org/en/latest/)

J'ai retenu *dispy* pour sa facilité d'utilisation en particulier la manière transparente dont il retransfère le code à exécuter vers les nodes.  

```python
from operator import add
import sys
import time
import dispy
import socket
from random import shuffle

def setup():
    global add
    from operator import add
    return 0

def cleanup():
    del globals()['add']

def crack(iterable, r, limit):
    global add
    pool = tuple(iterable)
    n = len(pool)
    if r > n:
        return "no solution"
    indices = range(r)
    total = reduce(add, (pool[i] for i in indices))
    if total == 0:
        return [pool[i] for i in indices]
    count = 0
    while True:
        for i in reversed(range(r)):
            if indices[i] != i + n - r:
                break
        else:
            return
        total -= pool[indices[i]]
        indices[i] += 1
        total += pool[indices[i]]
        for j in range(i+1, r):
            total -= pool[indices[j]]
            indices[j] = indices[j-1] + 1
            total += pool[indices[j]]
        if total == 0:
            return [pool[i] for i in indices]
        if count >= limit:
            return "no solution"
        count += 1
    return "no solution"

sock = socket.socket()
sock.connect(('192.168.1.64', 9876))
print sock.recv(1024)  # banner

cluster = dispy.JobCluster(crack, setup=setup, cleanup=cleanup)

while True:
    buff = sock.recv(500)
    print "recu", buff
    lines = buff.splitlines()
    response_length = 0
    numbers = None

    for line in lines:
        if "Round:" in line:
            print line
        elif "Required response length:" in line:
            response_length = int(line.split(":")[1])
            print "required length:", response_length
        elif "Challenge:" in line:
            data = line.split(":", 1)[1]
            numbers = [int(x) for x in data.split()]
            print ">", numbers
            negatives = []
            positives = []
            for x in numbers:
                if x < 0:
                    negatives.append(x)
                else:
                    positives.append(x)
            max_negatives = sum(negatives)
            max_positives = sum(positives)
            numbers = [x for x in numbers if x < max_positives and x > max_negatives]
        elif "Timeout" in line:
            print "Fail : timeout :("
            sys.exit()
        elif "Incorrect" in line:
            print line
            sys.exit()
        else:
            print "Unknown line:", line
            break

    ret = "no solution"
    if response_length > 17:
        sock.send(ret)
        buff = sock.recv(2014)
        print "buff triche >", buff
        if "Timeout" in buff:
            sock.close()
            sys.exit()
        elif "Incorrect" in buff:
            sock.close()
            sys.exit()
        continue

    # first case
    jobs = []
    limit = 1500000

    # sorted on absolute value ascending
    numbers.sort(cmp=lambda x, y: cmp(abs(x), abs(y)))

    # start with the middle of the previous list
    new_list = numbers[4:24] + numbers[:4] + numbers[24:]
    job = cluster.submit(new_list, response_length, limit)
    jobs.append(job)

    job = cluster.submit(numbers, response_length, limit)
    jobs.append(job)

    # sorted on abs, reversed
    numbers.reverse()
    job = cluster.submit(numbers, response_length, limit)
    jobs.append(job)

    # random
    shuffle(numbers)
    job = cluster.submit(numbers, response_length, limit)
    jobs.append(job)

    print "Waiting for jobs..."
    for job in jobs:
        response = job()
        print "Received solution", response
        if isinstance(response, list):
            ret = " ".join((str(x) for x in response))
        elif isinstance(response, str):
            ret = response
        break
    for job in jobs:
        if job.status in [dispy.DispyJob.Created, dispy.DispyJob.Running, dispy.DispyJob.ProvisionalResult]:
            cluster.cancel(job)

    sock.send(ret)
    buff = sock.recv(2014)
    print "buff >", buff
    if "Timeout" in buff:
        sock.close()
        sys.exit()
    elif "Incorrect" in buff:
        sock.close()
        sys.exit()

    print "===================="
```

Ici chaque node (lancée simplement avec la commande *dispynode.py -i adresse\_ip\_node*) va obtenir la liste dans un ordre particulier, le nombre d'entiers à utiliser et la limite de tours de boucles (ici 1500000) avant de considérer qu'aucune solution n'est présente.  

La méthode *crack()* est envoyée aux nodes et doit être conçue pour être indépendante. En temps normal on mettra par exemple les imports nécessaires directement dans la méthode.  

Ici pour gagner du temps de calcul, les imports nécessaires sont fait dans la méthode *setup()* et la fonction *add()* importée est marquée globale pour être utilisée ensuite.  

Enfin la fonction *cleanup()* libère la mémoire utilisée par l'import (décharge le module).  

Quand une première node retourne un résultat on annule le travail en cours sur les autres et on donne le résultat au serveur de jeu.  

Dernier point : la liste de 28 entiers reçue est analysée afin de retirer les entiers inutilisables (cas où la somme des entiers de signe opposés ne permettent pas de contrebalancer un entier trop important) ce qui malheureusement arrive peu souvent.  

J'ai utilisé quatre machines pour lancer l'attaque :  

* ASUS Notebook Pentium dual-core T4200 (2 coeurs à 2Ghz) sous Windows 7
* Ultrabook Dell XPS 13 Intel core i7 (4 coeurs à 2Ghz) sous Lubuntu 14.04
* LDLC PC SSD-In Extensor Intel core i3 (4 coeurs à 3.30Ghz) sous openSUSE 13.2
* Apple MacBook Pro core i7 (4 coeurs à 2.6Ghz) sous OSX 10.9.5

Le résultat généré est assez verbeux :  

```plain
recu Round: 1
Required response length: 16
Challenge: 628 1138 413 -389 725 -133 1059 676 427 175 197 -609 1004 -16 483 550 898 709 -521 496 -345 875 -227 984 307 -373 -110 654

Round: 1
required length: 16
> [628, 1138, 413, -389, 725, -133, 1059, 676, 427, 175, 197, -609, 1004, -16, 483, 550, 898, 709, -521, 496, -345, 875, -227, 984, 307, -373, -110, 654]
Waiting for jobs...
Received solution [197, -227, 307, -345, -373, -389, 413, 427, -521, 550, -609, 654, -16, -110, -133, 175]
buff > Correct.

====================
recu Round: 2
Required response length: 10
Challenge: 1123 1079 240 1151 502 -305 384 708 -303 -150 410 -571 464 178 -63 828 156 462 324 720 722 -45 746 -523 -200 614 351 106

Round: 2
required length: 10
> [1123, 1079, 240, 1151, 502, -305, 384, 708, -303, -150, 410, -571, 464, 178, -63, 828, 156, 462, 324, 720, 722, -45, 746, -523, -200, 614, 351, 106]
Waiting for jobs...
Received solution [156, 178, -200, 240, -303, 502, -571, -45, -63, 106]
buff > Correct.

====================
--- snip ---

recu Round: 9
Required response length: 17
Challenge: 748 806 1023 -830 434 162 285 168 730 -421 791 392 -189 -30 1143 908 -700 -288 -509 380 -83 962 1163 1132 5 -330 1143 872

Round: 9
required length: 17
> [748, 806, 1023, -830, 434, 162, 285, 168, 730, -421, 791, 392, -189, -30, 1143, 908, -700, -288, -509, 380, -83, 962, 1163, 1132, 5, -330, 1143, 872]
Waiting for jobs...
Received solution [168, -189, 285, -288, -330, 392, -421, 434, -509, -700, 791, -830, 5, -30, -83, 162, 1143]
buff > Correct.

====================
recu Round: 10
Required response length: 18
Challenge: 545 562 620 640 495 68 -72 270 202 673 230 -299 240 900 -777 899 -75 161 324 451 99 651 428 -435 993 741 794 79

Round: 10
required length: 18
> [545, 562, 620, 640, 495, 68, -72, 270, 202, 673, 230, -299, 240, 900, -777, 899, -75, 161, 324, 451, 99, 651, 428, -435, 993, 741, 794, 79]
buff triche > Correct.

recu Flag: PanoramaSpaceBackflip582
```

Spelunking! (280 points)
------------------------

> FortCerts are working on a breakthrough project known as project EVATAR. Using the EVATAR interface,
> players use neural brain circuit interferometry to control a real person trying to escape from a dangerous scenario.
> In this case, the scenario is a person stuck in a cave (with steps, apparently). Write a program to control your EVATAR to find
> the key and escape the maze. Watch your EVATAR's step though, the ceiling may be unstable.
> The project EVATAR access interface is located at 192.168.1.64:7788. Also don't tell anyone, it's super hush hush.

On a donc un scénario [de sortie de labyrinthe](https://en.wikipedia.org/wiki/Maze_solving_algorithm). Quand on se connecte au serveur on peut communiquer en utilisant un nombre limité de commandes :  

```plain
Please wait while the map loads...
Map loaded.
help
Invalid command: help. Possible commands include are: ['north', 'south', 'east', 'west', 'up', 'down', 'pickup', 'escape']
north
There is a wall there.
east
There is a wall there.
west
There is a wall there.
south
You moved south.
south
You moved south.
south
There is a wall there.
```

Toute l'exploration du labyrinthe va se faire ainsi, en découvrant au fur et à mesure de nouveaux messages d'erreurs (ou de succès).  

La première implémentation du mon robot utilisait la seule technique que je connaissais pour sortir d'un labyrinthe : on pause la main gauche sur le mur gauche (ou main droite sur le mur droit) puis on longe le mur jusqu'à arriver à la sortie.  

Cette technique simple fonctionne sur des labyrinthes basiques malheureusement la configuration du challenge est différente : en affichant les directions prises par mon robot j’observais des suites qui se répétaient.  

Le labyrinthe est en réalité composé d’îlots, comme si vous commenciez la partie par poser la main sur un pilier et continuiez indéfiniment à tourner autour de ce pilier.  

L'algorithme de [Pledge](https://interstices.info/jcms/c_46065/l-algorithme-de-pledge) permet de se sortir de ce genre de situations en définissant en plus une direction d'exploration principale.  

Mais ici il faut prendre une autre particularité en compte : on ne souhaite pas sortir immédiatement du labyrinthe mais d'abord récupérer une clé pour laquelle il faudra d'abord explorer toutes les branches du labyrinthe.  

Parmi [les différents algorithmes d'explorations](http://www.astrolog.org/labyrnth/algrithm.htm#solve), celui de *Charles Pierre Trémaux* m'a semblé le plus adapté.  

Il consiste grosso-modo à marquer à la craie le chemin que l'on prend. Arrivé à un croisement on prend par exemple le chemin le plus à notre gauche et on le marque. Si on revient sur se croisement on suit le chemin de gauche suivant et ainsi de suite jusqu'à avoir passé en revue toutes les possibilités.  

Dans le cadre de ce level on ne peut pas réellement marquer à la craie les chemins, on va donc garder en permanence un tableau des coordonnées visitées. Puisque chaque direction saisie qui n'amène pas dans un mur nous fait avancer de la même unité de distance c'est simple à faire.  

Si l'on se retrouve sur un ilôt il suffit de confronter les coordonnées de la nouvelle position à celles existantes pour déterminer si les cellules voisines sont inconnues ou en réalité déjà explorées.  

Arrivé à ce stade du développement je suis en mesure d'explorer un étage, trouver et prendre un escalier qui monte (up) s'il y en a un ou prendre la clé (pickup) si elle est présente.  

La saisie de la clé provoque un décompte dont on est averti de cette façon :  

```plain
You picked up the key.
The ceiling starts to collapse.
Get out of here!
```

On dispose donc d'un nombre de mouvements limités pour trouver la porte de sortie et utiliser la clé.  

Ayant commencé arbitrairement l'exploration en remontant les étages, j'ai modifié mon robot pour qu'il commence par les étages inférieurs et repère la porte de sortie.  

Il est alors inutile de refaire une exploration complète des niveaux que l'on a préalablement traversé. C'est là qu'interviennent [les algorithmes de recherche de chemin le plus court](https://fr.wikipedia.org/wiki/Recherche_de_chemin).  

Plutôt que de vous expliquer ici la différences entre les algos *Dijkstra*, *A\**, etc. je vous invite à visionner [cette vidéo](https://www.youtube.com/watch?v=DINCL5cd_w0) permettant de comprendre au premier coup d’œil le principe de chaque solution.  

Je me suis naturellement dirigé vers l'algorithme *A\** qui est très bien expliqué par *Sebastian Lague* [dans cette vidéo](https://www.youtube.com/watch?v=-L-WgKMFuhE).  

L'idée est de donner à chaque cellule deux poids différents. Le premier poids est la distance à vol d'oiseau d'une cellule par rapport à la destination.  

L'autre poids est la distance d'une cellule depuis le départ en prenant en compte les obstacles.  

Le chemin le plus court sera celui dont les cellules ont le plus petit poids global (somme des deux poids).  

L'algorithme final utilisé est le suivant :  

1. Utiliser *Trémeaux* pour explorer le niveau de départ ainsi que les niveaux inférieurs jusqu'à celui où se trouve la porte de sortie.
2. Remonter intelligemment ces étages grâce à *A\** pour se diriger vers les bon escaliers (ceux montants).
3. Utiliser *Trémeaux* pour explorer les étages supérieurs inconnus et s'arrêter sur celui contenant la clé.
4. Via *A\** récupérer la clé, descendre les escaliers puis prendre la porte de sortie.

Le code du bot est le suivant (les trois boucles while ne sont pas très belles mais j'ai la flemme d'améliorer). Les positions sont simplement stockées dans une liste. Chaque position est reliée à ses cellules voisines grâce aux index correspondants dans la liste. Une dictionnaire permet de retrouver une position pour des coordonnées données.  

```python
import socket
import select
import sys

WEST = "west"
NORTH = "north"
EAST = "east"
SOUTH = "south"
UP = "up"
DOWN = "down"

DIRECTIONS = [WEST, NORTH, EAST, SOUTH]
OPPOSITES = {
    WEST: EAST,
    NORTH: SOUTH,
    EAST: WEST,
    SOUTH: NORTH,
    UP: DOWN,
    DOWN: UP
}

class Position(object):
    def __init__(self, north=-1, east=-1, south=-1, west=-1, up=-1, down=-1):
        self.north = north
        self.west = west
        self.south = south
        self.east = east
        self.up = up
        self.down = down
        self.back = ""  # direction
        self.g_cost = -1
        self.h_cost = -1
        self.parent = -1

    def f_cost(self):
        return self.g_cost + self.h_cost

    def is_dead_end(self):
        count = 0
        if self.north == -2:
            count += 1
        if self.east == -2:
            count += 1
        if self.west == -2:
            count += 1
        if self.south == -2:
            count += 1
        return count == 3

    def status(self, direction):
        if hasattr(self, direction):
            return getattr(self, direction)

    def set_status(self, direction, index):
        if hasattr(self, direction):
            return setattr(self, direction, index)

    def set_opposite_status(self, direction, index):
        opposite = OPPOSITES[direction]
        self.back = opposite
        self.set_status(opposite, index)

    def direction_for(self, index):
        if self.east == index:
            return EAST
        elif self.west == index:
            return WEST
        elif self.north == index:
            return NORTH
        elif self.south == index:
            return SOUTH
        return "unknown"

class Buddy(object):
    def __init__(self):
        self.position = Position()
        self.maze = [self.position]
        self.coords = {"1000,1000,5": 0}
        self.direction = NORTH
        self.index = 0  # index of position in maze
        self.x = 1000
        self.y = 1000
        self.z = 5
        self.floors = {}
        self.has_key = False
        self.escape_index = -1
        self.key_index = -1

        self.s = socket.socket()
        self.s.connect(("192.168.1.64", 7788))
        self.s.recv(1024)  # Please wait...
        self.s.recv(1024)  # Map loaded
        self.s.setblocking(0)
        #self.receive()

    def get_key(self):
        self.send("pickup")
        lines = self.receive()
        if "You picked up the key." in lines:
            self.has_key = True
        print lines

    def escape(self):
        self.send("escape")
        lines = self.receive()
        if not 'No door here.' in lines:
            print lines

    def receive(self):
        lines = []
        for __ in range(2):
            ready = select.select([self.s], [], [], 5 if not lines else 0.1)
            if ready[0]:
                buff = self.s.recv(1024).strip()
                if (not "You moved" in buff and
                        not "There is a wall" in buff and
                        not "No key here." in buff and
                        not "There are stairs heading" in buff and
                        not "Get out of here!" in buff and
                        not "No door here." in buff and
                        not "There is a key here." in buff):
                    print buff
                lines.append(buff)
        if "You are dead." in lines:
            sys.exit()
        return lines

    def send(self, data):
        while True:
            ready = select.select([], [self.s], [], 0.1)
            if ready[1]:
                self.s.send(data)
                break

    def update_coords(self):
        if self.direction == NORTH:
            self.y += 1
        elif self.direction == SOUTH:
            self.y -= 1
        elif self.direction == WEST:
            self.x -= 1
        elif self.direction == EAST:
            self.x += 1
        elif self.direction == UP:
            self.z += 1
        elif self.direction == DOWN:
            self.z -= 1
        coordinates = "{0},{1},{2}".format(self.x, self.y, self.z)
        if coordinates not in self.coords:
            self.coords[coordinates] = self.index

    def move_direction(self, new_direction):
        new_position = None
        lines = []

        if new_direction in DIRECTIONS:  # same floor
            new_index = self.position.status(new_direction)
            if new_index >= 0:
                # already known position
                new_position = self.maze[new_index]
                self.index = new_index
                # but we still have to move on the server
                self.send(new_direction + "\n")
                lines = self.receive()
            elif new_index == -2:
                # known dead end
                return False
            else:
                # unknown direction : we try to move
                self.send(new_direction + "\n")
                lines = self.receive()
                if "You moved {0}.".format(new_direction) in lines:
                    new_position = Position()
                    new_position.set_opposite_status(new_direction, self.index)
                    self.index = len(self.maze)
                    self.position.set_status(new_direction, self.index)
                    self.maze.append(new_position)
                    if "There are stairs heading upward." in lines and self.position.status(UP) == -1:
                        up_position = Position()
                        up_position.set_status(DOWN, self.index)
                        up_position.set_status("back", DOWN)
                        new_position.up = len(self.maze)
                        self.maze.append(up_position)
                        print "Found stairs going up."
                    if "There are stairs heading downward." in lines and self.position.status(DOWN) == -1:
                        down_position = Position()
                        down_position.set_status(UP, self.index)
                        down_position.set_status("back", UP)
                        new_position.down = len(self.maze)
                        self.maze.append(down_position)
                        print "Found stairs going down."
                elif "There is a wall there." in lines:
                    # new dead end
                    self.position.set_status(new_direction, -2)
                    return False
                else:
                    print "Uhoh"
                    print lines
                    sys.exit()
        elif new_direction == UP:
            if self.position.up >= 0:
                print "Moving upstair"
                self.send("up\n")
                lines = self.receive()
                if "You moved upstairs." in lines:
                    new_index = self.position.up
                    new_position = self.maze[new_index]
                    print "New upstair position:", new_position
                    self.index = new_index
                else:
                    print "No upstair :("
                    sys.exit()
            else:
                print "UP fail"
                sys.exit()
        elif new_direction == DOWN:
            if self.position.down >= 0:
                print "Moving downstair"
                self.send("down\n")
                lines = self.receive()
                if "You moved downstairs." in lines:
                    new_index = self.position.down
                    new_position = self.maze[new_index]
                    print "New downstair position:", new_position
                    self.index = new_index
                else:
                    print "No downstair :("
                    sys.exit()
            else:
                print "DOWN fail"
                sys.exit()

        # On success
        self.position = new_position
        self.direction = new_direction
        print self.direction

        self.update_coords()
        new_coords = "{0},{1},{2}".format(self.x, self.y, self.z)

        if self.z not in self.floors:
            self.floors[self.z] = {}

        if "There is a key here." in lines:
            self.floors[self.z]["key"] = new_coords
        if "There is a locked door here." in lines:  # You need the key to unlock the door.
            self.escape_index = self.index
            self.floors[self.z]["escape"] = new_coords
            self.escape()
        if "There are stairs heading upward." in lines:
            self.floors[self.z]["up"] = new_coords
        if "There are stairs heading downward." in lines:
            self.floors[self.z]["down"] = new_coords

        self.fix_map()
        return True

    def myself(self):
        return "{0},{1},{2}".format(self.x, self.y, self.z)

    def move_tremeaux(self):
        # UP and DOWN are "one-time" directions
        if self.direction == UP or self.direction == DOWN:
            self.direction = NORTH

        if True or not self.has_key:
            if False and self.position.down >= 0 and self.z + 1 < 9 not in self.floors:  # NICO up
                self.move_direction(DOWN)  # UP
            else:
                index = DIRECTIONS.index(self.direction)
                for i in range(3, 7):
                    direction = DIRECTIONS[(index + i) % 4]
                    # Only go to unknown directions
                    if self.position.status(direction) == -1:
                        if self.move_direction(direction):
                            break
                else:
                    # if self.position.back:
                    if self.position.back and self.position.back != UP and self.position.back != DOWN:
                        print "Going back to", self.position.back
                        if self.position.back == DOWN:
                            self.floors.append(self.z)
                        if not self.move_direction(self.position.back):
                            print "Error going back :("
                            sys.exit()
                    else:
                        print "Oups, can't go back, position: {0},{1},{2}".format(self.x, self.y, self.z)
                        return False
        else:
            self.move_direction(self.position.back)
        return True

    def fix_map(self):
        if self.position.north == -1:
            next_north = "{0},{1},{2}".format(self.x, self.y + 1, self.z)
            if next_north in self.coords:
                self.position.north = self.coords[next_north]
                north_position = self.maze[self.position.north]
                north_position.south = self.index
                print "Already known cell at north ({0}) : {1}".format(next_north, self.position.north)
        if self.position.south == -1:
            next_south = "{0},{1},{2}".format(self.x, self.y - 1, self.z)
            if next_south in self.coords:
                self.position.south = self.coords[next_south]
                south_position = self.maze[self.position.south]
                south_position.north = self.index
                print "Already known cell at south ({0}) : {1}".format(next_south, self.position.south)
        if self.position.west == -1:
            next_west = "{0},{1},{2}".format(self.x - 1, self.y, self.z)
            if next_west in self.coords:
                self.position.west = self.coords[next_west]
                west_position = self.maze[self.position.west]
                west_position.east = self.index
                print "Already known cell at west ({0}) : {1}".format(next_west, self.position.west)
        if self.position.east == -1:
            next_east = "{0},{1},{2}".format(self.x + 1, self.y, self.z)
            if next_east in self.coords:
                self.position.east = self.coords[next_east]
                east_position = self.maze[self.position.east]
                east_position.west = self.index
                print "Already known cell at east ({0}) : {1}".format(next_east, self.position.east)

    def print_floor(self, level):
        min_x = 7000
        min_y = 7000
        max_x = 0
        max_y = 0
        for coord in self.coords:
            x, y, z = [int(x) for x in coord.split(',')]
            if z == level:
                if x < min_x:
                    min_x = x
                if x > max_x:
                    max_x = x
                if y < min_y:
                    min_y = y
                if y > max_y:
                    max_y = y
        print
        print "min_x = {0}, min_y = {1}".format(min_x, min_y)

        for y in xrange(max_y + 1, min_y - 2, -1):
            for x in xrange(min_x - 1, max_x + 2):
                coord = "{0},{1},{2}".format(x, y, level)
                if coord in self.coords:
                    floor = self.floors[level]

                    if coord == floor.get("key"):
                        sys.stdout.write("(")
                    elif coord == floor.get("escape"):
                        sys.stdout.write("?")
                    elif coord == floor.get("up"):
                        sys.stdout.write(">")
                    elif coord == floor.get("down"):
                        sys.stdout.write("<")
                    elif coord == self.myself():
                        sys.stdout.write("@")
                    else:
                        sys.stdout.write(" ")
                else:
                    sys.stdout.write("#")
            sys.stdout.write('\n')
        print ''

    def find_short_path(self, start, end):
        x_end, y_end, z_end = [int(x) for x in end.split(',')]

        # set H-cost for every nodes on the same floor
        for coord in self.coords:
            x, y, z = [int(x) for x in coord.split(',')]
            if z == z_end:
                position = self.maze[self.coords[coord]]
                position.h_cost = abs(x_end - x) + abs(y_end - y)
                # force reinit
                position.parent = -1
                position.g_cost = -1

        end_position = self.maze[self.coords[end]]
        start_position = self.maze[self.coords[start]]
        start_position.g_cost = 0

        open_nodes = [start_position]
        closed_nodes = []

        print start, "->", end
        while True:
            min_cost = 7000
            min_position = None
            for position in open_nodes:
                if position.f_cost() < min_cost:
                    min_position = position
                    min_cost = min_position.f_cost()
            open_nodes.remove(min_position)
            closed_nodes.append(min_position)

            if min_position == end_position:
                print "done"
                commands = []
                while min_position.parent != -1:
                    commands.append(OPPOSITES[min_position.direction_for(min_position.parent)])
                    min_position = self.maze[min_position.parent]
                return commands[::-1]

            neighbors_idx = [min_position.east,
                             min_position.south,
                             min_position.north,
                             min_position.west]

            for neighbor_idx in neighbors_idx:
                if neighbor_idx < 0:
                    continue
                neighbor = self.maze[neighbor_idx]
                if neighbor in closed_nodes:
                    continue

                if neighbor not in open_nodes or (neighbor.f_cost() > min_position.f_cost() + 1):
                    neighbor.parent = self.maze.index(min_position)
                    neighbor.g_cost = min_position.f_cost() + 1
                    if neighbor not in open_nodes:
                        open_nodes.append(neighbor)

if __name__ == "__main__":
    bud = Buddy()
    bud_coords = ""
    # go to the lowest level
    while True:
        # explore the whole floor
        while True:
            if not bud.move_tremeaux():
                break

        bud_coords = "{0},{1},{2}".format(bud.x, bud.y, bud.z)
        bud.print_floor(bud.z)
        if "down" in bud.floors[bud.z]:
            commands = bud.find_short_path(bud_coords, bud.floors[bud.z]["down"])
            print ", ".join(commands)
            for direction in commands:
                bud.move_direction(direction)
            bud.move_direction(DOWN)
        else:
            # lowest level, we must have found the escape door
            print "Reached end of cave"
            bud.move_direction(UP)
            break

    # now go to higher floors
    while True:
        bud_coords = "{0},{1},{2}".format(bud.x, bud.y, bud.z)
        # known floor
        if "up" in bud.floors[bud.z]:
            commands = bud.find_short_path(bud_coords, bud.floors[bud.z]["up"])
            print ", ".join(commands)
            for direction in commands:
                bud.move_direction(direction)
            bud.move_direction(UP)
        else:
            # discover unknown floor
            bud_coords = "{0},{1},{2}".format(bud.x, bud.y, bud.z)
            while True:
                if not bud.move_tremeaux():
                    break
            bud_coords = "{0},{1},{2}".format(bud.x, bud.y, bud.z)
            bud.print_floor(bud.z)
            if "key" in bud.floors[bud.z]:
                commands = bud.find_short_path(bud_coords, bud.floors[bud.z]["key"])
                print ", ".join(commands)
                for direction in commands:
                    bud.move_direction(direction)
                bud.get_key()
                break
            elif "up" in bud.floors[bud.z]:
                commands = bud.find_short_path(bud_coords, bud.floors[bud.z]["up"])
                print ", ".join(commands)
                for direction in commands:
                    bud.move_direction(direction)
                bud.move_direction(UP)

            else:
                print "Can't find key nor upstair :("
                break

    while True:
        bud_coords = "{0},{1},{2}".format(bud.x, bud.y, bud.z)
        bud.print_floor(bud.z)
        if "escape" in bud.floors[bud.z]:
            print "Go to escape"
            commands = bud.find_short_path(bud_coords, bud.floors[bud.z]["escape"])
            print ", ".join(commands)
            for direction in commands:
                bud.move_direction(direction)
            bud.escape()
            break
        elif "down" in bud.floors[bud.z]:
            commands = bud.find_short_path(bud_coords, bud.floors[bud.z]["down"])
            print ", ".join(commands)
            for direction in commands:
                bud.move_direction(direction)
            bud.move_direction(DOWN)
```

La dernière ligne obtenue par le bot est la suivante :  

```plain
['YOU ESCAPED!', 'Key: TroubleStudentsRealize972Get out of here!\nThere is a locked door here.']
```

La clé est donc **TroubleStudentsRealize972**.

Vous pouvez voir le robot à l'oeuvre [sur Vimeo](https://vimeo.com/119634395) (16 bonnes minutes). Quand un niveau est complètement exploré, il est affiché, ce qui permet de mieux comprendre l'architecture du labyrinthe.  

 [Cyber Security Challenge Australia 2014 - Mad Coding Skillz / Spelunking! (Maze solving)](https://vimeo.com/119634395) from [devloop](https://vimeo.com/user2531158) on [Vimeo](https://vimeo.com).



*Published February 14 2015 at 18:00*