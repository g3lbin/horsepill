#!/bin/bash
# This script allows you to extract the 'run-init' binary from
# the ramdisk image and place it in the '/lost+found' folder

cd /lost+found
mkdir tmp2
mkdir tmp2/extracted

# ramdisk unpack
cp /boot/initrd.img-$(uname -r) tmp2/
cd tmp2/
unmkinitramfs initrd.img-$(uname -r) ./extracted/
cd extracted/

# extract run-init binary
cp main/usr/bin/run-init /lost+found/run-init

# cleanup
cd /lost+found
rm -rf tmp2/