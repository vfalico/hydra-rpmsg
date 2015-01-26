#!/bin/sh

. ./defines.sh

sudo rm -f $AP_VMLINUX_FW
sudo ln -s $HYDRA_SCRIPTS/$AP_VMLINUX $AP_VMLINUX_FW

sudo rm -f $AP_INITRD_FW
sudo ln -s $AP_INITRD $AP_INITRD_FW

echo done:
ls -liah $AP_VMLINUX_FW $AP_INITRD_FW

