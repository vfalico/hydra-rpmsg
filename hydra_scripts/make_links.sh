#!/bin/sh

if [ "$(id -u)" != "0" ]; then
	echo "$0 must be run as root" 1>&2
	exit 1
fi

. ./defines.sh

rm -f $AP_VMLINUX_FW
ln -s $HYDRA_SCRIPTS/$AP_VMLINUX $AP_VMLINUX_FW

rm -f $AP_INITRD_FW
ln -s $AP_INITRD $AP_INITRD_FW

echo done:
ls -liah $AP_VMLINUX_FW $AP_INITRD_FW

