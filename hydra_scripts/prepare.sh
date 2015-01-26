#!/bin/sh

. ./defines.sh

./make_ap.sh
./make_tun.sh
./make_initrd.sh
./make_links.sh
./make_bsp.sh

echo "everything created, BSP vmlinux built"
echo "install the BSP the VM - usually a plain 'make install modules_install' will work"
echo "reboot into it and run start_ap.sh"

