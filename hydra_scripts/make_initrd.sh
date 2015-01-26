#!/bin/sh

. ./defines.sh

[ ! -x "$TUN_DIR/tunnel" ] && echo "$0: first make tun" && exit 2

cp $TUN_DIR/tunnel $AP_INITRD_DIR/bin/
cp $HYDRA_SCRIPTS/start_tunnel.sh $AP_INITRD_DIR/bin/

cd $AP_INITRD_DIR
find . | cpio --quiet -R root:root -H newc -o | gzip -9 -n > $AP_INITRD

echo done initrd
