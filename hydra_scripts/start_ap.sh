#!/bin/sh

if [ "$(id -u)" != "0" ]; then
   echo "$0 must be run as root" 1>&2
   exit 1
fi

. ./defines.sh

./make_links.sh

echo "starting AP on default CPU (1) and second serial console, then starting the networking"
modprobe dummy_remoteproc serial_number=0 && ./start_tunnel.sh

