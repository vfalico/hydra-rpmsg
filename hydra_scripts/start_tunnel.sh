#!/bin/sh

if [ "$(id -u)" != "0" ]; then
   echo "$0 must be run as root" 1>&2
   exit 1
fi

[ -f ./defines.sh ] && . ./defines.sh

[ -z "$TUN_ADDR" ] && TUN_ADDR=0x1e11000

REPRESENTATIVE=`cat /proc/cpuinfo | grep processor | awk '{print $3}' | head -n 1`
TUN_CPU=$(( $REPRESENTATIVE + 1 ))
echo tun_addr = $TUN_ADDR tun_cpu = $TUN_CPU


[ -x "$TUN_DIR/tunnel" ] && TUNNEL="$TUN_DIR/tunnel"
[ -z "$TUNNEL" ] && [ -x /bin/tunnel ] && TUNNEL="/bin/tunnel"
[ -z "$TUNNEL" ] && [ -x /sbin/tunnel ] && TUNNEL="/sbin/tunnel"
[ -z "$TUNNEL" ] && echo "$0: tunnel not found, exiting" && exit 2

$TUNNEL $TUN_ADDR $REPRESENTATIVE & 2>/dev/null >/dev/null
TUN_ID=""
while [ -z $TUN_ID ]
do
  TUN_ID=`ip -f inet link show |  awk '/tun[0-9]:/ {print $2}' | tail -n 1`
done

TUN_DEV=${TUN_ID%:}
echo "ifconfig $TUN_DEV 10.1.2.$TUN_CPU up"
ifconfig $TUN_DEV 10.1.2.$TUN_CPU up
route add -net 10.1.2.0 netmask 255.255.255.0 dev $TUN_DEV
sysctl -w net.ipv4.conf.$TUN_DEV.accept_local=1
echo "tunnel device $TUN_DEV setup on 10.1.2.$TUN_CPU"
