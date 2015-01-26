#!/bin/sh

HYDRA_SCRIPTS=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

#base memory addresses, currently can't intersect
AP_CONFIG_START=0x4100000
BSP_CONFIG_START=0x2000000

#workaround the cma offset issue
BSP_CMDLINE_APPEND="cma=500M@0x`printf "%X" $((AP_CONFIG_START - 0x100000))`"

#these must be kept in the hydra_scripts dir
AP_VMLINUX="vmlinux.ap"
BSP_VMLINUX="vmlinux.bsp"

#symlinks for the firmware loader, namely udev - requests can be viewed
#with "udevadm monitor"
AP_INITRD_FW="/lib/firmware/initrd"
AP_VMLINUX_FW="/lib/firmware/rproc-dummy-rproc-fw"

#tunnel address for kmem-based networking, can be whatever suits
#TUN_ADDR is defined in start_tunnel.sh
TUN_DIR="$HYDRA_SCRIPTS/net_tunnel/"

#initrd filenames
AP_INITRD_DIR="$HYDRA_SCRIPTS/initrd/"
AP_INITRD="$HYDRA_SCRIPTS/ramdisk.img.gz"
