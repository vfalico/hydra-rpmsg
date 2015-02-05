#!/bin/sh

. ./defines.sh
cd ../
cp vfalico_config .config

sed -i.bak -e "s/^CONFIG_PHYSICAL_START=.*/CONFIG_PHYSICAL_START=$BSP_CONFIG_START/g" .config
sed -i.bak -e "s/^CONFIG_DEFAULT_HOSTNAME=.*/CONFIG_DEFAULT_HOSTNAME=\"hydra_bsp\"/g" .config
sed -i.bak -e "s/^# CONFIG_CMDLINE_BOOL is not set/CONFIG_CMDLINE_BOOL=y\nCONFIG_CMDLINE=\"$BSP_CMDLINE_APPEND\"\n# CONFIG_CMDLINE_OVERRIDE is not set/g" .config

make -j `nproc` || { echo "BSP build failed"; exit 1; }

cp vmlinux $HYDRA_SCRIPTS/$BSP_VMLINUX
echo bsp done
