#!/bin/sh

. ./defines.sh
cd ../
cp vfalico_config .config
sed -i.bak -e "s/^CONFIG_PHYSICAL_START=.*/CONFIG_PHYSICAL_START=$AP_CONFIG_START/g" .config
sed -i.bak -e "s/^CONFIG_DEFAULT_HOSTNAME=.*/CONFIG_DEFAULT_HOSTNAME=\"hydra_ap\"/g" .config

make -j `nproc` || { echo "AP build failed"; exit 1; }

cp vmlinux $HYDRA_SCRIPTS/$AP_VMLINUX
echo ap done
