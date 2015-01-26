#!/bin/sh

. ./defines.sh

cd $TUN_DIR
make clean
make || exit 1
echo created $TUN_DIR/tunnel
