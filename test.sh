#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
# Modified for testing purposes.
# Run as: ./test serial pin pubkey

set -e
set -x
[[ $UID == 0 ]] || { echo "You must be root to run this."; exit 1; }
SERIAL=$1
PIN=$2
PUBKEY=$3
exec 3<>/dev/tcp/demo.wireguard.com/42912
echo "$PUBKEY" >&3
IFS=: read -r status server_pubkey server_port internal_ip <&3
[[ $status == OK ]]
./wireguard-go wg0
wg set wg0 peer "$server_pubkey" allowed-ips 0.0.0.0/0 endpoint "demo.wireguard.com:$server_port" persistent-keepalive 25
./wireguard-go -serial "$SERIAL" -pin "$PIN" wg0
ip address add "$internal_ip"/24 dev wg0
ip link set up dev wg0