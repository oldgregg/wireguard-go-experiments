#!/bin/bash
set -eou pipefail

echo "This script will wipe your YubiKey and set it up with defaults for Wireguard. Press Ctrl+C now to exit if you do not want to do this."
read -s -p "Enter pin: " pin
echo ""

default_mgm_key=010203040506070801020304050607080102030405060708
default_pin=123456
default_puk=12345678

echo "Resetting YubiKey"
ykman piv reset -f
serial=$(ykman list -s)

new_mgm_key=$(dd if=/dev/urandom bs=512 count=1 | sha512sum | head -c64)
new_puk=$(dd if=/dev/urandom bs=512 count=1 | sha512sum | head -c8)
junk_puk=$(dd if=/dev/urandom bs=512 count=1 | sha512sum | head -c8)
junk_puk2=$(dd if=/dev/urandom bs=512 count=1 | sha512sum | head -c8)

echo "Changing management key"
ykman piv access change-management-key -f -a "AES256" -m "$default_mgm_key" -n "$new_mgm_key" -P "$default_pin"

echo "Changing PIN retries"
ykman piv access set-retries -f -m "$new_mgm_key" -P "$default_pin" 3 1 # pin, puk respectively

echo "Changing PUK"
ykman piv access change-puk -p "$default_puk" -n "$new_puk"

echo "Changing PIN"
ykman piv access change-pin -P "$default_pin" -n "$pin"

echo "Locking out PUK"
ykman piv access change-puk -p "$junk_puk" -n "$junk_puk2" || true

echo "Generating x25519 private key"
slot_pubkey=$(ykman piv keys generate -a X25519 -F PEM -P "$pin" -m "$new_mgm_key" --pin-policy ONCE --touch-policy NEVER 9a -)

echo "Printing attestation cert"
ykman piv keys attest 9a -

echo ""

echo "Wireguard pubkey -----------------------------"
openssl pkey -pubin -in <(echo "$slot_pubkey") -outform DER | tail -c 32 | base64
