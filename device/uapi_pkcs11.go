//go:build pkcs11
// +build pkcs11

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/base64"
)

func handlePkcs11Key(device *Device, value string) error {
	sk, err := NewPkcs11BackedPrivateKey(value)
	if err != nil {
		return err
	}
	device.log.Verbosef("UAPI: pkcs11 handling private key")
	pub := sk.PublicKey()
	device.log.Verbosef("UAPI: pkcs11 public key: %s", base64.StdEncoding.EncodeToString(pub[:]))
	device.SetPrivateKey(sk)
	return nil
}
