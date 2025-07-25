//go:build !pkcs11
// +build !pkcs11

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
)

func handlePkcs11Key(device *Device, value string) error {
	return fmt.Errorf("not implemented")
}
