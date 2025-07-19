/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

const (
	NoisePublicKeySize    = 32
	NoisePrivateKeySize   = 32
	NoisePresharedKeySize = 32
)

type NoisePrivateKeyInterface interface {
	PublicKey() NoisePublicKey
	SharedSecret(peer NoisePublicKey) (ss [32]byte, err error)
	IsZero() bool
	FromHex(src string) error
	FromMaybeZeroHex(src string) error
	IsHardware() bool
}

var _ NoisePrivateKeyInterface = (*SoftNoisePrivateKey)(nil)

type (
	NoisePublicKey      [NoisePublicKeySize]byte
	SoftNoisePrivateKey [NoisePrivateKeySize]byte
	NoisePresharedKey   [NoisePresharedKeySize]byte
	NoiseNonce          uint64 // padded to 12-bytes
)

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

func (key SoftNoisePrivateKey) IsZero() bool {
	var zero SoftNoisePrivateKey
	return subtle.ConstantTimeCompare(key[:], zero[:]) == 1
}

func (key *SoftNoisePrivateKey) FromHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	key.clamp()
	return
}

func (key *SoftNoisePrivateKey) FromMaybeZeroHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	if key.IsZero() {
		return
	}
	key.clamp()
	return
}

func (key *SoftNoisePrivateKey) IsHardware() bool {
	return false
}

func (key *NoisePublicKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key NoisePublicKey) IsZero() bool {
	var zero NoisePublicKey
	return key.Equals(zero)
}

func (key NoisePublicKey) Equals(tar NoisePublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoisePresharedKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}
