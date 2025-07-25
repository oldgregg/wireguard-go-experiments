/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

const (
	NoisePublicKeySize    = 65 /* uncompressed key size for ec256 */
	NoisePrivateKeySize   = 32
	NoisePresharedKeySize = 32
)

type (
	NoisePublicKey      [NoisePublicKeySize]byte
	NoiseSoftPrivateKey [NoisePrivateKeySize]byte
	NoisePresharedKey   [NoisePresharedKeySize]byte
	NoiseNonce          uint64 // padded to 12-bytes
)

var _ NoisePrivateKey = (*NoiseSoftPrivateKey)(nil)

type NoisePrivateKey interface {
	PublicKey() NoisePublicKey
	SharedSecret(peer NoisePublicKey) (ss [32]byte, err error)
	IsZero() bool
	FromHex(src string) error
	FromMaybeZeroHex(src string) error
	IsHardware() bool
}

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

func (key NoiseSoftPrivateKey) IsZero() bool {
	var zero NoiseSoftPrivateKey
	return bytes.Equal(key[:], zero[:])
}

func (key NoiseSoftPrivateKey) Equals(tar NoisePrivateKey) bool {
	pub := key.PublicKey()
	tpub := tar.PublicKey()
	return subtle.ConstantTimeCompare(pub[:], tpub[:]) == 1
}

func (key *NoiseSoftPrivateKey) FromHex(src string) error {
	b, err := hex.DecodeString(src)
	if err != nil {
		return err
	}

	pk, err := ecdh.P256().NewPrivateKey(b)
	if err != nil {
		return err
	}

	copy(key[:], pk.Bytes())
	return nil
}

func (key *NoiseSoftPrivateKey) FromMaybeZeroHex(src string) error {
	b, err := hex.DecodeString(src)
	if err != nil {
		return err
	}

	if isZero(b) {
		return nil
	}

	pk, err := ecdh.P256().NewPrivateKey(b)
	if err != nil {
		return err
	}

	copy(key[:], pk.Bytes())
	return nil
}

func (key NoiseSoftPrivateKey) IsHardware() bool {
	return false
}

func (key *NoisePublicKey) FromHex(src string) error {
	b, err := hex.DecodeString(src)
	if err != nil {
		return err
	}

	pub, err := ecdh.P256().NewPublicKey(b)
	if err != nil {
		return err
	}

	copy(key[:], pub.Bytes())
	return nil
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
