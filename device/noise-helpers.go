/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
)

/* KDF related functions.
 * HMAC-based Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 */

func HMAC1(sum *[sha256.Size]byte, key, in0 []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func HMAC2(sum *[sha256.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func KDF1(t0 *[sha256.Size]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[sha256.Size]byte, key, input []byte) {
	var prk [sha256.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func KDF3(t0, t1, t2 *[sha256.Size]byte, key, input []byte) {
	var prk [sha256.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	HMAC2(t2, prk[:], t1[:], []byte{0x3})
	setZero(prk[:])
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

/* This function is not used as pervasively as it should because this is mostly impossible in Go at the moment */
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func newPrivateKey() (NoiseSoftPrivateKey, error) {

	pk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return NoiseSoftPrivateKey{}, err
	}

	k := NoiseSoftPrivateKey(pk.Bytes())
	return k, nil
}

func (sk *NoiseSoftPrivateKey) PublicKey() NoisePublicKey {

	if sk.IsZero() {
		return NoisePublicKey{}
	}

	pk, _ := ecdh.P256().NewPrivateKey(sk[:])
	return NoisePublicKey(pk.PublicKey().Bytes())
}

var errInvalidPublicKey = errors.New("invalid public key")

func (sk *NoiseSoftPrivateKey) SharedSecret(pub NoisePublicKey) ([NoisePresharedKeySize]byte, error) {

	peerPub, err := ecdh.P256().NewPublicKey(pub[:])
	if err != nil {
		return [NoisePresharedKeySize]byte{}, errInvalidPublicKey
	}

	pk, _ := ecdh.P256().NewPrivateKey(sk[:])

	ss, err := pk.ECDH(peerPub)
	if err != nil {
		return [NoisePresharedKeySize]byte{}, errInvalidPublicKey
	}

	var ret [NoisePresharedKeySize]byte
	copy(ret[:], ss[:NoisePresharedKeySize])
	return ret, nil
}

func CompressECDHPublicKey(pub *ecdh.PublicKey) ([]byte, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), pub.Bytes())
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid ecdh public key bytes")
	}

	byteLen := 32 // P-256 coordinate size
	compressed := make([]byte, 1+byteLen)
	if y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}

	xBytes := x.Bytes()
	copy(compressed[1+byteLen-len(xBytes):], xBytes)

	return compressed, nil
}

func DecompressECDHPublicKey(compressed []byte) ([]byte, error) {
	if len(compressed) != 33 {
		return nil, fmt.Errorf("invalid compressed key length")
	}

	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, fmt.Errorf("invalid compression prefix")
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(compressed[1:])
	params := curve.Params()

	// Compute y² = x³ - 3x + b mod p
	x3 := new(big.Int).Exp(x, big.NewInt(3), params.P)
	threeX := new(big.Int).Mul(x, big.NewInt(3))
	x3.Sub(x3, threeX)
	x3.Add(x3, params.B)
	x3.Mod(x3, params.P)

	y := new(big.Int).ModSqrt(x3, params.P)
	if y == nil {
		return nil, fmt.Errorf("no modular sqrt exists")
	}

	// Correct the parity
	if (y.Bit(0) == 1 && prefix == 0x02) || (y.Bit(0) == 0 && prefix == 0x03) {
		y.Sub(params.P, y)
	}

	uncompressed := elliptic.Marshal(curve, x, y)
	return uncompressed, nil
}
