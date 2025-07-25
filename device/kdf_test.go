/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

type KDFTest struct {
	key   string
	input string
	t0    string
	t1    string
	t2    string
}

func TestKDF(t *testing.T) {
	tests := []KDFTest{
		{
			key:   "746573742d6b6579746573742d6b6579",
			input: "746573742d696e707574",
			t0:    "5b90fd04556584e37c2b13872408e3a7ddbc303cea7e10f816554b799c1517e8",
			t1:    "d09676437f04ef6e06e3fc599ccaa9bc57c4415e03594bc1a2cd7218e4bcc0d4",
			t2:    "e4f67a96717884d4205ae6c8f952c1d796c1cacf541f3b9f2c2ad5cb707a8dd3",
		},
		{
			key:   "776972656775617264776972656775617264",
			input: "776972656775617264",
			t0:    "bf54f6436b6134a0c162e8716411c8a6f0b0d0dd1cf871bb581910dc7a66f370",
			t1:    "7e996023f2ac54e99beda32ed1605ddcedcc3814946832ec1bf83fee8b2d08b1",
			t2:    "a7c47264f76e086d918de1f49977c300fba44f8f4bd3df1f92dd770bb18f3196",
		},
		{
			key:   "905804385040348509438509843095844540398492344",
			input: "",
			t0:    "cedf0605fba3be2d92b8a9c5a3d12e4364eb318db6ca7f95ada86e6c90f4c614",
			t1:    "e9ce078d50d5b8a5eaa13463da723d6378b5fa82da11db27975856748ffaa267",
			t2:    "dfa65a06bda265cc193d31405f82177bb79fb9403e808a60da74de6b3989527b",
		},
	}

	var t0, t1, t2 [sha256.Size]byte

	for _, test := range tests {
		t.Run("kdf3: "+test.key, func(t *testing.T) {
			key, _ := hex.DecodeString(test.key)
			input, _ := hex.DecodeString(test.input)
			KDF3(&t0, &t1, &t2, key, input)
			t0s := hex.EncodeToString(t0[:])
			t1s := hex.EncodeToString(t1[:])
			t2s := hex.EncodeToString(t2[:])
			assert.Equal(t, test.t0, t0s)
			assert.Equal(t, test.t1, t1s)
			assert.Equal(t, test.t2, t2s)
		})
	}

	for _, test := range tests {
		t.Run("kdf2: "+test.key, func(t *testing.T) {
			key, _ := hex.DecodeString(test.key)
			input, _ := hex.DecodeString(test.input)
			KDF2(&t0, &t1, key, input)
			t0s := hex.EncodeToString(t0[:])
			t1s := hex.EncodeToString(t1[:])
			assert.Equal(t, test.t0, t0s)
			assert.Equal(t, test.t1, t1s)
		})
	}

	for _, test := range tests {
		t.Run("kdf1: "+test.key, func(t *testing.T) {
			key, _ := hex.DecodeString(test.key)
			input, _ := hex.DecodeString(test.input)
			KDF1(&t0, key, input)
			t0s := hex.EncodeToString(t0[:])
			assert.Equal(t, test.t0, t0s)
		})
	}
}
