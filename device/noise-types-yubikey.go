package device

import (
	"crypto/ecdh"
	"crypto/x509"
	"fmt"

	"github.com/go-piv/piv-go/v2/piv"
)

var _ NoisePrivateKeyInterface = (*YubiKeyBackedPrivateKey)(nil)

var ErrUnsupported = fmt.Errorf("unsupported operation")
var ErrNotFound = fmt.Errorf("not found")

type YubiKeyBackedPrivateKey struct {
	serial uint32
	slotId uint32
	pin string

	pubKey NoisePublicKey
}

type wrappedPrivateKey struct {
	*piv.X25519PrivateKey

	yk *piv.YubiKey
}

func (pk *wrappedPrivateKey) Close() error {
	return pk.yk.Close()
}

func NewYubiKeyBackedPrivateKey(serial uint32, slotId uint32, pin string) (NoisePrivateKeyInterface, error) {

	yk := YubiKeyBackedPrivateKey{
		serial: serial,
		slotId: slotId,
		pin: pin,
	}

	priv, err := yk.getPrivateKeyCommon()
	if err != nil {
		return nil, err
	}
	defer priv.Close()

	pub := priv.Public().(*ecdh.PublicKey).Bytes()
	yk.pubKey = NoisePublicKey(pub)

	return &yk, nil
}

func (key *YubiKeyBackedPrivateKey) getPrivateKeyCommon() (*wrappedPrivateKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}

	slot := piv.Slot{Key: key.slotId, Object: 0x5fc105}

	maybeClose := func(yk *piv.YubiKey, found *bool) {
		if !*found {
			yk.Close()
		}
	}

	var yk *piv.YubiKey
	for _, card := range cards {
		var found bool
		yk, err = piv.Open(card)
		if err != nil {
			continue
		}
		defer maybeClose(yk, &found)

		s, err := yk.Serial()
		if err != nil || s != key.serial {
			continue
		}

		attest, err := yk.Attest(slot)
		if err != nil {
			return nil, err
		}

		pub, err := x509.ParsePKIXPublicKey(attest.RawSubjectPublicKeyInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RawSubjectPublicKeyInfo: %v", err)
		}

		pk, err := yk.PrivateKey(slot, pub, piv.KeyAuth{
			PIN:       key.pin,
			PINPolicy: piv.PINPolicyOnce,
		})
		if err != nil {
			return nil, err
		}

		x25519, ok := pk.(*piv.X25519PrivateKey)
		if !ok {
			return nil, fmt.Errorf("slot does not contain x25519 key")
		}

		found = true

		return &wrappedPrivateKey{
			X25519PrivateKey: x25519,
			yk: yk,
		}, nil
	}

	return nil, ErrNotFound
}

func (yk *YubiKeyBackedPrivateKey) PublicKey() NoisePublicKey {
	return yk.pubKey
}

func (yk *YubiKeyBackedPrivateKey) SharedSecret(peer NoisePublicKey) ([32]byte, error) {

	priv, err := yk.getPrivateKeyCommon()
	if err != nil {
		return [32]byte{}, err
	}
	defer priv.Close()

	pub := priv.Public().(*ecdh.PublicKey).Bytes()
	if !yk.pubKey.Equals(NoisePublicKey(pub)) {
		return [32]byte{}, fmt.Errorf("public key mismatch")
	}

	xpk, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return [32]byte{}, err
	}

	ss, err := priv.ECDH(xpk)
	if err != nil {
		return [32]byte{}, err
	}

	var ss32 [32]byte
	copy(ss32[:], ss[:32])

	return ss32, nil
}

func (yk *YubiKeyBackedPrivateKey) IsZero() bool {
	return false
}

func (yk *YubiKeyBackedPrivateKey) FromHex(src string) error {
	return ErrUnsupported
}

func (yk *YubiKeyBackedPrivateKey) FromMaybeZeroHex(src string) error {
	return ErrUnsupported
}

func (yk *YubiKeyBackedPrivateKey) IsHardware() bool {
	return true
}
