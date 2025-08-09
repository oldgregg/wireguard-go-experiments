//go:build pkcs11
// +build pkcs11

package kppkcs11

import (
	"crypto/ecdh"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
	reg "golang.zx2c4.com/wireguard/device/keyproviders/registry"
	nt "golang.zx2c4.com/wireguard/device/noisetypes"
)

func init() {
	reg.RegisterHardwareKeyProvider("pkcs11", NewPkcs11BackedPrivateKey)
}

var _ nt.NoisePrivateKey = (*pkcs11BackedPrivateKey)(nil)

var ErrUnsupported = fmt.Errorf("unsupported operation")
var ErrNotFound = fmt.Errorf("not found")

type pkcs11BackedPrivateKey struct {
	cfg      *pkcs11Data
	pubBytes []byte
}

type wrappedPrivateKey struct {
	mu sync.Mutex

	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle

	pkHandle pkcs11.ObjectHandle
	pubBytes []byte
}

func (pk *wrappedPrivateKey) Close() error {
	defer pk.ctx.Destroy()
	defer pk.ctx.Finalize()
	defer pk.ctx.CloseSession(pk.session)
	defer pk.ctx.Logout(pk.session)
	return nil
}

func NewPkcs11BackedPrivateKey(pkcs11Uri string) (nt.NoisePrivateKey, error) {

	dat, err := parsePkcs11Uri(pkcs11Uri)
	if err != nil {
		return nil, err
	}

	pk, err := getKeyCommon(dat)
	if err != nil {
		return nil, err
	}
	defer pk.Close()

	return &pkcs11BackedPrivateKey{
		cfg:      dat,
		pubBytes: pk.pubBytes,
	}, nil

}

func getKeyCommon(cfg *pkcs11Data) (*wrappedPrivateKey, error) {
	cleanup := true

	p := pkcs11.New(cfg.module)
	if p == nil {
		return nil, fmt.Errorf("failed to initialize pkcs11 library")
	}

	shouldCleanup := func(fn func(), shouldCleanup *bool) {
		if *shouldCleanup {
			fn()
		}
	}

	defer shouldCleanup(p.Destroy, &cleanup)

	err := p.Initialize()
	if err != nil {
		return nil, err
	}
	defer shouldCleanup(func() { p.Finalize() }, &cleanup)

	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, err
	}
	if len(slots) == 0 {
		return nil, fmt.Errorf("no slots found")
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	defer shouldCleanup(func() { p.CloseSession(session) }, &cleanup)

	err = p.Login(session, pkcs11.CKU_USER, cfg.pin)
	if err != nil {
		return nil, err
	}

	defer shouldCleanup(func() { p.Logout(session) }, &cleanup)

	curve, _ := hex.DecodeString("06082a8648ce3d030107") // 1.2.840.10045.3.1 (NIST p256)
	if err := p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_ID, cfg.id),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, curve),
	}); err != nil {
		return nil, err
	}

	pkObjs, _, err := p.FindObjects(session, 1)
	if err != nil {
		return nil, err
	}

	if len(pkObjs) == 0 {
		return nil, fmt.Errorf("could not find private key object")
	}

	// can always run this.
	p.FindObjectsFinal(session)

	// Find public key
	if err := p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_ID, cfg.id),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, curve),
	}); err != nil {
		return nil, err
	}

	pubObjs, _, err := p.FindObjects(session, 1)
	if err != nil {
		return nil, err
	}

	if len(pubObjs) == 0 {
		return nil, fmt.Errorf("could not find public key object")
	}

	// can always run this.
	p.FindObjectsFinal(session)

	pubAttr, err := p.GetAttributeValue(session, pubObjs[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, err
	}

	var rawPoint []byte
	if _, err := asn1.Unmarshal(pubAttr[0].Value, &rawPoint); err != nil {
		return nil, err
	}

	pub, err := ecdh.P256().NewPublicKey(rawPoint[:])
	if err != nil {
		return nil, err
	}

	cleanup = false
	return &wrappedPrivateKey{
		ctx:      p,
		session:  session,
		pubBytes: pub.Bytes(),
		pkHandle: pkObjs[0],
	}, nil
}

func (k *pkcs11BackedPrivateKey) PublicKey() nt.NoisePublicKey {
	return nt.NoisePublicKey(k.pubBytes)
}

func (k *pkcs11BackedPrivateKey) SharedSecret(peer nt.NoisePublicKey) ([32]byte, error) {

	pk, err := getKeyCommon(k.cfg)
	if err != nil {
		return [32]byte{}, err
	}
	defer pk.Close()

	deriveMech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, &pkcs11.ECDH1DeriveParams{
		KDF:           pkcs11.CKD_NULL,
		SharedData:    nil,
		PublicKeyData: peer[:],
	})}
	secretTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}

	secretKey, err := pk.ctx.DeriveKey(pk.session, deriveMech, pk.pkHandle, secretTemplate)
	if err != nil {
		return [32]byte{}, err
	}

	// Extract the shared secret
	secretAttr, err := pk.ctx.GetAttributeValue(pk.session, secretKey, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return [32]byte{}, err
	}

	return [32]byte(secretAttr[0].Value), nil
}

func (yk *pkcs11BackedPrivateKey) IsZero() bool {
	return false
}

func (yk *pkcs11BackedPrivateKey) FromHex(src string) error {
	return ErrUnsupported
}

func (yk *pkcs11BackedPrivateKey) FromMaybeZeroHex(src string) error {
	return ErrUnsupported
}

func (yk *pkcs11BackedPrivateKey) IsHardware() bool {
	return true
}

type pkcs11Data struct {
	pin    string
	module string
	id     []byte
}

func parsePkcs11Uri(uri string) (*pkcs11Data, error) {

	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	vals, err := url.ParseQuery(strings.ReplaceAll(u.Opaque, ";", "&"))
	if err != nil {
		return nil, err
	}

	module := vals.Get("module-path")
	if module == "" {
		return nil, fmt.Errorf("no module specified in pkcs11 uri")
	}

	pin := vals.Get("pin-value")
	if pin == "" {
		pinSource := vals.Get("pin-source")
		if pinSource == "" {
			return nil, fmt.Errorf("no pin-value or pin-source specified")
		}
		b, err := os.ReadFile(pinSource)
		if err != nil {
			return nil, err
		}
		pin = string(b)
	}

	id := vals.Get("id")
	if id == "" {
		return nil, fmt.Errorf("no id specified for pkcs11 module")
	}

	idBytes, err := hex.DecodeString(id)
	if err != nil {
		return nil, err
	}

	return &pkcs11Data{
		pin:    pin,
		module: module,
		id:     idBytes,
	}, nil
}
