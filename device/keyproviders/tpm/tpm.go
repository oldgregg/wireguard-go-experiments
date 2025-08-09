package kptpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	reg "golang.zx2c4.com/wireguard/device/keyproviders/registry"
	nt "golang.zx2c4.com/wireguard/device/noisetypes"
)

func init() {
	reg.RegisterHardwareKeyProvider("tpm", newTpmBackedKey)
}

var _ nt.NoisePrivateKey = (*tpmBackedPrivateKey)(nil)

var ErrUnsupported = fmt.Errorf("unsupported operation")
var ErrNotFound = fmt.Errorf("not found")

type tpmBackedPrivateKey struct {
	path string
	handle uint32 // 0x81010004
	pubBytes []byte
}

type wrappedPrivateKey struct {
	mu sync.Mutex

	rwc    io.ReadWriteCloser
	handle tpmutil.Handle

	pubBytes []byte
}

func (pk *wrappedPrivateKey) Close() error {
	return pk.rwc.Close()
}

func newTpmBackedKey(pkcs11Uri string) (nt.NoisePrivateKey, error) {

	path, handle, err := parsePkcs11Uri(pkcs11Uri)
	if err != nil {
		return nil, err
	}

	pk, err := getKeyCommon(path, handle)
	if err != nil {
		return nil, err
	}
	defer pk.Close()

	return &tpmBackedPrivateKey{
		path: path,
		handle: handle,
		pubBytes: pk.pubBytes,
	}, nil

}

func getKeyCommon(path string, handle uint32) (*wrappedPrivateKey, error) {
	cleanup := true

	rwc, err := tpm2.OpenTPM(path)
	if err != nil {
		return nil, err
	}

	shouldCleanup := func(fn func(), shouldCleanup *bool) {
		if *shouldCleanup {
			fn()
		}
	}

	defer shouldCleanup(func() { rwc.Close() }, &cleanup)

	keyHandle := tpmutil.Handle(handle) // TODO: configurable

	tpmPub, _, _, err := tpm2.ReadPublic(rwc, keyHandle)
	if err != nil {
		return nil, err
	}

	// Convert TPM public key to ecdh.PublicKey
	tpmPubKey, err := tpmPub.Key()
	if err != nil {
		return nil, err
	}
	ecdsaPubKey, ok := tpmPubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ecdsa key")
	}

	pub, err := ecdsaPubKey.ECDH()
	if err != nil {
		return nil, err
	}

	cleanup = false
	return &wrappedPrivateKey{
		rwc:      rwc,
		handle:   keyHandle,
		pubBytes: pub.Bytes(),
	}, nil
}

func (k *tpmBackedPrivateKey) PublicKey() nt.NoisePublicKey {
	return nt.NoisePublicKey(k.pubBytes)
}

func (k *tpmBackedPrivateKey) SharedSecret(peer nt.NoisePublicKey) ([32]byte, error) {

	pk, err := getKeyCommon(k.path, k.handle)
	if err != nil {
		return [32]byte{}, err
	}
	defer pk.Close()

	peerX, peerY := elliptic.Unmarshal(elliptic.P256(), peer[:])
	peerECPoint := tpm2.ECPoint{
		XRaw: peerX.Bytes(),
		YRaw: peerY.Bytes(),
	}
	z, err := tpm2.ECDHZGen(pk.rwc, pk.handle, "", peerECPoint)
	if err != nil {
		return [32]byte{}, err
	}

	zBytes := z.X().Bytes()
	return [32]byte(zBytes), nil
}

func (yk *tpmBackedPrivateKey) IsZero() bool {
	return false
}

func (yk *tpmBackedPrivateKey) FromHex(src string) error {
	return ErrUnsupported
}

func (yk *tpmBackedPrivateKey) FromMaybeZeroHex(src string) error {
	return ErrUnsupported
}

func (yk *tpmBackedPrivateKey) IsHardware() bool {
	return true
}

func parsePkcs11Uri(uri string) (string, uint32, error) {

	u, err := url.Parse(uri)
	if err != nil {
		return "", 0, err
	}

	vals, err := url.ParseQuery(strings.ReplaceAll(u.Opaque, ";", "&"))
	if err != nil {
		return "", 0, err
	}

	path := vals.Get("path")
	if path == "" {
		path = "/dev/tpm0"
	}

	handle := vals.Get("handle")
	if handle == "" {
		return "", 0, fmt.Errorf("no handle specified in tpm key")
	}

	h, err := strconv.ParseUint(handle, 0, 32)
	if err != nil {
		return "", 0, err
	}

	return path, uint32(h), nil
}
