package registry

import (
	"fmt"
	"net/url"

	nt "golang.zx2c4.com/wireguard/device/noisetypes"
)

type HardwareBackedKeyFunc func(string) (nt.NoisePrivateKey, error)

var hardwareBackedKeyProviders = map[string]HardwareBackedKeyFunc{}

func RegisterHardwareKeyProvider(provider string, fn HardwareBackedKeyFunc) {
	hardwareBackedKeyProviders[provider] = fn
}

func HandleHardwareKey(value string) (nt.NoisePrivateKey, error) {

	u, err := url.Parse(value)
	if err != nil {
		return nil, err
	}

	fn, ok := hardwareBackedKeyProviders[u.Scheme]
	if !ok {
		return nil, fmt.Errorf("not implemented")
	}

	sk, err := fn(value)
	if err != nil {
		return nil, err
	}

	return sk, nil
}
