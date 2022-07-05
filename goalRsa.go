package goalRsa

import (
	"crypto/rand"
	"crypto/rsa"
)

func NewRsaKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, error := rsa.GenerateKey(rand.Reader, bits)
	if error != nil {
		return nil, nil, error
	}
	return privateKey, &privateKey.PublicKey, nil
}
