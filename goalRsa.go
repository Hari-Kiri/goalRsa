package goalRsa

import (
	"crypto/rand"
	"crypto/rsa"
)

func NewRsaKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, errorGeneration := rsa.GenerateKey(rand.Reader, bits)
	if errorGeneration != nil {
		return nil, nil, errorGeneration
	}
	return privateKey, &privateKey.PublicKey, nil
}
