package goalRsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func NewRsaKeyPair(bits int) (string, string, error) {
	// Generate new key
	privateKey, errorPrivateKeyGeneration := rsa.GenerateKey(rand.Reader, bits)
	if errorPrivateKeyGeneration != nil {
		return "", "", errorPrivateKeyGeneration
	}
	// Format private key to pem
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem := new(bytes.Buffer)
	errorCreatePrivatePem := pem.Encode(privatePem, privateKeyBlock)
	if errorCreatePrivatePem != nil {
		return "", "", errorCreatePrivatePem
	}
	// Format public key to pem
	publicKeyBytes, errorPublicKeyBytes := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if errorPublicKeyBytes != nil {
		return "", "", errorPublicKeyBytes
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem := new(bytes.Buffer)
	errorCreatePublicPem := pem.Encode(publicPem, publicKeyBlock)
	if errorCreatePublicPem != nil {
		return "", "", errorCreatePublicPem
	}
	// Return result
	return privatePem.String(), publicPem.String(), nil
}
