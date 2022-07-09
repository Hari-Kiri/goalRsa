package goalRsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Generate new key pair
func NewRsaKeyPair(keyBitsSize int) (*bytes.Buffer, *bytes.Buffer, error) {
	// Generate new key
	generateKey, errorGenerateKey := rsa.GenerateKey(rand.Reader, keyBitsSize)
	if errorGenerateKey != nil {
		return nil, nil, errorGenerateKey
	}
	// Format private key to pem
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(generateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPem := new(bytes.Buffer)
	errorCreatePrivatePem := pem.Encode(privateKeyPem, privateKeyBlock)
	if errorCreatePrivatePem != nil {
		return nil, nil, errorCreatePrivatePem
	}
	// Format public key to pem
	publicKeyBytes, errorPublicKeyBytes := x509.MarshalPKIXPublicKey(&generateKey.PublicKey)
	if errorPublicKeyBytes != nil {
		return nil, nil, errorPublicKeyBytes
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPem := new(bytes.Buffer)
	errorCreatePublicPem := pem.Encode(publicKeyPem, publicKeyBlock)
	if errorCreatePublicPem != nil {
		return nil, nil, errorCreatePublicPem
	}
	// Return result
	return privateKeyPem, publicKeyPem, nil
}

// Decrypt ecrypted data with private key
func RsaOaepDecryptWithPrivateKey(privateKey string, base64EncryptedData string) (string, error) {
	// Extract private key
	extractPrivateKey, result := pem.Decode([]byte(privateKey))
	if extractPrivateKey == nil {
		return "", fmt.Errorf("cannot read key, no pem encoded data: %s", fmt.Sprintf("%v", result))
	}
	if extractPrivateKey.Type != "RSA PRIVATE KEY" {
		return "", fmt.Errorf("not expected key type %q, expected %q", extractPrivateKey.Type, "RSA PRIVATE KEY")
	}
	// Decode private key
	parsePKCS1PrivateKey, errorDecodePrivateKey := x509.ParsePKCS1PrivateKey(extractPrivateKey.Bytes)
	if errorDecodePrivateKey != nil {
		return "", fmt.Errorf("key parsing failed: %s", errorDecodePrivateKey)
	}
	// Decode encrypted data from base64 to byte array
	decodeEncryptedData, errorDecodeEncryptedData := base64.StdEncoding.DecodeString(base64EncryptedData)
	if errorDecodeEncryptedData != nil {
		return "", fmt.Errorf("base64EncryptedData decoding failed: %s", errorDecodeEncryptedData)
	}
	decryptData, errorDecryptData := rsa.DecryptPKCS1v15(
		rand.Reader,
		parsePKCS1PrivateKey,
		decodeEncryptedData)
	if errorDecryptData != nil {
		return "", fmt.Errorf("data decrypting failed: %s", errorDecryptData)
	}
	return string(decryptData), nil
}
