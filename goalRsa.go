package goalRsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	convertPrivateKeyBytes, errorConvertPrivateKeyBytes := x509.MarshalPKCS8PrivateKey(generateKey)
	if errorConvertPrivateKeyBytes != nil {
		return nil, nil, errorConvertPrivateKeyBytes
	}
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: convertPrivateKeyBytes,
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
func DecryptRSAWithPrivateKey(pemFormatPKCS8PrivateKey string, base64EncryptedData string) (string, error) {
	var result string
	// Extract private key
	extractPrivateKey, rest := pem.Decode([]byte(pemFormatPKCS8PrivateKey))
	if extractPrivateKey == nil {
		return result, fmt.Errorf("cannot read key, no pem encoded data: %s", fmt.Sprintf("%v", rest))
	}
	if extractPrivateKey.Type != "PRIVATE KEY" {
		return result, fmt.Errorf("not expected key type %q, expected %q", extractPrivateKey.Type, "PRIVATE KEY")
	}
	// Decode private key
	parsePKCS1PrivateKey, errorDecodePrivateKey := x509.ParsePKCS8PrivateKey(extractPrivateKey.Bytes)
	if errorDecodePrivateKey != nil {
		return result, fmt.Errorf("key parsing failed: %s", errorDecodePrivateKey)
	}
	// Decode encrypted data from base64 to byte array
	decodeEncryptedData, errorDecodeEncryptedData := base64.StdEncoding.DecodeString(base64EncryptedData)
	if errorDecodeEncryptedData != nil {
		return result, fmt.Errorf("base64EncryptedData decoding failed: %s", errorDecodeEncryptedData)
	}
	// Decrypt encrypted data using RSA OAEP
	decryptData, errorDecryptData := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		parsePKCS1PrivateKey.(*rsa.PrivateKey),
		decodeEncryptedData,
		[]byte("OAEP Encrypted"))
	result = string(decryptData)
	if errorDecryptData != nil {
		return result, fmt.Errorf("data decrypting failed: %s", errorDecryptData)
	}
	return result, nil
}
