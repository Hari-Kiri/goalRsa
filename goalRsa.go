package goalRsa

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Extract RSA private key from string PEM format
func extractRSAPrivateKey(pemFormatPKCS8PrivateKey string) (*rsa.PrivateKey, error) {
	// Extract private key
	extractPrivateKey, rest := pem.Decode([]byte(pemFormatPKCS8PrivateKey))
	if extractPrivateKey == nil {
		return nil, fmt.Errorf("cannot read key, no pem encoded data: %q", fmt.Sprintf("%v", rest))
	}
	if extractPrivateKey.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("expected key type %q, provided key type %q", "PRIVATE KEY", extractPrivateKey.Type)
	}
	// Decode private key
	parsePKCS1PrivateKey, errorDecodePrivateKey := x509.ParsePKCS8PrivateKey(extractPrivateKey.Bytes)
	if errorDecodePrivateKey != nil {
		return nil, fmt.Errorf("key parsing failed: %q", errorDecodePrivateKey)
	}
	return parsePKCS1PrivateKey.(*rsa.PrivateKey), nil
}

// Extract RSA public key from string PEM format
func extractRSAPublicKey(pemFormatPKCS8PublicKey string) (*rsa.PublicKey, error) {
	// Extract public key
	extractPublicKey, rest := pem.Decode([]byte(pemFormatPKCS8PublicKey))
	if extractPublicKey == nil {
		return nil, fmt.Errorf("cannot read key, no pem encoded data: %q", fmt.Sprintf("%v", rest))
	}
	if extractPublicKey.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("expected key type %q, provided key type %q", "PUBLIC KEY", extractPublicKey.Type)
	}
	// Decode public key
	parsePKCS1PublicKey, errorDecodePublicKey := x509.ParsePKIXPublicKey(extractPublicKey.Bytes)
	if errorDecodePublicKey != nil {
		return nil, fmt.Errorf("key parsing failed: %q", errorDecodePublicKey)
	}
	return parsePKCS1PublicKey.(*rsa.PublicKey), nil
}

// Generate new key pair
func NewRsaKeyPair(keyBitsSize int) ([]byte, []byte, error) {
	// Generate new key
	generateKey, errorGenerateKey := rsa.GenerateKey(rand.Reader, keyBitsSize)
	if errorGenerateKey != nil {
		return nil, nil, errorGenerateKey
	}
	generatePrivateKey, errorGeneratePrivateKey := x509.MarshalPKCS8PrivateKey(generateKey)
	if errorGeneratePrivateKey != nil {
		return nil, nil, errorGeneratePrivateKey
	}
	generatePublicKey, errorGeneratePublicKey := x509.MarshalPKIXPublicKey(&generateKey.PublicKey)
	if errorGeneratePublicKey != nil {
		return nil, nil, errorGeneratePublicKey
	}
	return generatePrivateKey, generatePublicKey, nil
}

// Generate new key pair in pem formated
func NewPemFormatRsaKeyPair(keyBitsSize int) (*bytes.Buffer, *bytes.Buffer, error) {
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
	convertPublicKeyBytes, errorPublicKeyBytes := x509.MarshalPKIXPublicKey(&generateKey.PublicKey)
	if errorPublicKeyBytes != nil {
		return nil, nil, errorPublicKeyBytes
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: convertPublicKeyBytes,
	}
	publicKeyPem := new(bytes.Buffer)
	errorCreatePublicPem := pem.Encode(publicKeyPem, publicKeyBlock)
	if errorCreatePublicPem != nil {
		return nil, nil, errorCreatePublicPem
	}
	// Return result
	return privateKeyPem, publicKeyPem, nil
}

// Decrypt encrypted data with RSA private key. This method using RSA padding PKCS#1 v1.5.
func DecryptRSAPKCS1v15(pemFormatPKCS8PrivateKey string, base64EncryptedData string) (string, error) {
	var result string
	// Extract RSA private key from string PEM format
	parsePKCS1PrivateKey, errorParsePKCS1PrivateKey := extractRSAPrivateKey(pemFormatPKCS8PrivateKey)
	if errorParsePKCS1PrivateKey != nil {
		return result, errorParsePKCS1PrivateKey
	}
	// Decode encrypted data from base64 to byte array
	decodeEncryptedData, errorDecodeEncryptedData := base64.StdEncoding.DecodeString(base64EncryptedData)
	if errorDecodeEncryptedData != nil {
		return result, fmt.Errorf("base64EncryptedData decoding failed: %q", errorDecodeEncryptedData)
	}
	// Decrypt data
	decryptData, errorDecryptData := rsa.DecryptPKCS1v15(
		rand.Reader,
		parsePKCS1PrivateKey,
		decodeEncryptedData)
	if errorDecryptData != nil {
		return result, fmt.Errorf("data decrypting failed: %q", errorDecryptData)
	}
	result = string(decryptData)
	return result, nil
}

// Decrypt encrypted data with RSA private key. This method using RSA padding OAEP with Md5 hash.
func DecryptRSAOAEPMd5(pemFormatPKCS8PrivateKey string, base64EncryptedData string, label string) (string, error) {
	var result string
	// Extract RSA private key from string PEM format
	parsePKCS1PrivateKey, errorParsePKCS1PrivateKey := extractRSAPrivateKey(pemFormatPKCS8PrivateKey)
	if errorParsePKCS1PrivateKey != nil {
		return result, errorParsePKCS1PrivateKey
	}
	// Decode encrypted data from base64 to byte array
	decodeEncryptedData, errorDecodeEncryptedData := base64.StdEncoding.DecodeString(base64EncryptedData)
	if errorDecodeEncryptedData != nil {
		return result, fmt.Errorf("base64EncryptedData decoding failed: %q", errorDecodeEncryptedData)
	}
	// Decrypt data
	decryptData, errorDecryptData := rsa.DecryptOAEP(
		md5.New(),
		rand.Reader,
		parsePKCS1PrivateKey,
		decodeEncryptedData,
		[]byte(label))
	if errorDecryptData != nil {
		return result, fmt.Errorf("data decrypting failed: %q", errorDecryptData)
	}
	result = string(decryptData)
	return result, nil
}

// Decrypt encrypted data with RSA private key. This method using RSA padding OAEP with Sha1 hash.
func DecryptRSAOAEPSha1(pemFormatPKCS8PrivateKey string, base64EncryptedData string, label string) (string, error) {
	var result string
	// Extract RSA private key from string PEM format
	parsePKCS1PrivateKey, errorParsePKCS1PrivateKey := extractRSAPrivateKey(pemFormatPKCS8PrivateKey)
	if errorParsePKCS1PrivateKey != nil {
		return result, errorParsePKCS1PrivateKey
	}
	// Decode encrypted data from base64 to byte array
	decodeEncryptedData, errorDecodeEncryptedData := base64.StdEncoding.DecodeString(base64EncryptedData)
	if errorDecodeEncryptedData != nil {
		return result, fmt.Errorf("base64EncryptedData decoding failed: %q", errorDecodeEncryptedData)
	}
	// Decrypt data
	decryptData, errorDecryptData := rsa.DecryptOAEP(
		sha1.New(),
		rand.Reader,
		parsePKCS1PrivateKey,
		decodeEncryptedData,
		[]byte(label))
	if errorDecryptData != nil {
		return result, fmt.Errorf("data decrypting failed: %q", errorDecryptData)
	}
	result = string(decryptData)
	return result, nil
}

// Decrypt encrypted data with RSA private key. This method using RSA padding OAEP with Sha256 hash.
func DecryptRSAOAEPSha256(pemFormatPKCS8PrivateKey string, base64EncryptedData string, label string) (string, error) {
	var result string
	// Extract RSA private key from string PEM format
	parsePKCS1PrivateKey, errorParsePKCS1PrivateKey := extractRSAPrivateKey(pemFormatPKCS8PrivateKey)
	if errorParsePKCS1PrivateKey != nil {
		return result, errorParsePKCS1PrivateKey
	}
	// Decode encrypted data from base64 to byte array
	decodeEncryptedData, errorDecodeEncryptedData := base64.StdEncoding.DecodeString(base64EncryptedData)
	if errorDecodeEncryptedData != nil {
		return result, fmt.Errorf("base64EncryptedData decoding failed: %q", errorDecodeEncryptedData)
	}
	// Decrypt data
	decryptData, errorDecryptData := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		parsePKCS1PrivateKey,
		decodeEncryptedData,
		[]byte(label))
	if errorDecryptData != nil {
		return result, fmt.Errorf("data decrypting failed: %q", errorDecryptData)
	}
	result = string(decryptData)
	return result, nil
}

// Decrypt encrypted data with RSA private key. This method using RSA padding OAEP with Sha512 hash.
func DecryptRSAOAEPSha512(pemFormatPKCS8PrivateKey string, base64EncryptedData string, label string) (string, error) {
	var result string
	// Extract RSA private key from string PEM format
	parsePKCS1PrivateKey, errorParsePKCS1PrivateKey := extractRSAPrivateKey(pemFormatPKCS8PrivateKey)
	if errorParsePKCS1PrivateKey != nil {
		return result, errorParsePKCS1PrivateKey
	}
	// Decode encrypted data from base64 to byte array
	decodeEncryptedData, errorDecodeEncryptedData := base64.StdEncoding.DecodeString(base64EncryptedData)
	if errorDecodeEncryptedData != nil {
		return result, fmt.Errorf("base64EncryptedData decoding failed: %q", errorDecodeEncryptedData)
	}
	// Decrypt data
	decryptData, errorDecryptData := rsa.DecryptOAEP(
		sha512.New(),
		rand.Reader,
		parsePKCS1PrivateKey,
		decodeEncryptedData,
		[]byte(label))
	if errorDecryptData != nil {
		return result, fmt.Errorf("data decrypting failed: %q", errorDecryptData)
	}
	result = string(decryptData)
	return result, nil
}

// Encrypt data with RSA public key. This method using RSA padding PKCS#1 v1.5.
// WARNING: encrypt plaintext with this method is dangerous. Please use encryption method with padding OAEP.
func EncryptRSAPKCS1v15(pemFormatPKCS8PublicKey string, dataToEncrypt string) (string, error) {
	var result string
	// Extract RSA public key from string PEM format
	parsePKCS1PublicKey, errorParsePKCS1PublicKey := extractRSAPublicKey(pemFormatPKCS8PublicKey)
	if errorParsePKCS1PublicKey != nil {
		return result, errorParsePKCS1PublicKey
	}
	// Encrypt data
	encryptData, errorEncryptData := rsa.EncryptPKCS1v15(
		rand.Reader,
		parsePKCS1PublicKey,
		[]byte(dataToEncrypt))
	if errorEncryptData != nil {
		return result, fmt.Errorf("data encrypting failed: %q", encryptData)
	}
	result = base64.StdEncoding.EncodeToString(encryptData)
	return result, nil
}

// Encrypt data with RSA public key. This method using RSA padding OAEP and MD5 hash.
func EncryptRSAOAEPMd5(pemFormatPKCS8PublicKey string, dataToEncrypt string, label string) (string, error) {
	var result string
	// Extract RSA public key from string PEM format
	parsePKCS1PublicKey, errorParsePKCS1PublicKey := extractRSAPublicKey(pemFormatPKCS8PublicKey)
	if errorParsePKCS1PublicKey != nil {
		return result, errorParsePKCS1PublicKey
	}
	// Encrypt data
	encryptData, errorEncryptData := rsa.EncryptOAEP(
		md5.New(),
		rand.Reader,
		parsePKCS1PublicKey,
		[]byte(dataToEncrypt),
		[]byte(label))
	if errorEncryptData != nil {
		return result, fmt.Errorf("data encrypting failed: %q", encryptData)
	}
	result = base64.StdEncoding.EncodeToString(encryptData)
	return result, nil
}

// Encrypt data with RSA public key. This method using RSA padding OAEP and SHA1 hash.
func EncryptRSAOAEPSha1(pemFormatPKCS8PublicKey string, dataToEncrypt string, label string) (string, error) {
	var result string
	// Extract RSA public key from string PEM format
	parsePKCS1PublicKey, errorParsePKCS1PublicKey := extractRSAPublicKey(pemFormatPKCS8PublicKey)
	if errorParsePKCS1PublicKey != nil {
		return result, errorParsePKCS1PublicKey
	}
	// Encrypt data
	encryptData, errorEncryptData := rsa.EncryptOAEP(
		sha1.New(),
		rand.Reader,
		parsePKCS1PublicKey,
		[]byte(dataToEncrypt),
		[]byte(label))
	if errorEncryptData != nil {
		return result, fmt.Errorf("data encrypting failed: %q", encryptData)
	}
	result = base64.StdEncoding.EncodeToString(encryptData)
	return result, nil
}

// Encrypt data with RSA public key. This method using RSA padding OAEP and SHA256 hash.
func EncryptRSAOAEPSha256(pemFormatPKCS8PublicKey string, dataToEncrypt string, label string) (string, error) {
	var result string
	// Extract RSA public key from string PEM format
	parsePKCS1PublicKey, errorParsePKCS1PublicKey := extractRSAPublicKey(pemFormatPKCS8PublicKey)
	if errorParsePKCS1PublicKey != nil {
		return result, errorParsePKCS1PublicKey
	}
	// Encrypt data
	encryptData, errorEncryptData := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		parsePKCS1PublicKey,
		[]byte(dataToEncrypt),
		[]byte(label))
	if errorEncryptData != nil {
		return result, fmt.Errorf("data encrypting failed: %q", encryptData)
	}
	result = base64.StdEncoding.EncodeToString(encryptData)
	return result, nil
}

// Encrypt data with RSA public key. This method using RSA padding OAEP and SHA512 hash.
func EncryptRSAOAEPSha512(pemFormatPKCS8PublicKey string, dataToEncrypt string, label string) (string, error) {
	var result string
	// Extract RSA public key from string PEM format
	parsePKCS1PublicKey, errorParsePKCS1PublicKey := extractRSAPublicKey(pemFormatPKCS8PublicKey)
	if errorParsePKCS1PublicKey != nil {
		return result, errorParsePKCS1PublicKey
	}
	// Encrypt data
	encryptData, errorEncryptData := rsa.EncryptOAEP(
		sha512.New(),
		rand.Reader,
		parsePKCS1PublicKey,
		[]byte(dataToEncrypt),
		[]byte(label))
	if errorEncryptData != nil {
		return result, fmt.Errorf("data encrypting failed: %q", encryptData)
	}
	result = base64.StdEncoding.EncodeToString(encryptData)
	return result, nil
}
