package goalRsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func NewRsaKeyPair(bits int) (*pem.Block, *pem.Block, error) {
	privateKey, error := rsa.GenerateKey(rand.Reader, bits)
	if error != nil {
		return nil, nil, error
	}

	// dump private key to file
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	// privatePem, err := os.Create("private.pem")
	// if err != nil {
	//     return nil, nil, error
	// }
	// err = pem.Encode(privatePem, privateKeyBlock)
	// if err != nil {
	//     return nil, nil, error
	// }

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, error
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	// publicPem, err := os.Create("public.pem")
	// if err != nil {
	//     return nil, nil, error
	// }
	// err = pem.Encode(publicPem, publicKeyBlock)
	// if err != nil {
	//     return nil, nil, error
	// }

	return privateKeyBlock, publicKeyBlock, nil
}
