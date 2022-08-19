package keymanager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
)

func pubKeyExists(path string) bool {
	if _, err := os.Stat(pubKeyFilePath(path)); err == nil {
		return true
	}
	return false
}

func privKeyExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

func pubKeyFilePath(privKeyFilePath string) (ret string) {
	ret = privKeyFilePath
	if !strings.HasSuffix(privKeyFilePath, ".pub") {
		ret += ".pub"
	}
	return
}

func generateKeyPair() (*rsa.PrivateKey, error) {
	// This method requires a random number of bits.
	return rsa.GenerateKey(rand.Reader, 2048)

}

// Export public key as a string in PEM format
func exportPubKeyAsPEMStr(pubkey *rsa.PublicKey) []byte {
	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pubkey),
		},
	)
	return pubKeyPem
}

// Export private key as a string in PEM format
func exportPrivKeyAsPEMStr(privkey *rsa.PrivateKey) []byte {
	privKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privkey),
		},
	)
	return privKeyPem

}

func preValidate(km keyManager) error {
	path := km.privKeyFilePath
	if path == "" {
		return errPathInvalid
	}
	switch km.mode {
	case GEN_MODE:
		if pubKeyExists(path) || privKeyExists(path) {
			return errFileExists
		}
	case WRITE_MODE:
		if !pubKeyExists(path) {
			return errNoPubKey
		}
	case READ_MODE:
		if !privKeyExists(path) {
			return errNoPrivKey
		}
	default:
	}
	return nil
}
