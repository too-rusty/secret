package keymanager

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

var _ KeyManagerIface = keyManager{}
var errPathInvalid = errors.New("invalid path")
var errFileExists = errors.New("file exists")
var errNoPubKey = errors.New("no pub key")
var errNoPrivKey = errors.New("no priv key")
var errIncorrectMode = errors.New("incorrect mode")

const (
	GEN_MODE = iota
	READ_MODE
	WRITE_MODE
)

type keyManager struct {
	privKeyFilePath string
	mode            uint8
}

func NewKeyManager(privKeyFilePath string, mode uint8) (keyManager, error) {
	km := keyManager{
		privKeyFilePath: privKeyFilePath,
		mode:            mode,
	}
	return km, preValidate(km)
}

// generates pub priv key pairs as pem files, the files should not exist
func (k keyManager) Generate() error {

	if k.mode != GEN_MODE {
		return errIncorrectMode
	}
	path := k.privKeyFilePath

	if pubKeyExists(path) || privKeyExists(path) {
		return errFileExists
	}

	privKey, err := generateKeyPair()
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(path, exportPrivKeyAsPEMStr(privKey), 0777); err != nil {
		return err
	}

	if err := ioutil.WriteFile(pubKeyFilePath(path), exportPubKeyAsPEMStr(&privKey.PublicKey), 0777); err != nil {
		os.Remove(path) // remove the private file too
		return err
	}

	return nil
}

func (k keyManager) EncryptData(data []byte) ([]byte, error) {
	if k.mode != WRITE_MODE {
		return nil, errIncorrectMode
	}
	if !pubKeyExists(k.privKeyFilePath) {
		return nil, errNoPubKey
	}
	pubKey, err := k.loadPubKey()
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pubKey,
		data,
		nil,
	)

}

func (k keyManager) DecryptData(data []byte) ([]byte, error) {
	if k.mode != READ_MODE {
		return nil, errIncorrectMode
	}
	if !privKeyExists(k.privKeyFilePath) {
		return nil, errNoPrivKey
	}
	privKey, err := k.loadPrivKey()
	if err != nil {
		return nil, err
	}
	return privKey.Decrypt(nil, data, &rsa.OAEPOptions{Hash: crypto.SHA256})
}

func (k keyManager) loadPubKey() (*rsa.PublicKey, error) {
	pemBytes, err := ioutil.ReadFile(pubKeyFilePath(k.privKeyFilePath))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func (k keyManager) loadPrivKey() (*rsa.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(k.privKeyFilePath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
