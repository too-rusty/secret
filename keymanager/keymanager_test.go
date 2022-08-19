package keymanager

import (
	"errors"
	"os"
	"testing"
)

func TestKeyManagerGeneratesFile(t *testing.T) {
	_, err := NewKeyManager("", GEN_MODE)
	if err != errPathInvalid {
		t.Errorf("got: %v, want: %v", err, errPathInvalid)
	}

	_, err = NewKeyManager("", WRITE_MODE)
	if err != errPathInvalid {
		t.Errorf("got: %v, want: %v", err, errIncorrectMode)
	}

	path := "path"
	cleanup, err := generateFileAndCleanup(path)
	if err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}
	if err := cleanup(); err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}

}

func TestKeyManagerEncryptsAndDecryptsData(t *testing.T) {

	path := "path"
	cleanup, err := generateFileAndCleanup(path)
	if err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}
	defer cleanup()

	data := []byte("some super secret data")

	kmEncrypt, err := NewKeyManager(path, WRITE_MODE)
	if err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}

	kmDecrypt, err := NewKeyManager(path, READ_MODE)
	if err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}

	encryptedData, err := kmEncrypt.EncryptData(data)
	if err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}

	got, err := kmDecrypt.DecryptData(encryptedData)
	if err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}

	if string(got) != string(data) {
		t.Errorf("got: %v, want: %v", string(got), string(data))
	}
}

func TestKeyManagerShouldNotDecryptFromOtherKey(t *testing.T) {

	path := "path"
	cleanup, err := generateFileAndCleanup(path)
	if err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}
	defer cleanup()

	path2 := "path2"
	cleanup2, err := generateFileAndCleanup(path2)
	if err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}
	defer cleanup2()

	data := []byte("some super secret data")

	kmEncrypt, err := NewKeyManager(path, WRITE_MODE)
	if err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}

	kmDecrypt, err := NewKeyManager(path2, READ_MODE)
	if err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}

	encryptedData, err := kmEncrypt.EncryptData(data)
	if err != nil {
		t.Errorf("got: %v, want: %v", err, nil)
	}

	_, err = kmDecrypt.DecryptData(encryptedData)
	decryptionErr := errors.New("crypto/rsa: decryption error")
	if err.Error() != decryptionErr.Error() {
		t.Errorf("got: %v, want: %v", err, decryptionErr)
	}

}

func generateFileAndCleanup(path string) (func() error, error) {
	km, err := NewKeyManager(path, GEN_MODE)

	if err != nil {
		return nil, err
	}
	if err := km.Generate(); err != nil {
		return nil, err
	}

	cleanup := func() error {
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := os.Remove(pubKeyFilePath(path)); err != nil {
			return err
		}
		return nil
	}
	return cleanup, nil
}
