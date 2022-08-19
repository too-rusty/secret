package keymanager

type KeyManagerIface interface {
	Generate() error
	// generates public private key and saves them to a file

	EncryptData([]byte) ([]byte, error)
	// encrypts data

	DecryptData([]byte) ([]byte, error)
	// decrypts data
}
