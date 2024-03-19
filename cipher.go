package CipherShield

type IEncryptionAlgorithm interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(ciphertext string) (string, error)
}

type EncryptionAlgorithm struct {
	Strategy IEncryptionAlgorithm
}

func (i *EncryptionAlgorithm) SetStrategy(strategy IEncryptionAlgorithm) error {
	i.Strategy = strategy
	return nil
}

func (i *EncryptionAlgorithm) Encrypt(plaintext string) (string, error) {

	return i.Strategy.Encrypt([]byte(plaintext))
}

func (i *EncryptionAlgorithm) Decrypt(ciphertext string) (string, error) {
	return i.Strategy.Decrypt(ciphertext)
}
