package CipherShield_test

import (
	"log"
	"testing"

	"github.com/go-bineanshi/CipherShield"
	"github.com/go-bineanshi/CipherShield/algorithm"
	"github.com/go-bineanshi/CipherShield/pkg"
)

const (
	keyLength = 16
	ivLength  = 16
)

var (
	key = pkg.RandStr(keyLength)
	iv  = pkg.RandStr(ivLength)
)

var ciphertext string
var algor CipherShield.EncryptionAlgorithm

func newAESActuator(actuatorName string) {
	aesActuator, err := algorithm.NewAESAlgorithm([]byte(key), []byte(iv), algorithm.WithAESActuator(actuatorName))
	if err != nil {
		panic(err)
	}
	algor = CipherShield.EncryptionAlgorithm{Strategy: aesActuator}
}

func TestAES(t *testing.T) {
	actuatorName := "cbc"
	log.Printf("\n\t\t\t\t\t算法模式: %s \n\t\t\t\t\tKEY\t\t:    %s \n\t\t\t\t\tIV\t\t:     %s\n", actuatorName, key, iv)
	newAESActuator(actuatorName)
	Decryption(Encryption())
}

func newRSAActuator() {
	cert, _ := pkg.GenerateCert()
	aesActuator := algorithm.NewRSAStrategy(cert)
	log.Printf("\n\t\t\t\t\t算法模式: %s \n\t\t\t\t\tPrivateKEY\t\t:    %s \n\t\t\t\t\tPublicKey\t\t:     %s\n", "RSA", cert.GetPrivateKeyString(), cert.GetPublicKeyString())
	algor = CipherShield.EncryptionAlgorithm{Strategy: aesActuator}
}

func TestRSA(t *testing.T) {

	newRSAActuator()

	Decryption(Encryption())
}

func Encryption() string {
	plaintext := "hello world"
	var err error
	ciphertext, err = algor.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	log.Printf("密文\t\t：%s\n", ciphertext)
	return ciphertext
}

func Decryption(ciphertext string) {
	plaintext, err := algor.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	log.Printf("明文\t\t：%s\n", plaintext)
}
