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

func setup(actuatorName string) {
	aesActuator, err := algorithm.NewAESAlgorithm([]byte(key), []byte(iv), algorithm.WithActuator(actuatorName))
	if err != nil {
		panic(err)
	}
	algor = CipherShield.EncryptionAlgorithm{Strategy: aesActuator}
}

func TestMain(m *testing.M) {
	actuatorName := "cbc"
	log.Printf("\n算法模式: %s \nKEY:    %s \nIV:     %s\n", actuatorName, key, iv)
	setup(actuatorName)
	m.Run()
}

func TestEncryptionWithAES(t *testing.T) {
	plaintext := "hello world"
	var err error
	ciphertext, err = algor.Encrypt(plaintext)
	if err != nil {
		t.Errorf("Encryption failed: %v", err)
	}

	t.Logf("密文：%s\n", ciphertext)
}

func TestDecryptionWithAES(t *testing.T) {
	plaintext, err := algor.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("Decryption failed: %v", err)
	}

	t.Logf("明文：%s\n", plaintext)
}
