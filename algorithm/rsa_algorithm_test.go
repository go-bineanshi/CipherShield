package algorithm_test

import (
	"crypto"
	"github.com/go-bineanshi/CipherShield/algorithm"
	"github.com/go-bineanshi/CipherShield/pkg"
	"testing"
)

func TestRSAStrategy(t *testing.T) {
	cert, err := pkg.GenerateCert()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rsaStrategy cert: %s", cert.GetPrivateKeyString())
	t.Logf("rsaStrategy key: %s", cert.GetPublicKeyString())
	rsaStrategy := algorithm.NewRSAStrategy(
		cert,
		algorithm.WithRSAPadding("OAEP"),
		algorithm.WithRSAHash(crypto.SHA256.New()),
		algorithm.WithRSAMGFHash(crypto.SHA512.New()))

	ciphertext, err := rsaStrategy.Encrypt([]byte("hello work"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rsaStrategy ciphertext: %s", ciphertext)
	plaintext, err := rsaStrategy.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rsaStrategy plaintext: %s", plaintext)

}
