package pkg_test

import (
	"github.com/go-bineanshi/CipherShield/pkg"
	"testing"
)

func TestGenerateCert(t *testing.T) {
	cert, err := pkg.GenerateCert()
	if err != nil {
		t.Errorf("Failed to generate cert: %v", err)
	}

	t.Logf(cert.GetPrivateKeyString())
	t.Logf(cert.GetPublicKeyString())
}
