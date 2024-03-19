package algorithm

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/go-bineanshi/CipherShield/pkg"
	"hash"
	"strings"
)

type RSAStrategy struct {
	cert pkg.Cert
	hash.Hash
	MGFHash hash.Hash
	padding string
}

type RSAOptions struct {
	hash.Hash
	MGFHash hash.Hash
	Padding string
}

type RSAOption func(*RSAOptions)

func WithRSAPadding(padding string) RSAOption {
	return func(options *RSAOptions) {
		options.Padding = strings.ToUpper(padding)
	}
}

func WithRSAHash(hash hash.Hash) RSAOption {
	return func(options *RSAOptions) {
		options.Hash = hash
	}
}

func WithRSAMGFHash(hash hash.Hash) RSAOption {
	return func(options *RSAOptions) {
		options.MGFHash = hash
	}
}

func NewRSAStrategy(cert pkg.Cert, options ...RSAOption) *RSAStrategy {
	opts := &RSAOptions{
		Padding: "PKCS1v15",
		Hash:    nil,
		MGFHash: nil,
	}
	for _, option := range options {
		option(opts)
	}
	return &RSAStrategy{
		cert,
		opts.Hash,
		opts.MGFHash,
		opts.Padding,
	}
}

func (r *RSAStrategy) Encrypt(plaintext []byte) (string, error) {
	var ciphertext []byte
	var err error
	switch r.padding {
	case "OAEP":
		ciphertext, err = rsa.EncryptOAEP(r.Hash, rand.Reader, r.cert.PublicKey, plaintext, nil)
	case "PKCS1v15":
		ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, r.cert.PublicKey, plaintext)
	default:
		return "", fmt.Errorf("unsupport Error decrypting message: %s\n", err)
	}
	if err != nil {
		return "", fmt.Errorf("Error encrypting message: %s\n", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (r *RSAStrategy) Decrypt(ciphertext string) (string, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	var plaintext []byte
	switch r.padding {
	case "OAEP":
		plaintext, err = rsa.DecryptOAEP(r.Hash, rand.Reader, r.cert.PrivateKey, cipherBytes, nil)
	case "PKCS1v15":
		plaintext, err = rsa.DecryptPKCS1v15(rand.Reader, r.cert.PrivateKey, cipherBytes)
	default:
		return "", fmt.Errorf("unsupport Error decrypting message: %s\n", err)
	}
	if err != nil {
		return "", fmt.Errorf("Error decrypting message: %s\n", err)
	}
	return string(plaintext), nil
}
