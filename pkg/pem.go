package pkg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type Cert struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func NewCertByKey(privateKeyStr, publicKeyStr string) Cert {
	return Cert{
		PrivateKey: parsePrivateKey(privateKeyStr),
		PublicKey:  parsePublicKey(publicKeyStr),
	}
}

func GenerateCert() (Cert, error) {
	return GenerateCertWithKeySize(2048)
}

func GenerateCertWithKeySize(keySize int) (Cert, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return Cert{}, err
	}
	// 将公钥提取为 *rsa.PublicKey 类型
	publicKey := &privateKey.PublicKey

	return Cert{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

func (c Cert) GetPrivateKeyString() string {
	privateDER := x509.MarshalPKCS1PrivateKey(c.PrivateKey)
	// 将 DER 编码的私钥转换为 PEM 格式
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateDER,
	})
	return string(privatePEM)
}

func (c Cert) GetPublicKeyString() string {
	// 将公钥转换为 ASN.1 PKIX DER 编码
	pubDER, _ := x509.MarshalPKIXPublicKey(c.PublicKey)
	//if err != nil {
	//	return fmt.Errorf("公钥编码失败: %v", err)
	//}
	// 将 DER 编码的公钥转换为 PEM 格式
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubDER,
	})
	return string(publicPEM)
}

func parsePrivateKey(privateKeyStr string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("failed to decode PEM block containing private key")
		return &rsa.PrivateKey{}
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Error parsing private key: %s\n", err)
		return &rsa.PrivateKey{}
	}

	return privateKey
}
func parsePublicKey(publicKeyStr string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		fmt.Println("failed to decode PEM block containing public key")
		return &rsa.PublicKey{}
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("Error parsing public key: %s\n", err)
		return &rsa.PublicKey{}
	}

	publicKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		fmt.Printf("Error casting public key to RSA Public Key\n")
		return &rsa.PublicKey{}
	}

	return publicKey
}
