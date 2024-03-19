package algorithm_test

import (
	"encoding/base64"
	"fmt"
	"github.com/go-bineanshi/CipherShield/algorithm"
	"github.com/go-bineanshi/CipherShield/pkg"
	"github.com/stretchr/testify/assert"
	"testing"
)

func newAESAlgorithm(actuatorName string) *algorithm.AESAlgorithm {
	key := pkg.RandStr(16)
	iv := pkg.RandStr(16)
	_aesAlgorithm, err := algorithm.NewAESAlgorithm([]byte(key), []byte(iv), algorithm.WithAESActuator(actuatorName))
	if err != nil {
		panic(err)
	}
	fmt.Printf("key: %s\n", key)
	fmt.Printf("iv : %s\n", iv)
	return _aesAlgorithm
}

func TestAESAlgorithm(t *testing.T) {
	aesAlgorithm := newAESAlgorithm("cbc")
	plaintext := pkg.RandStr(22)
	fmt.Printf("明文:    %s\n", plaintext)
	// 加密
	encrypt, err := aesAlgorithm.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("加密结果: %s\n", encrypt)
	assert.NoErrorf(t, err, "加密失败")
	// 解密
	decrypt, err := aesAlgorithm.Decrypt(encrypt)
	assert.NoErrorf(t, err, "解密失败")
	fmt.Printf("解密结果: %s\n", decrypt)
	assert.Equal(t, decrypt, plaintext)
}

func newAESAlgorithmWithGCM(additionalData []byte) *algorithm.AESAlgorithm {
	key := pkg.RandStr(16)
	iv := pkg.RandStr(16)
	_aesAlgorithm, err := algorithm.NewAESAlgorithm([]byte(key), []byte(iv), algorithm.WithAESActuator("gcm"), algorithm.WithAESAdditionalData(additionalData))
	if err != nil {
		panic(err)
	}
	fmt.Printf("key: %s\n", key)
	fmt.Printf("iv : %s\n", iv)
	return _aesAlgorithm
}

func TestAESAlgorithmWithGCM(t *testing.T) {
	additionData := pkg.RandStr(10)
	fmt.Printf("附加数据: %s\n", additionData)
	aesAlgorithm := newAESAlgorithmWithGCM([]byte(additionData))

	plaintext := pkg.RandStr(22)
	fmt.Printf("明文: %s\n", plaintext)
	// 加密
	encrypt, err := aesAlgorithm.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("加密结果: %s\n", encrypt)
	assert.NoErrorf(t, err, "加密失败")
	ciphertext, err := base64.StdEncoding.DecodeString(encrypt)
	if err != nil {
		return
	}
	fmt.Printf("密文: %s\n", base64.StdEncoding.EncodeToString(ciphertext[:len(ciphertext)-16]))
	fmt.Printf("确认码: %s\n", base64.StdEncoding.EncodeToString(ciphertext[len(ciphertext)-16:]))
	// 解密
	decrypt, err := aesAlgorithm.Decrypt(encrypt)
	assert.NoErrorf(t, err, "解密失败")
	fmt.Printf("解密结果: %s\n", decrypt)
	assert.Equal(t, string(decrypt), plaintext)
}
