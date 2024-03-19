package actuator

import (
	"crypto/cipher"
)

type GCMActuator struct {
	Block          cipher.Block
	iv             []byte
	nonce          []byte
	additionalData []byte
}

func (gcm *GCMActuator) SetBlock(block cipher.Block, options ...ActuatorOption) {
	opts := &ActuatorOptions{}
	for _, option := range options {
		option(opts)
	}
	gcm.Block = block
	gcm.additionalData = opts.AdditionalData
	gcm.nonce = opts.IV
}

func (gcm *GCMActuator) Encrypt(data []byte) []byte {
	aesGCM, err := cipher.NewGCMWithNonceSize(gcm.Block, len(gcm.nonce))
	if err != nil {
		panic(err)
	}

	// 加密数据，并获取密文和消息认证码（TAG）
	ciphertext := aesGCM.Seal(nil, gcm.nonce, data, gcm.additionalData)

	//tagSize := aesGCM.Overhead()
	//tag := ciphertext[len(ciphertext)-tagSize:]
	//fmt.Printf("size：%v\n", tagSize)
	//fmt.Printf("密文: %s\n", base64.StdEncoding.EncodeToString(ciphertext[:len(ciphertext)-tagSize]))
	//fmt.Printf("确认码: %s;size:%v\n", base64.StdEncoding.EncodeToString(tag), len(tag))
	return ciphertext
}

func (gcm *GCMActuator) Decrypt(data []byte) []byte {
	aesGCM, err := cipher.NewGCMWithNonceSize(gcm.Block, len(gcm.nonce))
	if err != nil {
		panic(err)
	}

	// 加密数据，并获取密文和消息认证码（TAG）
	ciphertext, _ := aesGCM.Open(nil, gcm.nonce, data, gcm.additionalData)

	return ciphertext
}
