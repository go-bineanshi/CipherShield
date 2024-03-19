package algorithm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"github.com/go-bineanshi/CipherShield/algorithm/actuator"
	"github.com/go-bineanshi/CipherShield/padding"
	"github.com/go-bineanshi/CipherShield/pkg"
	"strings"
	"sync"
)

// 单例
var once sync.Once
var _aesAlgorithmInstance *AESAlgorithm
var _aesAlgorithmError error

type AESAlgorithm struct {
	iv    []byte
	block cipher.Block

	// 填充
	padding func([]byte, int) []byte
	// 模式
	actuator actuator.Actuator

	additionalData []byte
}

type AESActuatorOptions struct {
	actuator       actuator.Actuator
	additionalData []byte
}

type AESActuatorOption func(*AESActuatorOptions)

func WithAESActuator(actuatorName string) AESActuatorOption {
	return func(options *AESActuatorOptions) {
		switch strings.ToUpper(actuatorName) {
		case "ECB":
			options.actuator = &actuator.ECBActuator{}
		case "CBC":
			options.actuator = &actuator.CBCActuator{}
		case "OFB":
			options.actuator = &actuator.OFBActuator{}
		case "CFB":
			options.actuator = &actuator.CFBActuator{}
		case "CTR":
			options.actuator = &actuator.CTRActuator{}
		case "GCM":
			options.actuator = &actuator.GCMActuator{}
		}
	}
}

func WithAESAdditionalData(data []byte) AESActuatorOption {
	return func(options *AESActuatorOptions) {
		options.additionalData = data
	}
}

// NewAESAlgorithm 构建AES算法
func NewAESAlgorithm(key, iv []byte, options ...AESActuatorOption) (*AESAlgorithm, error) {
	if _aesAlgorithmInstance == nil {
		once.Do(
			func() {

				block, err := aes.NewCipher(key)
				if err != nil {
					_aesAlgorithmError = err
					return
				}

				//if len(iv) != 0 && len(iv) != aes.BlockSize {
				//	_aesAlgorithmError = errors.New("crypto/aes: invalid iv size")
				//}

				opts := &AESActuatorOptions{
					actuator: &actuator.CBCActuator{},
				}
				for _, option := range options {
					option(opts)
				}

				_aesAlgorithmInstance = &AESAlgorithm{
					block:          block,
					iv:             iv,
					actuator:       opts.actuator,
					additionalData: opts.additionalData,
				}
			},
		)
	}

	return _aesAlgorithmInstance, _aesAlgorithmError
}

// Encrypt 加密
func (a *AESAlgorithm) Encrypt(plaintext []byte) (string, error) {
	// 填充
	plaintext = padding.PKCS7Padding(plaintext, aes.BlockSize)

	// 随机生成IV
	iv := a.iv
	if len(a.iv) == 0 {
		iv = []byte(pkg.RandStr(16))
	}

	// 加密
	var options []actuator.ActuatorOption
	if len(iv) != 0 {
		options = append(options, actuator.WithIVOption(iv))
	}
	if len(a.additionalData) != 0 {
		options = append(options, actuator.WithAdditionalDataOption(a.additionalData))
	}

	a.actuator.SetBlock(a.block, options...)
	ciphertext := a.actuator.Encrypt(plaintext)

	// 随机 IV 和 加密文本一起返回
	if len(a.iv) == 0 {
		ciphertext = append(iv, ciphertext...)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 解密
func (a *AESAlgorithm) Decrypt(ciphertext string) (string, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// 从加密文本中获取随机 IV
	iv := a.iv
	if len(a.iv) == 0 {
		iv = cipherBytes[:aes.BlockSize]
		cipherBytes = cipherBytes[aes.BlockSize:]
	}

	// 解码
	var options []actuator.ActuatorOption
	if len(iv) != 0 {
		options = append(options, actuator.WithIVOption(iv))
	}
	if len(a.additionalData) != 0 {
		options = append(options, actuator.WithAdditionalDataOption(a.additionalData))
	}
	a.actuator.SetBlock(a.block, options...)
	plaintext := a.actuator.Decrypt(cipherBytes)
	plaintext = padding.PKCS7UnPadding(plaintext)
	return string(plaintext), nil
}
