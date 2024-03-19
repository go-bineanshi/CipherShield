package actuator

import "crypto/cipher"

type Actuator interface {
	SetBlock(block cipher.Block, options ...ActuatorOption)
	Encrypt(data []byte) []byte
	Decrypt(data []byte) []byte
}

type ActuatorOptions struct {
	IV             []byte
	Nonce          []byte
	AdditionalData []byte
}

type ActuatorOption func(options *ActuatorOptions)

func WithIVOption(iv []byte) ActuatorOption {
	return func(options *ActuatorOptions) {
		options.IV = iv
	}
}

func WithAdditionalDataOption(additionalData []byte) ActuatorOption {
	return func(options *ActuatorOptions) {
		options.AdditionalData = additionalData
	}
}
