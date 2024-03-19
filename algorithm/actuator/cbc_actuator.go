package actuator

import "crypto/cipher"

type CBCActuator struct {
	Block cipher.Block
	iv    []byte
}

func (cbc *CBCActuator) SetBlock(block cipher.Block, options ...ActuatorOption) {
	opts := &ActuatorOptions{}
	for _, option := range options {
		option(opts)
	}
	cbc.Block = block
	cbc.iv = opts.IV
}

func (cbc *CBCActuator) Encrypt(data []byte) []byte {
	cipher.NewCBCEncrypter(cbc.Block, cbc.iv).CryptBlocks(data, data)
	return data
}
func (cbc *CBCActuator) Decrypt(data []byte) []byte {
	cipher.NewCBCDecrypter(cbc.Block, cbc.iv).CryptBlocks(data, data)
	return data
}
