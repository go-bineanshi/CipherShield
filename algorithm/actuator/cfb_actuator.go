package actuator

import "crypto/cipher"

type CFBActuator struct {
	Block cipher.Block
	iv    []byte
}

func (cfb *CFBActuator) SetBlock(block cipher.Block, options ...ActuatorOption) {
	opts := &ActuatorOptions{}
	for _, option := range options {
		option(opts)
	}
	cfb.Block = block
	cfb.iv = opts.IV
}

func (cfb *CFBActuator) Encrypt(data []byte) []byte {
	cipher.NewCFBEncrypter(cfb.Block, cfb.iv).XORKeyStream(data, data)
	return data
}

func (cfb *CFBActuator) Decrypt(data []byte) []byte {
	cipher.NewCFBDecrypter(cfb.Block, cfb.iv).XORKeyStream(data, data)
	return data
}
