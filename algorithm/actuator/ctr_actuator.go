package actuator

import "crypto/cipher"

type CTRActuator struct {
	Block cipher.Block
	iv    []byte
}

func (ctr *CTRActuator) SetBlock(block cipher.Block, options ...ActuatorOption) {
	opts := &ActuatorOptions{}
	for _, option := range options {
		option(opts)
	}
	ctr.Block = block
	ctr.iv = opts.IV
}

func (ctr *CTRActuator) Encrypt(data []byte) []byte {
	cipher.NewCTR(ctr.Block, ctr.iv).XORKeyStream(data, data)
	return data
}

func (ctr *CTRActuator) Decrypt(data []byte) []byte {
	cipher.NewCTR(ctr.Block, ctr.iv).XORKeyStream(data, data)
	return data
}
