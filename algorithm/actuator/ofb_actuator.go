package actuator

import "crypto/cipher"

type OFBActuator struct {
	Block cipher.Block
	iv    []byte
}

func (ofb *OFBActuator) SetBlock(block cipher.Block, options ...ActuatorOption) {
	opts := &ActuatorOptions{}
	for _, option := range options {
		option(opts)
	}
	ofb.Block = block
	ofb.iv = opts.IV
}

func (ofb *OFBActuator) Encrypt(data []byte) []byte {
	cipher.NewOFB(ofb.Block, ofb.iv).XORKeyStream(data, data)
	return data
}

func (ofb *OFBActuator) Decrypt(data []byte) []byte {
	cipher.NewOFB(ofb.Block, ofb.iv).XORKeyStream(data, data)
	return data
}
