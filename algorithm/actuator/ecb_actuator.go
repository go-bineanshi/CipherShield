package actuator

import "crypto/cipher"

type ECBActuator struct {
	Block cipher.Block
}

func (ecb *ECBActuator) SetBlock(block cipher.Block, options ...ActuatorOption) {
	opts := &ActuatorOptions{}
	for _, option := range options {
		option(opts)
	}
	ecb.Block = block
}

func (ecb *ECBActuator) Encrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	ecb.Block.Encrypt(encrypted, data)
	return encrypted
}
func (ecb *ECBActuator) Decrypt(data []byte) []byte {
	decrypted := make([]byte, len(data))

	ecb.Block.Decrypt(decrypted, data)
	return decrypted
}
