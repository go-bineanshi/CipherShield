package padding

import "bytes"

func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func PKCS7UnPadding(origData []byte) []byte {
	padding := int(origData[len(origData)-1])
	return origData[:len(origData)-padding]
}
