package crowbar

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const aes_key_size = 16

func Enc_test() {
	//basekey := string("0123456789012345")
	//msg := "A quick brown fox jumped over the lazy dog."

	basekey := string("abcdefg")
	msg := "A"

	aeskey := InitKeyAES(basekey)

	encrypted, err := EncryptAES(aeskey, msg)
	if err != nil {
		fmt.Printf("%s", err)
		return
	}

	fmt.Printf("CIPHER KEY: %s(%d)\n", string(aeskey), len(aeskey))
	fmt.Printf("MSG      : %s(%d)\n", string(msg), len(msg))
	fmt.Printf("ENCRYPTED: %s(%d)\n", encrypted, len(encrypted))

	decrypted, err := DecryptAES(aeskey, encrypted)
	if err != nil {
		fmt.Printf("%s", err)
		return
	}

	fmt.Printf("DECRYPTED: %s(%d)\n", decrypted, len(decrypted))
}

func InitKeyAES(basekey string) []byte {
	klen := len(basekey)
	bytes := []byte(basekey)
	key := make([]byte, aes_key_size)

	if klen >= aes_key_size {
		copy(key[:], bytes[:aes_key_size])
	} else {
		// padding key
		copy(key[:], bytes[:])
		var l = aes_key_size - klen

		for i := 0; i < l; i++ {
			key[i+klen] = uint8(i%10) + '0'
		}
	}

	//fmt.Printf("klen=%d, bytes=%s, key=%s(%d) \n", klen, bytes, key, len(key))
	return key
}

func EncryptAES(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.StdEncoding.EncodeToString(cipherText)
	return
}

func DecryptAES(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.StdEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}
