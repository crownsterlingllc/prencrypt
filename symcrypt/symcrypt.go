package symcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func EncryptAes(secretKey, msg []byte) ([]byte, error) {

	var ct bytes.Buffer

	// AES encryption
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %v", err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: %v", err)
	}

	ct.Write(nonce)

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, fmt.Errorf("cannot create aes gcm: %v", err)
	}
	ciphertext := aesgcm.Seal(nil, nonce, msg, nil)
	tag := ciphertext[len(ciphertext)-aesgcm.NonceSize():]
	ct.Write(tag)
	ciphertext = ciphertext[:len(ciphertext)-len(tag)]
	ct.Write(ciphertext)
	return ct.Bytes(), nil
}

func DecryptAes(secretKey, msg []byte) ([]byte, error) {
	// Message cannot be less than length of public key (65) + nonce (16) + tag (16)
	if len(msg) <= (16 + 16) {
		return nil, fmt.Errorf("invalid length of message")
	}

	// AES decryption part
	nonce := msg[:16]
	tag := msg[16:32]

	// Create Golang-accepted ciphertext
	ciphertext := bytes.Join([][]byte{msg[32:], tag}, nil)

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %v", err)
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, fmt.Errorf("cannot create gcm cipher: %v", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt ciphertext: %v", err)
	}

	return plaintext, nil
}
