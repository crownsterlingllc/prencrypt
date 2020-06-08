package prencrypt

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/hongyuefan/prencrypt/cfrag"
	"github.com/hongyuefan/prencrypt/keys"
	"github.com/hongyuefan/prencrypt/symcrypt"
	"github.com/stretchr/testify/assert"
)

var (
	N = 7
	T = 5
)

func oneceOp() error {

	plainTextAlice := []byte("hello world")

	privAlice, _ := keys.GenerateKey()
	privBob, _ := keys.GenerateKey()

	// alice generate sharekey
	shareKeyAlice, capsule, err := Encapsulate(privAlice.PublicKey)
	if err != nil {
		return err
	}

	//fmt.Println(string(shareKeyAlice), len(shareKeyAlice))

	// alice use sharekey symcrypt plainText
	cipherText, err := symcrypt.EncryptAes(shareKeyAlice, plainTextAlice)
	if err != nil {
		return err
	}

	// alice authrize for bob，shamir secret share scheme
	kFrags, err := KfragsGen(privAlice, privBob.PublicKey, N, T)
	if err != nil {
		return err
	}

	var cFrags []*cfrag.CFrag

	for i := 0; i < T; i++ {
		//reencrypt capsule
		cfrg, err := ReEncapsulate(kFrags[i], capsule, nil)
		if err != nil {
			return err
		}

		bytCfrag := cfrg.Marshal()
		cfrg = cfrag.NewCFrag()
		err = cfrg.Unmarshal(bytCfrag)
		if err != nil {
			return err
		}

		cFrags = append(cFrags, cfrg)
	}

	//bob use his privatekey decapsule sharekey
	shareKeyBob, err := DecapsulateFrags(privBob, privAlice.PublicKey, cFrags)
	if err != nil {
		return err
	}

	//bob use sharekey decrypt ciphertext
	plainTextBob, err := symcrypt.DecryptAes(shareKeyBob, cipherText)
	if err != nil {
		return err
	}

	//compare plaintext
	if !bytes.Equal(plainTextAlice, plainTextBob) {
		return fmt.Errorf("plainText is not equal")
	}

	return nil
}

func TestBench(t *testing.T) {
	if !assert.NoError(t, oneceOp()) {
		return
	}
}
