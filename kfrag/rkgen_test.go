package kfrag

import (
	"testing"

	"prencrypt/keys"

	"github.com/stretchr/testify/assert"
)

func TestRkgen(t *testing.T) {

	privAlice, _ := keys.GenerateKey()
	privBob, _ := keys.GenerateKey()

	kFrags, err := Rkgen(privAlice, privBob.PublicKey, 5, 3)
	if !assert.NoError(t, err) {
		return
	}

	for _, kfrag := range kFrags {
		tKfrag := NewKFrag()
		tKfrag.FromHex(kfrag.Hex())
		assert.Equal(t, tKfrag.Hex(), kfrag.Hex())
	}
}
