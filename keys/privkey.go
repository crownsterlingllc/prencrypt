package keys

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/hongyuefan/prencrypt/curvebn"
	"github.com/hongyuefan/prencrypt/point"
	"github.com/hongyuefan/prencrypt/util"
)

type PrivateKey struct {
	Bnkey     *curvebn.CurveBN
	PublicKey *PublicKey
}

func GenerateKey() (*PrivateKey, error) {
	p, x, y, err := elliptic.GenerateKey(util.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key pair: %v", err)
	}
	return &PrivateKey{
		PublicKey: &PublicKey{
			Point: &point.Point{
				Curve: util.Curve,
				X:     x,
				Y:     y,
			},
		},
		Bnkey: &curvebn.CurveBN{
			Curve: util.Curve,
			P:     p,
		},
	}, nil
}

func NewPrivateKeyFromHex(s string) (*PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("cannot decode hex string: %v", err)
	}
	return NewPrivateKeyFromBytes(b), nil
}

// NewPrivateKeyFromBytes decodes private key raw bytes, computes public key and returns PrivateKey instance
func NewPrivateKeyFromBytes(priv []byte) *PrivateKey {
	x, y := util.Curve.ScalarBaseMult(priv)

	return &PrivateKey{
		PublicKey: &PublicKey{
			Point: &point.Point{
				Curve: util.Curve,
				X:     x,
				Y:     y,
			},
		},
		Bnkey: &curvebn.CurveBN{
			Curve: util.Curve,
			P:     priv,
		},
	}
}

// Bytes returns private key raw bytes
func (k *PrivateKey) Bytes() []byte {
	return k.Bnkey.P
}

// Hex returns private key bytes in hex form
func (k *PrivateKey) Hex() string {
	return hex.EncodeToString(k.Bytes())
}

func (k *PrivateKey) Int() *big.Int {
	return new(big.Int).SetBytes(k.Bnkey.P)
}

func (k *PrivateKey) Mul(u *big.Int) *big.Int {
	return new(big.Int).Mul(k.Int(), u)
}

func (k *PrivateKey) Add(u *big.Int) *big.Int {
	return new(big.Int).Add(k.Int(), u)
}
