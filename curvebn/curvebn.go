package curvebn

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"prencrypt/point"
	"prencrypt/util"
)

var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

type CurveBN struct {
	Curve elliptic.Curve
	P     []byte
}

func NewCurveBN(p []byte) *CurveBN {
	return &CurveBN{
		Curve: util.Curve,
		P:     p,
	}
}

func (c *CurveBN) Len() int {
	N := c.Curve.Params().N
	bitSize := N.BitLen()
	return (bitSize + 7) >> 3
}

func (c *CurveBN) FromBytes(data []byte) error {
	if len(data) != c.Len() {
		return errors.New("curveBN data length error")
	}
	c.P = data
	return nil
}

func (c *CurveBN) Bytes() []byte {
	return c.P
}

func (c *CurveBN) Int() *big.Int {
	return new(big.Int).SetBytes(c.P)
}

func (c *CurveBN) String() string {
	return c.Int().String()
}

func (c *CurveBN) Convert2CanInverseCurvBN() *CurveBN {
	c.P = new(big.Int).Add(big.NewInt(1), new(big.Int).Mod(new(big.Int).SetBytes(c.P), new(big.Int).Sub(c.Curve.Params().N, big.NewInt(1)))).Bytes()
	return c
}

func (c *CurveBN) InverseModCurvBN() *big.Int {
	return new(big.Int).ModInverse(new(big.Int).SetBytes(c.P), c.Curve.Params().N)
}

func PointsHash2CurvBN(points ...*point.Point) (*CurveBN, error) {
	var byt []byte
	for _, point := range points {
		byt = append(byt, point.Marshal()...)
	}

	hash, err := util.Hash_class(byt)
	if err != nil {
		return nil, err
	}
	p, err := generateDByHash(util.Curve, hash)
	if err != nil {
		return nil, err
	}
	return &CurveBN{Curve: util.Curve, P: p}, nil
}

func BytesHash2CurvBN(byts []byte) (*CurveBN, error) {
	hash, err := util.Hash_class(byts)
	if err != nil {
		return nil, err
	}
	p, err := generateDByHash(util.Curve, hash)
	if err != nil {
		return nil, err
	}
	return &CurveBN{Curve: util.Curve, P: p}, nil
}

func generateDByHash(curve elliptic.Curve, hash []byte) ([]byte, error) {
	N := curve.Params().N
	bitSize := N.BitLen()
	byteLen := (bitSize + 7) >> 3

	if len(hash) != byteLen {
		return nil, errors.New("length error")
	}
	hash[0] &= mask[bitSize%8]

	hash[1] ^= 0x42

	if new(big.Int).SetBytes(hash).Cmp(N) >= 0 {
		return nil, errors.New("out of range")
	}
	return hash, nil
}
