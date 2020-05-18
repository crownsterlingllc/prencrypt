package point

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"math/big"

	"prencrypt/util"
)

type Point struct {
	Curve elliptic.Curve
	X     *big.Int
	Y     *big.Int
}

func NewPoint() *Point {
	return &Point{
		Curve: util.Curve,
		X:     big.NewInt(0),
		Y:     big.NewInt(0),
	}
}

func (p *Point) Mul(m *big.Int) *Point {
	x, y := p.Curve.ScalarMult(p.X, p.Y, m.Bytes())
	return &Point{
		Curve: p.Curve,
		X:     x,
		Y:     y,
	}
}

func (p *Point) Add(u *Point) *Point {
	x, y := p.Curve.Add(p.X, p.Y, u.X, u.Y)
	return &Point{
		Curve: p.Curve,
		X:     x,
		Y:     y,
	}
}

func (p *Point) KDF() (key []byte, err error) {
	var secret bytes.Buffer
	l := len(p.Curve.Params().P.Bytes())
	secret.Write(util.ZeroPad(p.X.Bytes(), l))
	secret.Write(util.ZeroPad(p.Y.Bytes(), l))
	return util.Kdf(secret.Bytes())
}

// Marshal converts a point into the uncompressed form specified in section 4.3.6 of ANSI X9.62.
func (p *Point) Marshal() []byte {
	byteLen := (p.Curve.Params().BitSize + 7) >> 3

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	xBytes := p.X.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	yBytes := p.Y.Bytes()
	copy(ret[1+2*byteLen-len(yBytes):], yBytes)
	return ret
}

func (p *Point) Len() int {
	byteLen := (p.Curve.Params().BitSize + 7) >> 3
	return 1 + 2*byteLen
}

// Unmarshal converts a point, serialized by Marshal, into an x, y pair.
// It is an error if the point is not in uncompressed form or is not on the curve.
// On error, x = nil.
func (p *Point) Unmarshal(data []byte) error {
	byteLen := (p.Curve.Params().BitSize + 7) >> 3
	if len(data) != 1+2*byteLen {
		return errors.New("point data length error")
	}
	if data[0] != 4 { // uncompressed form
		return errors.New("data uncompressed form")
	}
	pBig := p.Curve.Params().P
	p.X = new(big.Int).SetBytes(data[1 : 1+byteLen])
	p.Y = new(big.Int).SetBytes(data[1+byteLen:])
	if p.X.Cmp(pBig) >= 0 || p.Y.Cmp(pBig) >= 0 {
		return errors.New("x/y too big")
	}
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return errors.New("x,y is not on the curve")
	}
	return nil
}

func (p *Point) IsEqual(u *Point) bool {
	if u == nil {
		return false
	}
	if 0 == p.X.Cmp(u.X) && 0 == p.Y.Cmp(u.Y) {
		return true
	}
	return false
}

func UPoint() *Point {
	byt, _ := hex.DecodeString("04fd69424254b879cecca99180f42aa9687b2d33fb3c4824c18f88ceaaff637cb145fdf0f656e0028f0918f4faefe38e8b01f686f5b31f9665b9c8876ec4787767")
	uP := NewPoint()
	uP.Unmarshal(byt)
	return uP
}
