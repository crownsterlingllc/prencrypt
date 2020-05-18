package capsule

import (
	"encoding/hex"
	"errors"
	"math/big"

	"prencrypt/curvebn"
	"prencrypt/keys"
	"prencrypt/point"
	"prencrypt/util"
)

type Capsule struct {
	E *point.Point
	V *point.Point
	S *big.Int
}

func NewCapsule() *Capsule {
	return &Capsule{
		E: point.NewPoint(),
		V: point.NewPoint(),
		S: big.NewInt(0),
	}
}

func (c *Capsule) Verify() bool {
	h, err := curvebn.PointsHash2CurvBN(c.E, c.V)
	if err != nil {
		return false
	}
	point := c.E.Mul(h.Int()).Add(c.V)
	return keys.NewPrivateKeyFromBytes(c.S.Bytes()).PublicKey.Point.IsEqual(point)
}

func (c *Capsule) Marshal() []byte {
	var marshal []byte
	marshal = append(marshal, c.E.Marshal()...)
	marshal = append(marshal, c.V.Marshal()...)
	marshal = append(marshal, c.S.Bytes()...)
	return marshal
}

func (c *Capsule) Unmarshal(data []byte) error {
	pointLen := point.NewPoint().Len()
	if len(data) < pointLen*2 {
		return errors.New("data length error")
	}
	if err := c.E.Unmarshal(data[:pointLen]); err != nil {
		return err
	}
	if err := c.V.Unmarshal(data[pointLen : pointLen*2]); err != nil {
		return err
	}
	c.S = new(big.Int).SetBytes(data[pointLen*2:])

	if !c.Verify() {
		return errors.New("capsule verification failed")
	}
	return nil
}

func (c *Capsule) Hex() string {
	return hex.EncodeToString(c.Marshal())
}

func (c *Capsule) FromHex(s string) error {
	byt, err := util.HexToBytes(s)
	if err != nil {
		return err
	}
	return c.Unmarshal(byt)
}
