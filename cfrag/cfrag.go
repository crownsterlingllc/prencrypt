package cfrag

import (
	"errors"
	"math/big"

	"prencrypt/curvebn"
	"prencrypt/point"
	"prencrypt/util"
)

type CFrag struct {
	Id *curvebn.CurveBN
	E1 *point.Point
	V1 *point.Point
	XA *point.Point

	Pi *Proof
}

func NewCFrag() *CFrag {
	return &CFrag{
		Id: curvebn.NewCurveBN(nil),
		E1: point.NewPoint(),
		V1: point.NewPoint(),
		XA: point.NewPoint(),
	}
}

func (c *CFrag) Verify(E, V *point.Point) bool {
	h, err := curvebn.BytesHash2CurvBN(util.AppendByt(E.Marshal(), c.E1.Marshal(), c.Pi.E2.Marshal(), V.Marshal(), c.V1.Marshal(), c.Pi.V2.Marshal(), point.UPoint().Marshal(), c.Pi.U1.Marshal(), c.Pi.U2.Marshal(), c.Pi.Aux))
	if err != nil {
		return false
	}
	if E.Mul(c.Pi.Rol).IsEqual(c.Pi.E2.Add(c.E1.Mul(h.Int()))) && V.Mul(c.Pi.Rol).IsEqual(c.Pi.V2.Add(c.V1.Mul(h.Int()))) && point.UPoint().Mul(c.Pi.Rol).IsEqual(c.Pi.U2.Add(c.Pi.U1.Mul(h.Int()))) {
		return true
	}
	return false
}

func (c *CFrag) Marshal() []byte {
	var marshal []byte
	marshal = append(marshal, c.Id.Bytes()...)
	marshal = append(marshal, c.E1.Marshal()...)
	marshal = append(marshal, c.V1.Marshal()...)
	marshal = append(marshal, c.XA.Marshal()...)
	return marshal
}

func (c *CFrag) Unmarshal(data []byte) error {
	bnLen, pLen := curvebn.NewCurveBN(nil).Len(), point.NewPoint().Len()
	if len(data) < pLen*3+bnLen {
		return errors.New("cfrag data length error")
	}
	if err := c.Id.FromBytes(data[:bnLen]); err != nil {
		return err
	}
	if err := c.E1.Unmarshal(data[bnLen : bnLen+pLen]); err != nil {
		return err
	}
	if err := c.V1.Unmarshal(data[bnLen+pLen : bnLen+pLen*2]); err != nil {
		return err
	}
	if err := c.XA.Unmarshal(data[bnLen+pLen*2 : bnLen+pLen*3]); err != nil {
		return err
	}
	return nil
}

type Proof struct {
	Z1     *curvebn.CurveBN
	Z2     *big.Int
	E2, V2 *point.Point
	U1, U2 *point.Point
	Rol    *big.Int
	Aux    []byte
}
