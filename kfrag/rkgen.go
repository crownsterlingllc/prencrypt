package kfrag

import (
	"errors"
	"math/big"

	"prencrypt/curvebn"
	"prencrypt/keys"
	"prencrypt/point"
	"prencrypt/util"
)

func Rkgen(privAlice *keys.PrivateKey, bobPub *keys.PublicKey, N, t int) ([]*KFrag, error) {

	if t > N {
		return nil, errors.New("t can not bigger than N")
	}
	if privAlice == nil || bobPub == nil {
		return nil, errors.New("params can not be nil")
	}

	privX, err := keys.GenerateKey()
	if err != nil {
		return nil, err
	}

	d, err := curvebn.PointsHash2CurvBN(privX.PublicKey.Point, bobPub.Point, bobPub.Point.Mul(privX.Int()))
	if err != nil {
		return nil, err
	}

	fn := make([]*big.Int, t)

	fn[0] = new(big.Int).Mul(privAlice.Int(), d.Convert2CanInverseCurvBN().InverseModCurvBN())

	for i := 1; i < t; i++ {
		rands, err := keys.GenerateKey()
		if err != nil {
			return nil, err
		}
		fn[i] = rands.Int()
	}

	D, err := curvebn.PointsHash2CurvBN(privAlice.PublicKey.Point, bobPub.Point, bobPub.Point.Mul(privAlice.Int()))
	if err != nil {
		return nil, err
	}

	kfrags := make([]*KFrag, N)

	for i := 0; i < N; i++ {

		privY, err := keys.GenerateKey()
		if err != nil {
			return nil, err
		}

		privID, err := keys.GenerateKey()
		if err != nil {
			return nil, err
		}
		s, err := curvebn.BytesHash2CurvBN(util.AppendByt(privID.Bytes(), D.P))
		if err != nil {
			return nil, err
		}

		rk := util.EvaluatePolynomial(fn, s.Int())

		u := point.UPoint().Mul(rk)

		z1, err := curvebn.BytesHash2CurvBN(util.AppendByt(privY.PublicKey.Bytes(true), privID.Bytes(), privAlice.PublicKey.Bytes(true), bobPub.Bytes(true), u.Marshal(), privX.PublicKey.Bytes(true)))
		if err != nil {
			return nil, err
		}

		z2 := new(big.Int).Sub(privY.Int(), new(big.Int).Mul(privAlice.Int(), z1.Int()))

		kfrags[i] = &KFrag{
			Id: privID.Bnkey,
			Rk: curvebn.NewCurveBN(rk.Bytes()),
			XA: privX.PublicKey.Point,
			Z1: z1,
			U:  u,
			Z2: z2,
		}
	}

	return kfrags, nil
}
