package prencrypt

import (
	"errors"
	"math/big"

	"prencrypt/capsule"
	"prencrypt/cfrag"
	"prencrypt/curvebn"
	"prencrypt/keys"
	"prencrypt/kfrag"
	"prencrypt/point"
	"prencrypt/util"
)

func Encapsulate(alicePub *keys.PublicKey) ([]byte, *capsule.Capsule, error) {
	if alicePub == nil {
		return nil, nil, errors.New("publickey is nil")
	}
	priv_r, err := keys.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	priv_u, err := keys.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	h, err := curvebn.PointsHash2CurvBN(priv_r.PublicKey.Point, priv_u.PublicKey.Point)
	if err != nil {
		return nil, nil, err
	}

	s := priv_u.Add(priv_r.Mul(h.Int()))

	sharedKey, err := alicePub.Point.Mul(priv_r.Add(priv_u.Int())).KDF()
	if err != nil {
		return nil, nil, err
	}
	return sharedKey, &capsule.Capsule{E: priv_r.PublicKey.Point, V: priv_u.PublicKey.Point, S: s}, nil
}

func DecapsulateOriginal(alicePriv *keys.PrivateKey, capsule *capsule.Capsule) ([]byte, error) {
	if !capsule.Verify() {
		return nil, errors.New("capsule verification failed")
	}
	return capsule.E.Add(capsule.V).Mul(alicePriv.Int()).KDF()
}

func KfragsGen(privAlice *keys.PrivateKey, bobPub *keys.PublicKey, N, t int) ([]*kfrag.KFrag, error) {
	return kfrag.Rkgen(privAlice, bobPub, N, t)
}

func ReEncapsulate(kfrag *kfrag.KFrag, capsule *capsule.Capsule, aux []byte) (*cfrag.CFrag, error) {
	if kfrag == nil || capsule == nil {
		return nil, errors.New("params is nil")
	}
	if !capsule.Verify() {
		return nil, errors.New("capsule verification failed")
	}
	cfrg := new(cfrag.CFrag)
	cfrg.E1 = capsule.E.Mul(kfrag.Rk.Int())
	cfrg.V1 = capsule.V.Mul(kfrag.Rk.Int())
	cfrg.Id = kfrag.Id
	cfrg.XA = kfrag.XA

	t, err := keys.GenerateKey()
	if err != nil {
		return nil, err
	}

	E2 := capsule.E.Mul(t.Int())
	V2 := capsule.V.Mul(t.Int())
	U2 := point.UPoint().Mul(t.Int())

	h, err := curvebn.BytesHash2CurvBN(util.AppendByt(capsule.E.Marshal(), cfrg.E1.Marshal(), E2.Marshal(), capsule.V.Marshal(), cfrg.V1.Marshal(), V2.Marshal(), point.UPoint().Marshal(), kfrag.U.Marshal(), U2.Marshal(), aux))
	if err != nil {
		return nil, err
	}
	cfrg.Pi = &cfrag.Proof{
		E2:  E2,
		V2:  V2,
		U2:  U2,
		U1:  kfrag.U,
		Z1:  kfrag.Z1,
		Z2:  kfrag.Z2,
		Rol: new(big.Int).Add(t.Int(), new(big.Int).Mul(h.Int(), kfrag.Rk.Int())),
		Aux: aux,
	}
	if !cfrg.Verify(capsule.E, capsule.V) {
		return nil, errors.New("cfrag verify failed")
	}
	return cfrg, nil
}

func DecapsulateFrags(privBob *keys.PrivateKey, pubAlice *keys.PublicKey, cfrags []*cfrag.CFrag) ([]byte, error) {

	if privBob == nil || pubAlice == nil || len(cfrags) < 1 {
		return nil, errors.New("params not right")
	}

	pXA := cfrags[0].XA

	D, err := curvebn.PointsHash2CurvBN(pubAlice.Point, privBob.PublicKey.Point, pubAlice.Point.Mul(privBob.Int()))
	if err != nil {
		return nil, err
	}

	var S []*big.Int
	for _, cfrag := range cfrags {
		s, err := curvebn.BytesHash2CurvBN(util.AppendByt(cfrag.Id.Bytes(), D.P))
		if err != nil {
			return nil, err
		}
		S = append(S, s.Int())
	}

	var e_summands []*point.Point
	var v_summands []*point.Point

	for index := range S {
		numerator, denominator, err := util.LambdaS(index, S)
		if err != nil {
			return nil, err
		}
		lambS := new(big.Int).Mul(numerator, new(big.Int).ModInverse(denominator, util.Curve.Params().N))
		e_summands = append(e_summands, cfrags[index].E1.Mul(lambS))
		v_summands = append(v_summands, cfrags[index].V1.Mul(lambS))
	}

	E := e_summands[0]
	V := v_summands[0]
	for index := 1; index < len(cfrags); index++ {
		E = E.Add(e_summands[index])
		V = V.Add(v_summands[index])
	}

	d, err := curvebn.PointsHash2CurvBN(pXA, privBob.PublicKey.Point, pXA.Mul(privBob.Int()))
	if err != nil {
		return nil, err
	}

	return E.Add(V).Mul(d.Convert2CanInverseCurvBN().Int()).KDF()
}
