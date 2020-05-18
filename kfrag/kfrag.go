package kfrag

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"prencrypt/curvebn"
	"prencrypt/point"
	"prencrypt/util"
)

type KFrag struct {
	Id, Rk, Z1 *curvebn.CurveBN
	U, XA      *point.Point
	Z2         *big.Int
}

func NewKFrag() *KFrag {
	return &KFrag{
		Id: curvebn.NewCurveBN(nil),
		Rk: curvebn.NewCurveBN(nil),
		Z1: curvebn.NewCurveBN(nil),
		U:  point.NewPoint(),
		XA: point.NewPoint(),
		Z2: big.NewInt(0),
	}
}

func (kf *KFrag) Marshal() []byte {
	var byt []byte
	byt = append(byt, kf.Id.Bytes()...)
	byt = append(byt, kf.Rk.Bytes()...)
	byt = append(byt, kf.Z1.Bytes()...)
	byt = append(byt, kf.U.Marshal()...)
	byt = append(byt, kf.XA.Marshal()...)
	byt = append(byt, kf.Z2.Bytes()...)
	return byt
}

func (kf *KFrag) Unmarshal(data []byte) error {
	bnLen := curvebn.NewCurveBN(nil).Len()
	ptLen := point.NewPoint().Len()
	if len(data) < bnLen*3+ptLen*2 {
		return errors.New("kfrag data len error")
	}
	kf.Id = curvebn.NewCurveBN(data[:bnLen])
	kf.Rk = curvebn.NewCurveBN(data[bnLen : bnLen*2])
	kf.Z1 = curvebn.NewCurveBN(data[bnLen*2 : bnLen*3])
	u := point.NewPoint()
	if err := u.Unmarshal(data[bnLen*3 : bnLen*3+ptLen]); err != nil {
		return err
	}
	kf.U = u
	xa := point.NewPoint()
	if err := xa.Unmarshal(data[bnLen*3+ptLen : bnLen*3+ptLen*2]); err != nil {
		return err
	}
	kf.XA = xa
	kf.Z2 = new(big.Int).SetBytes(data[bnLen*3+ptLen*2:])
	return nil
}

func (kf *KFrag) Hex() string {
	return hex.EncodeToString(kf.Marshal())
}

func (kf *KFrag) FromHex(s string) error {
	data, err := util.HexToBytes(s)
	if err != nil {
		return err
	}
	return kf.Unmarshal(data)
}

func (kf *KFrag) String() string {
	if kf.Rk == nil || kf.Z1 == nil || kf.Z2 == nil || kf.U == nil || kf.XA == nil {
		return ""
	}
	return fmt.Sprintf("Id:%v,Rk:%v,Z1:%v,Z2:%v,U:%v,XA:%v", kf.Id, kf.Rk.String(), kf.Z1.String(), kf.Z2.String(), kf.U.Marshal(), kf.XA.Marshal())
}
