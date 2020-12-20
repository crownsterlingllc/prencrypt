package kfrag

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/hongyuefan/prencrypt/curvebn"
	"github.com/hongyuefan/prencrypt/point"
	"github.com/hongyuefan/prencrypt/util"
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
	byt = append(byt, byte(len(kf.Id.Bytes())))
	byt = append(byt, kf.Id.Bytes()...)

	byt = append(byt, byte(len(kf.Rk.Bytes())))
	byt = append(byt, kf.Rk.Bytes()...)

	byt = append(byt, byte(len(kf.Z1.Bytes())))
	byt = append(byt, kf.Z1.Bytes()...)

	byt = append(byt, byte(len(kf.U.Marshal())))
	byt = append(byt, kf.U.Marshal()...)

	byt = append(byt, byte(len(kf.XA.Marshal())))
	byt = append(byt, kf.XA.Marshal()...)

	byt = append(byt, byte(len(kf.Z2.Bytes())))
	byt = append(byt, kf.Z2.Bytes()...)

	return byt
}

func (kf *KFrag) Unmarshal(data []byte) error {

	idLen := int(data[:1][0])
	idByt := data[1:idLen+1]
	kf.Id = curvebn.NewCurveBN(idByt)

	rkLen := int(data[1+idLen : 2+idLen][0])
	rkByt := data[2+idLen : 2+idLen+rkLen]
	kf.Rk = curvebn.NewCurveBN(rkByt)

	z1Len := int(data[2+idLen+rkLen : 3+idLen+rkLen][0])
	z1Byt := data[3+idLen+rkLen : 3+idLen+rkLen+z1Len]
	kf.Z1 = curvebn.NewCurveBN(z1Byt)

	uLen := int(data[3+idLen+rkLen+z1Len : 4+idLen+rkLen+z1Len][0])
	uByt := data[4+idLen+rkLen+z1Len : 4+idLen+rkLen+z1Len+uLen]
	u := point.NewPoint()
	if err := u.Unmarshal(uByt); err != nil {
		return err
	}
	kf.U = u

	xaLen := int(data[4+idLen+rkLen+z1Len+uLen : 5+idLen+rkLen+z1Len+uLen][0])
	xaByt := data[5+idLen+rkLen+z1Len+uLen : 5+idLen+rkLen+z1Len+uLen+xaLen]
	xa := point.NewPoint()
	if err := xa.Unmarshal(xaByt); err != nil {
		return err
	}
	kf.XA = xa

	z2Len := int(data[5+idLen+rkLen+z1Len+uLen+xaLen : 6+idLen+rkLen+z1Len+uLen+xaLen][0])
	z2Byt := data[6+idLen+rkLen+z1Len+uLen+xaLen : 6+idLen+rkLen+z1Len+uLen+xaLen+z2Len]
	kf.Z2 = new(big.Int).SetBytes(z2Byt)

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
