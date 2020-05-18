package util

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/fomichev/secp256k1"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
)

var Curve elliptic.Curve = secp256k1.SECP256K1()

func HexToBytes(s string) ([]byte, error) {
	s = strings.ToLower(s)
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}
	return hex.DecodeString(s)
}

func AppendByt(byts ...[]byte) []byte {
	var byt []byte
	for _, bt := range byts {
		if bt != nil {
			byt = append(byt, bt...)
		}
	}
	return byt
}

func Hash_class(data []byte) ([]byte, error) {
	hash, err := blake2b.New(32, nil)
	if err != nil {
		return nil, err
	}
	return hash.Sum(data)[:32], nil
}

func ZeroPad(b []byte, leigth int) []byte {
	for i := 0; i < leigth-len(b); i++ {
		b = append([]byte{0x00}, b...)
	}
	return b
}

func Kdf(secret []byte) (key []byte, err error) {
	key = make([]byte, 32)
	kdf := hkdf.New(sha256.New, secret, nil, nil)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("cannot read secret from HKDF reader: %v", err)
	}
	return key, nil
}

func LambdaS(i int, shares []*big.Int) (*big.Int, *big.Int, error) {
	origin := shares[i]
	numerator := big.NewInt(1)
	denominator := big.NewInt(1)
	for k := range shares {
		if k != i {
			current := shares[k]
			negative := big.NewInt(0)
			negative = negative.Mul(current, big.NewInt(-1))
			added := big.NewInt(0)
			added = added.Sub(origin, current)

			numerator = numerator.Mul(numerator, negative)
			numerator = numerator.Mod(numerator, Curve.Params().N)

			denominator = denominator.Mul(denominator, added)
			denominator = denominator.Mod(denominator, Curve.Params().N)
		}
	}
	return numerator, denominator, nil
}

/**
 * Evauluates a polynomial with coefficients specified in reverse order:
 * evaluatePolynomial([a, b, c, d], x):
 * 		returns a + bx + cx^2 + dx^3
**/
func EvaluatePolynomial(polynomial []*big.Int, value *big.Int) *big.Int {
	last := len(polynomial) - 1
	var result *big.Int = big.NewInt(0).Set(polynomial[last])
	for s := last - 1; s >= 0; s-- {
		result = result.Mul(result, value)
		result = result.Add(result, polynomial[s])
		result = result.Mod(result, Curve.Params().N)
	}
	return result
}

func CombineXY(shares [][]*big.Int) (*big.Int, error) {
	prime := Curve.Params().N
	secret := big.NewInt(0)
	for i := range shares { // LPI sum loop
		// ...remember the current x and y values...
		origin := shares[i][0]
		originy := shares[i][1]
		numerator := big.NewInt(1)   // LPI numerator
		denominator := big.NewInt(1) // LPI denominator
		for k := range shares {      // LPI product loop
			if k != i {
				current := shares[k][0]
				negative := big.NewInt(0)
				negative = negative.Mul(current, big.NewInt(-1))
				added := big.NewInt(0)
				added = added.Sub(origin, current)

				numerator = numerator.Mul(numerator, negative)
				numerator = numerator.Mod(numerator, prime)

				denominator = denominator.Mul(denominator, added)
				denominator = denominator.Mod(denominator, prime)
			}
		}

		// LPI product
		// ...multiply together the points (y)(numerator)(denominator)^-1...
		working := big.NewInt(0).Set(originy)
		working = working.Mul(working, numerator)
		working = working.Mul(working, new(big.Int).ModInverse(denominator, Curve.Params().N))

		// LPI sum
		secret = secret.Add(secret, working)
		secret = secret.Mod(secret, prime)
	}
	return secret, nil
}
