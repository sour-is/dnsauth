package main

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/sour-is/koblitz/kelliptic"
	"math/big"
)

func GenKey(user, pass []byte) (K *ecdsa.PrivateKey) {
	d, err := scrypt.Key(pass, Hash256(user), 16384, 8, 8, 32)
	if err != nil {
		panic(err)
	}
	
	K = new(ecdsa.PrivateKey)
	K.Curve = kelliptic.S256()
	K.D = new(big.Int).SetBytes(d)
	K.X, K.Y = K.ScalarBaseMult(d)

	return
}

func Sign(user, pass string) (Priv, Pub, Sig []byte) {

	K := GenKey([]byte(user), []byte(pass))

	H := make([]byte, 4)
	rand.Read(H)

	R, S, err := ecdsa.Sign(rand.Reader, K, H)
	if err != nil {
		panic(err)
	}

	Priv = make([]byte, 33)
	Priv[0] = 0x80
	copy(Priv[1:], K.D.Bytes())

	Pub = make([]byte, 65)
	Pub[0] = 0x04
	copy(Pub[1:], K.X.Bytes())
	copy(Pub[33:], K.Y.Bytes())

	Sig = make([]byte, 69)
	Sig[0] = 0x20
	copy(Sig[1:33], S.Bytes())
	copy(Sig[33:65], R.Bytes())
	copy(Sig[65:], H)

	return
}

func Verify(pub, sig []byte) bool {
	K := new(ecdsa.PublicKey)
	K.Curve = kelliptic.S256()
	K.X = new(big.Int).SetBytes(pub[1:33])
	K.Y = new(big.Int).SetBytes(pub[33:65])

	S := new(big.Int).SetBytes(sig[1:33])
	R := new(big.Int).SetBytes(sig[33:65])

	H := sig[65:]

	return ecdsa.Verify(K, H, R, S)
}
