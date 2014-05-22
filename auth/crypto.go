package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
)

// Sign takes a PrivateKey and optional text to create a Signature
func Sign(P *PrivateKey, hash string) (s Signature, err error) {

	s.H = make([]byte, 4)
	if hash != "" {
		copy(s.H, Hash256([]byte(hash))[:4])
	} else {
		rand.Read(s.H)
	}

	K := new(ecdsa.PrivateKey)
	K.Curve, K.D, K.X, K.Y = P.Curve, P.D, P.X, P.Y

	s.R, s.S, err = ecdsa.Sign(rand.Reader, K, s.H)
	if err != nil {
		return
	}
	return
}

func Verify(P *PublicKey, s *Signature) bool {
	K := new(ecdsa.PublicKey)
	K.Curve, K.X, K.Y = P.Curve, P.X, P.Y

	return ecdsa.Verify(K, s.H, s.R, s.S)
}
