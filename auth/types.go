package auth

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
)

type PrivateKey ecdsa.PrivateKey
type PublicKey ecdsa.PublicKey

type Signature struct {
	R, S *big.Int
	H    []byte
}

func (s Signature) Bytes() (b []byte) {
	b = make([]byte, 69)
	b[0] = 0x20
	copy(b[1:33], s.S.Bytes())
	copy(b[33:65], s.R.Bytes())
	copy(b[65:], s.H)

	return
}
func (s *Signature) SetBytes(b []byte) (err error) {
	if len(b) != 69 {
		return errors.New("Signature.SetBytes: invalid input length")
	}
	if b[0] != 0x20 {
		return errors.New("Signature.SetBytes: invalid input type")
	}

	s.S = new(big.Int).SetBytes(b[1:33])
	s.R = new(big.Int).SetBytes(b[33:65])
	s.H = b[65:]

	return nil
}
func (sig Signature) String() string {
	return Encode(sig.Bytes())
}
func (sig *Signature) SetString(s string) error {
	return sig.SetBytes(Decode(s))
}

func (p PrivateKey) Bytes() (b []byte) {
	b = make([]byte, 33)
	b[0] = 0x80
	copy(b[1:], p.D.Bytes())

	return
}
func (p *PrivateKey) SetBytes(c elliptic.Curve, b []byte) (err error) {
	if len(b) != 33 {
		return errors.New("PrivateKey.SetBytes: invalid input length")
	}
	if b[0] != 0x80 {
		return errors.New("PrivateKey.SetBytes: invalid input type")
	}

	p.Curve = c
	p.D = new(big.Int).SetBytes(b[1:33])
	p.X, p.Y = p.ScalarBaseMult(b[1:33])

	return nil
}
func (p PrivateKey) String() string {
	return Encode(p.Bytes())
}
func (p *PrivateKey) SetString(c elliptic.Curve, s string) error {
	return p.SetBytes(c, Decode(s))
}
func (p PrivateKey) Public() (pub PublicKey) {
	pub.X, pub.Y, pub.Curve = p.X, p.Y, p.Curve
	return
}

// Generate takes two byte strings to generate an ecdsa private key.
func (p *PrivateKey) Generate(c elliptic.Curve, user, pass []byte) (err error) {
	d, err := scrypt.Key(pass, user, 16384, 8, 8, 32)
	if err != nil {
		return
	}

	p.Curve = c
	p.D = new(big.Int).SetBytes(d)
	p.X, p.Y = p.ScalarBaseMult(d)

	return
}
func (p PublicKey) Bytes() (b []byte) {
	b = make([]byte, 65)
	b[0] = 0x04
	copy(b[1:], p.X.Bytes())
	copy(b[33:], p.Y.Bytes())

	return
}
func (s *PublicKey) SetBytes(c elliptic.Curve, b []byte) (err error) {
	if len(b) != 65 {
		return errors.New("PublicKey.SetBytes: invalid input length")
	}
	if b[0] != 0x04 {
		return errors.New("PublicKey.SetBytes: invalid input type")
	}

	s.Curve = c
	s.X = new(big.Int).SetBytes(b[1:33])
	s.Y = new(big.Int).SetBytes(b[33:65])

	return nil
}
func (p PublicKey) String() string {
	return Encode(p.Bytes())
}
func (p *PublicKey) SetString(c elliptic.Curve, s string) error {
	return p.SetBytes(c, Decode(s))
}
