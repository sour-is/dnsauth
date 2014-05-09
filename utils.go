package main

import (
	"crypto/sha256"
	"encoding/base64"
)

func Encode(in []byte) (out string) {
	out = base64.StdEncoding.EncodeToString(in)
	return
}

func Decode(in string) (out []byte, err error) {
	out, err = base64.StdEncoding.DecodeString(in)
	return
}

func Hash256(in []byte) []byte {
	s1 := sha256.New()
	s2 := sha256.New()

	s1.Write(in)
	s2.Write(s1.Sum(nil))

	return s2.Sum(nil)
}
