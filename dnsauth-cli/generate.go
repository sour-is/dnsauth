package main

import (
	"fmt"
	"github.com/sour-is/dnsauth/dnsauth"
	"github.com/sour-is/koblitz/kelliptic"
	"net"
)

func generate() {
	s256 := kelliptic.S256()

	switch {
	case args["gentxt"] == true:
		user := args["USER"].(string)
		INFO.Printf("User:   %s\n", user)

		pass := args["PASS"].(string)
		sha := dnsauth.Hash256([]byte(pass))
		INFO.Printf("Pass:   %x\n", dnsauth.Encode(sha))

		priv := new(dnsauth.PrivateKey)
		priv.Generate(s256, []byte(user), sha)

		fmt.Printf("Private Key: %x\n", priv.Bytes())
		fmt.Printf("%s. IN TXT \"algo:ecdsa curve:secp256k1 pubkey:%s\"\n", user, priv.Public())

	case args["sign"] == true:
		user := args["USER"].(string)
		INFO.Printf("User:   %s\n", user)

		pass := args["PASS"].(string)
		sha := dnsauth.Hash256([]byte(pass))

		nonce := ""
		if args["NONCE"] != nil {
			nonce = args["NONCE"].(string)
		}

		priv := new(dnsauth.PrivateKey)
		priv.Generate(s256, []byte(user), sha)
		INFO.Printf("Private Key: %s\n", priv)
		INFO.Printf("Public Key: %s\n", priv.Public())

		s, _ := dnsauth.Sign(priv, nonce)
		fmt.Printf("sig=%s\n", s.String())

	case args["verify"] == true:
		user := args["USER"].(string)
		INFO.Printf("User:   %s\n", user)

		pub := ""
		if args["PUB"] != nil {
			INFO.Println("PublicKey was provided.")
			pub = args["PUB"].(string)
		} else {
			INFO.Println("Looking Up:", user)
			txt, _ := net.LookupTXT(user)

			INFO.Println("Received TXT:", txt)
			for _, t := range txt {
				pub = dnsauth.TXTValue(t, "pubkey")

				if pub != "" {
					break
				}
			}
		}
		if pub == "" {
			ERROR.Println("No PublicKey Found!")
			fmt.Println("Verify: err")
			return
		}

		p := new(dnsauth.PublicKey)
		p.SetString(s256, pub)
		INFO.Printf("PubKey: %x\n", p.Bytes())

		sig := args["SIG"].(string)
		s := new(dnsauth.Signature)
		s.SetString(sig)
		INFO.Printf("Sig:    %x\n", s.Bytes())

		v := dnsauth.Verify(p, s)
		fmt.Println("Verify:", v)
	}
}
