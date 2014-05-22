package main

import (
	"fmt"
	"github.com/docopt/docopt.go"
	"github.com/sour-is/dnsauth/auth"
	"github.com/sour-is/koblitz/kelliptic"
	"io/ioutil"
	"log"
	"net"
	"os"
)

var APP_NAME string = "DNS-EC Authenticate"
var APP_USAGE string = `DNE-EC Authenticate
Copyright (c) 2014, Jon Lundy <jon@xuu.cc> 1NvmHfSjPq1UB9scXFhYDLkihnu9nkQ8xg

Usage:
  dnsauth [-v] gentxt USER PASS
  dnsauth [-v] sign   USER PASS [NONCE]
  dnsauth [-v] verify USER SIG [PUB]`

var args map[string]interface{}

var (
	INFO  *log.Logger
	ERROR *log.Logger
)

func init() {
	var err error
	args, err = docopt.Parse(APP_USAGE, nil, true, APP_NAME, false)
	if err != nil {
		panic(err)
	}

	if args["-v"] == true {
		INFO = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
		ERROR = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		INFO = log.New(ioutil.Discard, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
		ERROR = log.New(ioutil.Discard, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	}
}

func main() {
	s256 := kelliptic.S256()

	switch {
	case args["gentxt"] == true:
		user := args["USER"].(string)
		INFO.Printf("User:   %s\n", user)

		pass := args["PASS"].(string)
		sha := auth.Hash256([]byte(pass))
		INFO.Printf("Pass:   %x\n", auth.Encode(sha))

		priv := new(auth.PrivateKey)
		priv.Generate(s256, []byte(user), sha)

		fmt.Printf("Private Key: %x\n", priv.Bytes())
		fmt.Printf("%s. IN TXT \"algo:ecdsa curve:secp256k1 pubkey:%s\"\n", user, priv.Public())

	case args["sign"] == true:
		user := args["USER"].(string)
		INFO.Printf("User:   %s\n", user)

		pass := args["PASS"].(string)
		sha := auth.Hash256([]byte(pass))

		nonce := ""
		if args["NONCE"] != nil {
			nonce = args["NONCE"].(string)
		}

		priv := new(auth.PrivateKey)
		priv.Generate(s256, []byte(user), sha)
		INFO.Printf("Private Key: %s\n", priv)
		INFO.Printf("Public Key: %s\n", priv.Public())

		s, _ := auth.Sign(priv, nonce)
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
				pub = auth.TXTValue(t, "pubkey")

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

		p := new(auth.PublicKey)
		p.SetString(s256, pub)
		INFO.Printf("PubKey: %x\n", p.Bytes())

		sig := args["SIG"].(string)
		s := new(auth.Signature)
		s.SetString(sig)
		INFO.Printf("Sig:    %x\n", s.Bytes())

		v := auth.Verify(p, s)
		fmt.Println("Verify:", v)
	}
}
