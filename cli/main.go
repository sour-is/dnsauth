package main

import (
	"fmt"
	"encoding/base64"
	"github.com/docopt/docopt.go"
	"github.com/sour-is/dnsauth/auth"
	"os"
    "io/ioutil"
    "strings"
	"log"
	"net"
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
    INFO    *log.Logger
    ERROR   *log.Logger
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

	switch {
	case args["gentxt"] == true:
		user := args["USER"].(string)
		pass := args["PASS"].(string)
		
		priv, pub := auth.GenTXT(user, pass)

		fmt.Printf("Private Key: %x\n", priv)
		fmt.Printf("%s. IN TXT \"algo:ecdsa curve:secp256k1 pubkey:%s\"\n", user, encode(pub))

	case args["sign"] == true:

		user := args["USER"].(string)
		pass := args["PASS"].(string)
		nonce := ""

		if args["NONCE"] != nil {
			nonce = args["NONCE"].(string)
		}

		Priv, Pub, Sig := auth.Sign(user, pass, nonce)

		INFO.Printf("Private Key: %s\n", encode(Priv))
		INFO.Printf("Public Key: %s\n", encode(Pub))

		fmt.Printf("sig=%s\n", encode(Sig))

	case args["verify"] == true:

		user := args["USER"].(string)
		sig := args["SIG"].(string)
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

		p := decode(pub)
		s := decode(sig)
		INFO.Printf("User:   %s\n", user)
		INFO.Printf("PubKey: %x\n", p)
		INFO.Printf("Sig:    %x\n", s)
		
		v := auth.Verify(p, s)
		fmt.Println("Verify:", v)
	}
}

func encode(in []byte) (out string) {
	out = base64.URLEncoding.EncodeToString(in)
	strings.TrimRight(out, "+")
	return
}
func decode(in string) (out []byte) {
	if m := len(in) % 4; m != 0 {
		in += strings.Repeat("=", 4-m)
	}
	out, _ = base64.URLEncoding.DecodeString(in)
	return
}