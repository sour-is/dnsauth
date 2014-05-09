package main

import (
	"fmt"
	"github.com/docopt/docopt.go"
	"os"
    "io/ioutil"
	"log"
	"net"
)

var APP_NAME string = "DNS-EC Authenticate"
var APP_USAGE string = `DNE-EC Authenticate
Copyright (c) 2014, Jon Lundy <jon@xuu.cc> 1NvmHfSjPq1UB9scXFhYDLkihnu9nkQ8xg

Usage:
  dnsauth [-v] sign   USER PASS
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

	if args["sign"] == true {

		user := args["USER"].(string)
		pass := args["PASS"].(string)

		Priv, Pub, Sig := Sign(user, pass)

		INFO.Printf("Private Key: %s\n", Encode(Priv))
		INFO.Printf("Public Key:  %s\n", Encode(Pub))

		fmt.Printf("Sign:   %s\n", Encode(Sig))

	} else if args["verify"] == true {

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
				pub = GetKey(t, "pubkey")

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

		p, _ := Decode(pub)
		s, _ := Decode(sig)
		INFO.Printf("User:   %s\n", user)
		INFO.Printf("PubKey: %x\n", p)
		INFO.Printf("Sig:    %x\n", s)
		
		v := Verify(p, s)
		fmt.Println("Verify:", v)
	}
}
