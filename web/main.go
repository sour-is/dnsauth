package main

import (
	"fmt"
	"github.com/docopt/docopt.go"
	"github.com/sour-is/dnsauth/auth"
	"github.com/sour-is/koblitz/kelliptic"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
)

var APP_NAME string = "DNS-EC Authenticate Web"
var APP_USAGE string = `DNE-EC Authenticate Web
Copyright (c) 2014, Jon Lundy <jon@xuu.cc> 1NvmHfSjPq1UB9scXFhYDLkihnu9nkQ8xg

Usage:
  web [-v] [TCPPORT]`

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
	port := ":8080"
	if args["TCPPORT"] != nil {
		port = args["TCPPORT"].(string)
	}

	http.HandleFunc("/auth/", handler)
	http.ListenAndServe(port, nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
	s256 := kelliptic.S256()

	ident := r.URL.Path[6:]
	INFO.Println("Ident:", ident)

	pub := ""
	txt, _ := net.LookupTXT(ident)
	for _, t := range txt {
		pub = auth.TXTValue(t, "pubkey")
		if pub != "" {
			break
		}
	}
	if pub == "" {
		ERROR.Println("No Public Key found.")
		w.WriteHeader(400)
		fmt.Fprintf(w, `{"ident": "%s","auth": "err","msg":"No key found."}`, ident)
		return
	}
	INFO.Println("PubKey:", pub)

	p := new(auth.PublicKey)
	err := p.SetString(s256, pub)
	if err != nil {
		ERROR.Println(err)
		w.WriteHeader(400)
		fmt.Fprintf(w, `{"ident": "%s","auth": "err","msg":"Invalid Public Key."}`, ident)
		return
	}

	ok := false

	if pass := r.PostFormValue("pass"); pass != "" {

		c := auth.Hash256([]byte(pass))
		INFO.Printf("Pass: %s\n", auth.Encode(c))

		chk := new(auth.PrivateKey)
		err := chk.Generate(s256, []byte(ident), c)
		if err != nil {
			ERROR.Println(err)
			w.WriteHeader(403)
			fmt.Fprintf(w, `{"ident": "%s","auth": "err","msg":"Invalid Input."}`, ident)
			return
		}

		INFO.Println("Pub:", chk.Public())

		ok = pub == auth.Encode(chk.Public().Bytes())

	} else if sha := r.PostFormValue("sha"); sha != "" {

		INFO.Printf("Pass: %x\n", auth.Decode(sha))

		chk := new(auth.PrivateKey)
		err := chk.Generate(s256, []byte(ident), auth.Decode(sha))
		if err != nil {
			ERROR.Println(err)
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"ident": "%s","auth": "err","msg":"Invalid Input."}`, ident)
			return
		}

		INFO.Println("Signature:", chk.Public())

		ok = pub == auth.Encode(chk.Public().Bytes())

	} else if sig := r.PostFormValue("sig"); sig != "" {

		s := new(auth.Signature)
		s.SetString(sig)
		INFO.Println("Signature:", sig)

		if err != nil {
			ERROR.Println(err)
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"ident": "%s","auth": "err","msg":"Invalid Input."}`, ident)
			return
		}

		ok = auth.Verify(p, s)
	}
	if !ok {
		w.WriteHeader(403)
	}

	INFO.Println("AuthPass:", ident, ok)
	fmt.Fprintf(w, `{"ident": "%s", "auth": %t}`, ident, ok)

}
