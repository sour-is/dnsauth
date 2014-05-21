package main

import (
    "fmt"
	"encoding/base64"
	"github.com/docopt/docopt.go"
	"github.com/sour-is/dnsauth/auth"
	"os"
    "io/ioutil"	
    "net/http"
    "strings"
   	"net"
   		"log"
)

var APP_NAME string = "DNS-EC Authenticate Web"
var APP_USAGE string = `DNE-EC Authenticate Web
Copyright (c) 2014, Jon Lundy <jon@xuu.cc> 1NvmHfSjPq1UB9scXFhYDLkihnu9nkQ8xg

Usage:
  web [-v] [TCPPORT]`

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
	port := ":8080"
	if args["TCPPORT"] != nil {
		port = args["TCPPORT"].(string)
	}

    http.HandleFunc("/auth/", handler)
    http.ListenAndServe(port, nil)
}

func handler(w http.ResponseWriter, r *http.Request) {

	ident := r.URL.Path[6:]
	pub := ""

    txt, _ := net.LookupTXT(ident)
    for _, t := range txt { 
		pub = auth.TXTValue(t, "pubkey")

		if pub != "" {
			break
		}
	}

	if pub == "" {
		fmt.Fprintf(w, `{"ident": "%s","auth": "err","msg":"No key found."}`, ident)
	}

	if pass := r.PostFormValue("pass"); pass != "" {
		_, chk := auth.GenTXT(ident, pass)

		ok := pub == encode(chk)
		if !ok {
			w.WriteHeader(403)
		}

		INFO.Println("AuthPass:",ident, ok)
		fmt.Fprintf(w, `{"ident": "%s", "auth": %t}`, ident, ok)

	} else if sig := r.PostFormValue("sig"); sig != "" {
		INFO.Println("PubKey:", pub)
		INFO.Println("Signature:", sig)

		ok := auth.Verify(decode(pub), decode(sig))
		if !ok {
			w.WriteHeader(403)
		} 

		INFO.Println("AuthSig:",ident, ok)
		fmt.Fprintf(w, `{"ident": "%s", "auth": %t}`, ident, ok)
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