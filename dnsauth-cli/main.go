package main

import (
	"github.com/docopt/docopt.go"
	"io/ioutil"
	"log"
	"os"
)

var APP_NAME string = "DNS-EC Authenticate"
var APP_USAGE string = `DNE-EC Authenticate
Copyright (c) 2014, Jon Lundy <jon@xuu.cc> 1AtgpfWRcvb7bnB9Vgns68DbdB6XfoL9yU

Usage:
  dnsauth-cli [-v] gentxt USER PASS
  dnsauth-cli [-v] sign   USER PASS [NONCE]
  dnsauth-cli [-v] verify USER SIG [PUB]
  dnsauth-cli [-v] web    [TCPPORT]`

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
	if args["web"] == true {
		web()
	} else {
		generate()
	}
}
