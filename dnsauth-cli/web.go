package main

import (
	"fmt"
	"github.com/sour-is/dnsauth/dnsauth"
	"github.com/sour-is/koblitz/kelliptic"
	"net"
	"net/http"
)

func web() {
	port := ":8080"
	if args["TCPPORT"] != nil {
		port = args["TCPPORT"].(string)
	}

	INFO.Println("Listen and Serve on port", port)

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
		pub = dnsauth.TXTValue(t, "pubkey")
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

	p := new(dnsauth.PublicKey)
	err := p.SetString(s256, pub)
	if err != nil {
		ERROR.Println(err)
		w.WriteHeader(400)
		fmt.Fprintf(w, `{"ident": "%s","auth": "err","msg":"Invalid Public Key."}`, ident)
		return
	}

	ok := false

	if pass := r.PostFormValue("pass"); pass != "" {

		c := dnsauth.Hash256([]byte(pass))
		INFO.Printf("Pass: %s\n", dnsauth.Encode(c))

		chk := new(dnsauth.PrivateKey)
		err := chk.Generate(s256, []byte(ident), c)
		if err != nil {
			ERROR.Println(err)
			w.WriteHeader(403)
			fmt.Fprintf(w, `{"ident": "%s","auth": "err","msg":"Invalid Input."}`, ident)
			return
		}

		INFO.Println("Pub:", chk.Public())

		ok = pub == dnsauth.Encode(chk.Public().Bytes())

	} else if sha := r.PostFormValue("sha"); sha != "" {

		INFO.Printf("Pass: %x\n", dnsauth.Decode(sha))

		chk := new(dnsauth.PrivateKey)
		err := chk.Generate(s256, []byte(ident), dnsauth.Decode(sha))
		if err != nil {
			ERROR.Println(err)
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"ident": "%s","auth": "err","msg":"Invalid Input."}`, ident)
			return
		}

		INFO.Println("Signature:", chk.Public())

		ok = pub == dnsauth.Encode(chk.Public().Bytes())

	} else if sig := r.PostFormValue("sig"); sig != "" {

		s := new(dnsauth.Signature)
		s.SetString(sig)
		INFO.Println("Signature:", sig)

		if err != nil {
			ERROR.Println(err)
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"ident": "%s","auth": "err","msg":"Invalid Input."}`, ident)
			return
		}

		ok = dnsauth.Verify(p, s)
	}
	if !ok {
		w.WriteHeader(403)
	}

	INFO.Println("AuthPass:", ident, ok)
	fmt.Fprintf(w, `{"ident": "%s", "auth": %t}`, ident, ok)

}
