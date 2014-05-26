package dnsauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
)

func TXTValue(tag, key string) string {
	for tag != "" {
		// skip leading space
		i := 0
		for i < len(tag) && tag[i] == ' ' {
			i++
		}
		tag = tag[i:]
		if tag == "" {
			break
		}

		// scan to colon.
		// a space or a quote is a syntax error
		i = 0
		for i < len(tag) && tag[i] != ' ' && tag[i] != ':' && tag[i] != '"' {
			i++
		}

		if i+1 >= len(tag) || tag[i] != ':' || tag[i+1] != '"' {
			// Non quoted value ends at the next space.

			name := string(tag[:i])
			tag = tag[i+1:]

			i = 1
			for i < len(tag) && tag[i] != ' ' {
				i++
			}

			value := tag[:i]
			if key == name {
				return value
			}
		} else {
			name := string(tag[:i])
			tag = tag[i+1:]

			// scan quoted string to find value
			i = 1
			for i < len(tag) && tag[i] != '"' {
				if tag[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(tag) {
				break
			}
			qvalue := string(tag[:i+1])
			tag = tag[i+1:]

			if key == name {
				value, _ := strconv.Unquote(qvalue)
				return value
			}
		}
	}
	return ""
}

func Encode(in []byte) (out string) {
	out = base64.URLEncoding.EncodeToString(in)
	out = strings.TrimRight(out, "=")
	return
}
func Decode(in string) (out []byte) {
	if m := len(in) % 4; m != 0 {
		in += strings.Repeat("=", 4-m)
	}
	out, _ = base64.URLEncoding.DecodeString(in)
	return
}
func Hash256(in []byte) []byte {
	s1 := sha256.New()
	s2 := sha256.New()

	s1.Write(in)
	s2.Write(s1.Sum(nil))

	return s2.Sum(nil)
}
