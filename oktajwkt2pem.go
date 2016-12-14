package main

import (
	"fmt"
	"net/http"
	//"os"
	"io/ioutil"
	"encoding/json"
	"encoding/base64"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"log"
	"os"
)

var OktaKeys struct {
	Keys []struct {
		Alg string `json:"alg"`
		E   string `json:"e"`
		N   string `json:"n"`
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Use string `json:"use"`
	} `json:"keys"`
}

func main() {

	if len(os.Args) == 2 {

		url := os.Args[1]+"/oauth2/v1/keys"
		//url := "https://companyx.okta.com/oauth2/v1/keys"

		req, _ := http.NewRequest("GET", url, nil)

		req.Header.Add("accept", "application/json")
		req.Header.Add("content-type", "application/json")
		req.Header.Add("cache-control", "no-cache")

		res, _ := http.DefaultClient.Do(req)

		defer res.Body.Close()
		body, _ := ioutil.ReadAll(res.Body)

		json.Unmarshal([]byte (body), &OktaKeys)

		nb, err := base64.RawURLEncoding.DecodeString(OktaKeys.Keys[0].N)
		if err != nil {
			log.Fatal(err)
		}

		e := 0
		// The default exponent is usually 65537, so just compare the
		// base64 for [1,0,1] or [0,1,0,1]
		if OktaKeys.Keys[0].E == "AQAB" || OktaKeys.Keys[0].E == "AAEAAQ" {
			e = 65537
		} else {
			// need to decode "e" as a big-endian int
			log.Fatal("need to deocde e:", OktaKeys.Keys[0].E)
		}

		pk := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: e,
		}

		der, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			log.Fatal(err)
		}

		block := &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: der,
		}

		var out bytes.Buffer
		pem.Encode(&out, block)
		fmt.Println(out.String())

	} else {
		fmt.Fprintln(os.Stderr, "Usage: okwjwk2pem https://oktaorg.okta.com")

	}

}


