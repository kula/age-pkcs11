// Copyright 2020 Thomas L. Kula
// All Rights Reserved
//
// Use of this source code is governed by the license included
// in the LICENSE file

package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/x509"
    "crypto/rand"
    "encoding/pem"
    "io/ioutil"
    "os"

)

// Generate a new ECHD public key and write it as a PEM encoded
// file at `filename`, for use as a key "handle"
func do_newHandle(handlePath string) {
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
	panic(err)
    }

    der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
    if err != nil {
	panic(err)
    }

    block := &pem.Block{
	Type: "PUBLIC KEY",
	Bytes: der,
    }

    pemBytes := pem.EncodeToMemory(block)
    err = ioutil.WriteFile(handlePath, pemBytes, 0600)
    if err != nil {
	panic(err)
    }
    os.Exit(0)
}
