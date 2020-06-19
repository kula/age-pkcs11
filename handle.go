// Copyright 2020 Thomas L. Kula
// All Rights Reserved
//
// Use of this source code is governed by the license included
// in the LICENSE file

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// Generate a new ECHD public key and write it as a PEM encoded
// file at `filename`, for use as a key "handle"
func writeNewHandle(handlePath string) error {
	pemBytes, err := newHandle()
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(handlePath, *pemBytes, 0600)
	if err != nil {
		return err
	}

	return nil
}

// Generate a new ECDSA public key and output the PEM-encoded
// representaton of it as a byte string
func newHandle() (*[]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	pemBytes := pem.EncodeToMemory(block)
	return &pemBytes, nil
}
