// Copyright 2020 Thomas L. Kula
// All Rights Reserved
//
// Use of this source code is governed by the license included
// in the LICENSE file

package main

import (
    "crypto/ecdsa"
    // "crypto/elliptic"
    "crypto/x509"
    "encoding/binary"
    "encoding/pem"
    "errors"
    "fmt"
    "io/ioutil"
    "math"
    "strconv"
    "strings"
    "syscall"

    "golang.org/x/crypto/ssh/terminal"

    "github.com/miekg/pkcs11"
    "github.com/miekg/pkcs11/p11"
)

// Given a string s representing an unsigned integer, return a
// byte array representing the integer
func atoba(s string) ([]byte, error) {
    n, err := strconv.ParseUint(s, 0, 64)
    if err != nil {
	return nil, err
    }

    if n < 0 {
	return nil, errors.New("Cannot have a negative number")
    }

    if n <= math.MaxUint8 {
	b := make([]byte, 1)
	b[0] = byte(n)
	return b, nil
    } else if n <= math.MaxUint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(n))
	return b, nil
    } else if n <= math.MaxUint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(n))
	return b, nil
    } else if n <= math.MaxUint64 {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(n))
	return b, nil
    } else {
	return nil, errors.New("Number too large")
    }
}

func main() {

    module, err := p11.OpenModule("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")
    if err != nil {
	panic(err)
    }

    slots, err := module.Slots()
    if err != nil {
	panic(err)
    }
    optSlotNum := 0
    slot := slots[optSlotNum]

    session, err := slot.OpenSession()
    if err != nil {
	panic(err)
    }

    defer session.Close()

    fmt.Print("User PIN: ")
    bytePin, err := terminal.ReadPassword(syscall.Stdin)
    if err != nil {
	panic(err)
    }
    fmt.Print("\n")

    pin := string(bytePin)
    pin = strings.TrimSpace(pin)

    err = session.Login(pin)
    if err != nil {
	panic(err)
    }

    defer session.Logout()

    // Find the ECDH private key object by id
    id := "1"
    idBytes,err := atoba(id)
    if err != nil {
	panic(err)
    }

    object, err := session.FindObject([]*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes),
    })

    if err != nil {
	panic(err)
    }

    fmt.Printf("%+v\n", object)

    // Build derivation mechanism

    //optMechanism := pkcs11.CKM_ECDH1_DERIVE
    optFileName := "prime256v1-pub.pem"

    pemData, err := ioutil.ReadFile(optFileName)
    if err != nil {
	panic(err)
    }

    pemBlock, _ := pem.Decode(pemData)
    if pemBlock == nil {
	panic("failed to parse PEM block containing the public key")
    }

    if pemBlock.Type != "PUBLIC KEY" {
	panic("Not public key")
    }

    publicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
    if err != nil {
	panic(err)
    }

    switch publicKey.(type) {
    case *ecdsa.PublicKey:
    default:
	panic("Not an ECDSA public key")
    }

    fmt.Printf("%+v\n", publicKey)

    //publicKeyData :=
    //ecdh1Params := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, publicKeyData)

    // So all of the examples for NewMechanism have you passing
    // in directly a pkcs11.CKM constant, which are ints,
    // but the function signature requires uints. :shrug:
    //deriveMechanism := pkcs11.NewMechanism(uint(optMechanism), nil)

    // fmt.Printf("%+v\n", deriveMechanism)

    // Derive EC key

    // And extract the value from the returned ephemeral key

}
