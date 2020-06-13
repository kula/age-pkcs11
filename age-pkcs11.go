// Copyright 2020 Thomas L. Kula
// All Rights Reserved
//
// Use of this source code is governed by the license included
// in the LICENSE file

package main

import (
    "encoding/binary"
    "errors"
    "fmt"
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

    session, err := slots[0].OpenSession()
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

    // Ensure derivation mechanism is supported by token

    // Derive EC key

    // And extract the value from the returned ephemeral key

}
