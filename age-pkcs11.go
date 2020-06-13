// Copyright 2020 Thomas L. Kula
// All Rights Reserved
//
// Use of this source code is governed by the license included
// in the LICENSE file

package main

import (
    "fmt"
    "strings"
    "syscall"

    "golang.org/x/crypto/ssh/terminal"

    "github.com/miekg/pkcs11/p11"
)

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

}
