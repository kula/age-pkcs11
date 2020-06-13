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

    "github.com/miekg/pkcs11"
)

func main() {
    p:= pkcs11.New("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")
    err := p.Initialize()
    if err != nil {
	panic(err)
    }

    defer p.Destroy()
    defer p.Finalize()

    slots, err := p.GetSlotList(true)
    if err != nil {
	panic(err)
    }

    session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
    if err != nil {
	panic(err)
    }

    defer p.CloseSession(session)

    fmt.Print("User PIN: ")
    bytePin, err := terminal.ReadPassword(syscall.Stdin)
    if err != nil {
	panic(err)
    }
    fmt.Print("\n")

    pin := string(bytePin)
    pin = strings.TrimSpace(pin)

    err = p.Login(session, pkcs11.CKU_USER, pin)
    if err != nil {
	panic(err)
    }

    defer p.Logout(session)


}
