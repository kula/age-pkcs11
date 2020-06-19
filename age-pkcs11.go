// Copyright 2020 Thomas L. Kula
// All Rights Reserved
//
// Use of this source code is governed by the license included
// in the LICENSE file

package main

import (
    "errors"
    "flag"
    "fmt"
    "os"
    "strings"
    "syscall"

    "golang.org/x/crypto/ssh/terminal"

)

const usage = `Usage:
    age-pkcs11 -i [-m MODULE] [-s SLOT:TOKEN] [-h HANDLE] [-o OUTPUT]
    age-pkcs11 -r [-m MODULE] [-s SLOT:TOKEN] [-h HANDLE] [-o OUTPUT]
    age-pkcs11 --new-handle [-f HANDLE]

Derive an age encryption key via ECDH given a PKCS11 token with an
elliptic curve private key and a handle file HANDLE with an elliptic
curve public key. Or, generate a new file suitable for use as a handle.

Options:
    -i, --private   Output private half of age key
    -r, --public    Output public half of age key
    --new-handle    Generate a new handle
    -m, --module    Path to token PKCS11 module
    -s, --slot      Set in the form 'SLOT:TOKEN' to specify the 
                    PKCS11 slot and token numbers used. Defaults
		    to '0:0'
    -f, --handle    Path to 'handle' file
    -o, --output    Path to output file

OUTPUT defaults to standard output.

You can also set the following environment variables
    AGE_PKCS11_MODULE	     Path to MODULE
    AGE_PKCS11_SLOT          Slot and token number
    AGE_PKCS11_USER_PIN      If not set, will be prompted for PIN
    AGE_PKCS11_HANDLE_FILE   Path to HANDLE
`

func main() {
    var ok bool

    var modulePath, slotString, handlePath, outputPath string
    var showPrivate, showPublic, newHandle bool

    flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

    flag.StringVar(&modulePath, "module", "", "path to module")
    flag.StringVar(&modulePath, "m", "", "path to module")
    flag.StringVar(&slotString, "slot", "", "SLOT:TOKEN")
    flag.StringVar(&slotString, "s", "", "SLOT:TOKEN")
    flag.StringVar(&handlePath, "handle", "", "path to handle file")
    flag.StringVar(&handlePath, "f", "", "path to handle file")
    flag.BoolVar(&showPrivate, "private", false, "show private key")
    flag.BoolVar(&showPrivate, "i", false, "show private key")
    flag.BoolVar(&showPublic, "public", false, "show public key")
    flag.BoolVar(&showPublic, "r", false, "show public key")
    flag.StringVar(&outputPath, "output", "", "output to `FILE` (default stdout)")
    flag.StringVar(&outputPath, "o", "", "output to `FILE` (default stdout)")
    flag.BoolVar(&newHandle, "new-handle", false, "generate a new handle file")
    flag.Parse()

    if newHandle {
	if showPrivate || showPublic {
	    fmt.Fprintf(os.Stderr, "%s\n\n", usage)
	    fmt.Fprintf(os.Stderr, "Error: specify only one of --private, --public or --new-handle\n")
	    os.Exit(1)
	}

	do_newHandle(handlePath)
    }

    if (showPrivate && showPublic) || ( showPrivate == false && showPublic == false) {
	fmt.Fprintf(os.Stderr, "%s\n\n", usage)
	fmt.Fprintf(os.Stderr, "Error: Please specify one of --private or --public\n")
	os.Exit(1)
    }

    if modulePath == "" {
	modulePath, ok = os.LookupEnv("AGE_PKCS11_MODULE")
	if ! ok {
	    fmt.Fprintf(os.Stderr, "%s\n", usage)
	    panic("Must specify path to PKCS11 module")
	}
    }

    if slotString == "" {
	slotString, ok = os.LookupEnv("AGE_PKCS11_SLOT")
	if ! ok {
	    fmt.Fprintf(os.Stderr, "%s\n", usage)
	    panic("Must define slot and token number")
	}
    }

    slotNum, tokenNum, err := decode_slot(slotString)
    if err != nil {
	fmt.Fprintf(os.Stderr, "%s\n", usage)
	panic(err)
    }

    var outputFile *os.File
    if outputPath == "" {
	outputFile = os.Stdout
    } else {
	outputFile, err = os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
	    panic(err)
	}
	defer outputFile.Close()
    }

    var pinString string
    pinString, ok = os.LookupEnv("AGE_PKCS11_USER_PIN")
    if ! ok {
	fmt.Print("User PIN: ")
	pinBytes, err := terminal.ReadPassword(syscall.Stdin)
	fmt.Print("\n")
	if err != nil {
	    fmt.Fprintf(os.Stderr, "%s\n", usage)
	    panic(err)
	}
	pinString = string(pinBytes)
    }

    pinString = strings.TrimSpace(pinString)

    if handlePath == "" {
	handlePath, ok = os.LookupEnv("AGE_PKCS11_HANDLE_FILE")
	if ! ok {
	    fmt.Fprintf(os.Stderr, "%s\n", usage)
	    panic(errors.New("Must define AGE_PKCS11_HANDLE_FILE"))
	}
    }

    ageSecretKeyString, agePublicKeyString, err := age_pkcs11(modulePath, slotNum, tokenNum, pinString, handlePath)
    if err != nil {
	panic(err)
    }

    if showPrivate {
	fmt.Fprintf(outputFile, "%s\n", ageSecretKeyString)
    } else if showPublic {
	fmt.Fprintf(outputFile, "%s\n", agePublicKeyString)
    }
}
