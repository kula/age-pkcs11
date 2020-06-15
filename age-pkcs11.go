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
    "crypto/sha256"
    "encoding/pem"
    "errors"
    "flag"
    "fmt"
    "io/ioutil"
    "os"
    "strings"
    "syscall"

    "golang.org/x/crypto/ssh/terminal"

    "github.com/kula/pkcs11"
    "github.com/kula/pkcs11/p11"
    "github.com/kula/age-pkcs11/bech32"

    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/hkdf"
)

// Return private key string, public key string, error
func age_pkcs11(modulePath string, slotNum, tokenNum int, pinString, handlePemFile string) (string, string, error) {
    module, err := p11.OpenModule(modulePath)
    if err != nil {
	return "", "", err
    }

    slots, err := module.Slots()
    if err != nil {
	return "", "", err
    }

    if slotNum < 0 || slotNum > len(slots) {
	return "", "", errors.New("Slot not found")
    }
    slot := slots[slotNum]

    session, err := slot.OpenSession()
    if err != nil {
	return "", "", err
    }

    defer session.Close()

    err = session.Login(pinString)
    if err != nil {
	return "", "", err
    }

    defer session.Logout()

    // Find the ECDH private key object by id
    idBytes,err := itoba(tokenNum)
    if err != nil {
	return "", "", err
    }

    object, err := session.FindObject([]*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes),
    })

    privKey := p11.PrivateKey(object)
    if err != nil {
	return "", "", err
    }

    // Build derivation mechanism

    optMechanism := pkcs11.CKM_ECDH1_DERIVE

    pemData, err := ioutil.ReadFile(handlePemFile)
    if err != nil {
	return "", "", err
    }

    pemBlock, _ := pem.Decode(pemData)
    if pemBlock == nil {
	return "", "", errors.New("failed to parse PEM block containing the public key")
    }

    if pemBlock.Type != "PUBLIC KEY" {
	return "", "", errors.New("Not public key")
    }

    publicKeyIn, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
    if err != nil {
	return "", "", err
    }

    publicKey, ok := publicKeyIn.(*ecdsa.PublicKey)
    if ! ok {
	return "", "", errors.New("Not an ECDSA public key")
    }

    // serialize that for PKCS11 and add to the ECDH1 parameters

    // This assumes your PKCS11 token wants the parameter to be
    // the public point encoded as per section 4.3.6 of ANSI X9.62.
    // If you have something that expects a DER-encoding, I'd love
    // to hear from you so I can add that support

    publicKeyData := elliptic.Marshal(elliptic.P256(), publicKey.X, publicKey.Y)
    ecdh1Params := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, []byte{}, publicKeyData)

    // So all of the examples for NewMechanism have you passing
    // in directly a pkcs11.CKM constant, which are ints,
    // but the function signature requires uints. :shrug:
    deriveMechanism := pkcs11.NewMechanism(uint(optMechanism), ecdh1Params)
    deriveAttributes := []*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
	pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
	pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
	pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
	pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
    }

    // Derive EC key
    sharedSecretObj, err := privKey.Derive(*deriveMechanism, deriveAttributes)
    if err != nil {
	return "", "", err
    }

    // And extract the value from the returned ephemeral key

    sharedSecretBytes, err := sharedSecretObj.Value()
    if err != nil {
	return "", "", err
    }

    // Expand those bytes using an HKDF

    stretchedSecretBytes := hkdf.New(sha256.New, sharedSecretBytes, []byte{}, []byte{})

    ageSecretKey := make([]byte, 32)
    n, err := stretchedSecretBytes.Read(ageSecretKey)
    if n < 32 {
	return "", "", fmt.Errorf("Read %d bytes from stretched secret key", n)
    }

    // Convert and format as age Curve25519 keys

    agePublicKey, err := curve25519.X25519(ageSecretKey, curve25519.Basepoint)
    if err != nil {
	return "", "", err
    }

    ageSecretKeyString, err := bech32.Encode("AGE-SECRET-KEY-", ageSecretKey)
    if err != nil {
	return "", "", err
    }

    agePublicKeyString, err := bech32.Encode("age", agePublicKey)
    if err != nil {
	return "", "", err
    }

    return ageSecretKeyString, agePublicKeyString, nil
}

const usage = `Usage:
    age-pkcs11 -i [-m MODULE] [-s SLOT:TOKEN] [-h HANDLE] [-o OUTPUT]
    age-pkcs11 -r [-m MODULE] [-s SLOT:TOKEN] [-h HANDLE] [-o OUTPUT]

Derive an age encryption key via ECDH given a PKCS11 token with an
elliptic curve private key and a handle file HANDLE with an elliptic
curve public key.

Options:
    -i, --private   Output private half of age key
    -r, --public    Output public half of age key
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
    var showPrivate, showPublic bool

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
    flag.Parse()

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
