// Copyright 2020 Thomas L. Kula
// All Rights Reserved
//
// Use of this source code is governed by the license included
// in the LICENSE file

package main

import (
    "crypto/ecdsa"
    "crypto/x509"
    "encoding/hex"
    "encoding/pem"
    "errors"
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

    // serialize that for PKCS11

    // Some HSMs expect you to include the DER-encoded public key
    // as the paramter to NewECDH1DeriveParams. I believe SoftHSM2
    // is one of them. Currently not handled

    // Others expect you to simply send the bytes of the X and Y
    // points on the curve that represent the public key, after a
    // flag which tells the HSM if the points are uncompressed.
    // I handle that case.

    xString := fmt.Sprintf("%064s", fmt.Sprintf("%x", publicKey.X))
    yString := fmt.Sprintf("%064s", fmt.Sprintf("%x", publicKey.Y))

    publicKeyString := fmt.Sprintf("04%s%s", // '04' means uncompressed
	xString,
	yString)
    publicKeyData, err := hex.DecodeString(publicKeyString)
    if err != nil {
	return "", "", err
    }
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

    ageSecretKey, err := sharedSecretObj.Value()
    if err != nil {
	return "", "", err
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

func main() {

    modulePath, ok := os.LookupEnv("AGE_PKCS11_MODULE")
    if ! ok {
	panic("Must define AGE_PKCS11_MODULE")
    }

    slotString := os.Getenv("AGE_PKCS11_SLOT")
    slotNum, tokenNum, err := decode_slot(slotString)
    if err != nil {
	panic(err)
    }

    fmt.Print("User PIN: ")
    bytePin, err := terminal.ReadPassword(syscall.Stdin)
    if err != nil {
	panic(err)
    }
    fmt.Print("\n")

    pinString := string(bytePin)
    pinString = strings.TrimSpace(pinString)

    handlePemFile, ok := os.LookupEnv("AGE_PKCS11_HANDLE_FILE")
    if ! ok {
	panic(errors.New("Must define AGE_PKCS11_HANDLE_FILE"))
    }

    ageSecretKeyString, agePublicKeyString, err := age_pkcs11(modulePath, slotNum, tokenNum, pinString, handlePemFile)
    if err != nil {
	panic(err)
    }

    fmt.Printf("%s\n%s\n", ageSecretKeyString, agePublicKeyString)
}
