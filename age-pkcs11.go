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
    "strconv"
    "strings"
    "syscall"

    "golang.org/x/crypto/ssh/terminal"

    "github.com/kula/pkcs11"
    "github.com/kula/pkcs11/p11"
    "github.com/kula/age-pkcs11/bech32"

    "golang.org/x/crypto/curve25519"
)

// Given a string like "slot#:token#", return slot and
// token. Both default to 0. Return error if passed something
// not a number
func decode_slot(s string) (int, int, error) {
    if len(s) == 0 {
	// Return defaults
	return 0, 0, nil
    }

    var sliceString, tokenString string
    sSlice := strings.Split(s, ":")
    switch len(sSlice) {
    case 1:
	sliceString = sSlice[0]
	tokenString = "0"
    case 2:
	sliceString = sSlice[0]
	tokenString = sSlice[1]
    default:
	return 0,0 , errors.New("bad slot string")
    }

    slice, err := strconv.Atoi(sliceString)
    if err != nil {
	return 0,0 , fmt.Errorf("Bad slot value: %s", slice)
    }

    token, err := strconv.Atoi(tokenString)
    if err != nil {
	return 0, 0, fmt.Errorf("Bad token value: %s", slice)
    }

    if slice < 0 {
	return 0, 0, fmt.Errorf("Slice cannot be less than 0")
    }

    if token < 0 {
	return 0, 0, fmt.Errorf("Token cannot be less than 0")
    }

    return slice, token, nil
}

func main() {

    modulePath, ok := os.LookupEnv("AGE_PKCS11_MODULE")
    if ! ok {
	panic("Must define AGE_PKCS11_MODULE")
    }

    module, err := p11.OpenModule(modulePath)
    if err != nil {
	panic(err)
    }

    slots, err := module.Slots()
    if err != nil {
	panic(err)
    }

    slotString := os.Getenv("AGE_PKCS11_SLOT")
    optSlotNum, optTokenNum, err := decode_slot(slotString)
    if err != nil {
	panic(err)
    }

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
    idBytes,err := itoba(optTokenNum)
    if err != nil {
	panic(err)
    }

    object, err := session.FindObject([]*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes),
    })

    privKey := p11.PrivateKey(object)
    if err != nil {
	panic(err)
    }

    // Build derivation mechanism

    optMechanism := pkcs11.CKM_ECDH1_DERIVE
    optHandlePemFile, ok := os.LookupEnv("AGE_PKCS11_HANDLE_FILE")
    if ! ok {
	panic(errors.New("Must define AGE_PKCS11_HANDLE_FILE"))
    }

    pemData, err := ioutil.ReadFile(optHandlePemFile)
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

    publicKeyIn, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
    if err != nil {
	panic(err)
    }

    publicKey, ok := publicKeyIn.(*ecdsa.PublicKey)
    if ! ok {
	panic("Not an ECDSA public key")
    }
    // serialize that for PKCS11

    // Some HSMs expect you to include the DER-encoded public key
    // as the paramter to NewECDH1DeriveParams. I believe SoftHSM2
    // is one of them.

    // Others expect you to simply send the bytes of the X and Y
    // points on the curve that represent the public key, after a
    // flag which tells the HSM if the points are uncompressed.

    xString := fmt.Sprintf("%064s", fmt.Sprintf("%x", publicKey.X))
    yString := fmt.Sprintf("%064s", fmt.Sprintf("%x", publicKey.Y))

    publicKeyString := fmt.Sprintf("04%s%s", // '04' means uncompressed
	xString,
	yString)
    publicKeyData, err := hex.DecodeString(publicKeyString)
    if err != nil {
	panic(err)
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
	fmt.Printf("While calling privKey.Derive\n")
	panic(err)
    }

    // And extract the value from the returned ephemeral key

    ageSecretKey, err := sharedSecretObj.Value()
    if err != nil {
	panic(err)
    }

    // Convert and format as age Curve25519 keys

    agePublicKey, err := curve25519.X25519(ageSecretKey, curve25519.Basepoint)
    if err != nil {
	panic(err)
    }

    ageSecretKeyString, err := bech32.Encode("AGE-SECRET-KEY-", ageSecretKey)
    if err != nil {
	panic(err)
    }

    agePublicKeyString, err := bech32.Encode("age", agePublicKey)
    if err != nil {
	panic(err)
    }

    fmt.Printf("%s\n%s\n", ageSecretKeyString, agePublicKeyString)
}
