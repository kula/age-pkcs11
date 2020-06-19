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
    "fmt"
    "io/ioutil"

    "github.com/miekg/pkcs11"
    "github.com/miekg/pkcs11/p11"
    "github.com/kula/age-pkcs11/bech32"

    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/hkdf"
)


const contextString = "age-encryption.org/v1:pkcs11v1"

// Return private key string, public key string, error
func age_pkcs11(modulePath string, slotNum, tokenNum int, pinString, handlePemFile string) (string, string, error) {
    supportedCurve := elliptic.P256()

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

    // Verify it's a P-256 public key - one joint, keep it well
    // oiled
    if publicKey.Curve != supportedCurve {
	return "", "", fmt.Errorf("Must be a %s curve", supportedCurve.Params().Name)
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
    sharedSecretBytes, err := privKey.Derive(*deriveMechanism, deriveAttributes)
    if err != nil {
	return "", "", err
    }

    // Expand those bytes using an HKDF


    stretchedSecretBytes := hkdf.New(sha256.New, sharedSecretBytes, []byte{}, []byte(contextString))

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
