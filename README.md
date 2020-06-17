# age-encryption.org with PKCS11 Tokens

## An alternative

[This pull request in rage](https://github.com/str4d/rage/pull/25) (the Rust
implementation of age) provides an alternative, and is what is likely going
to be implemented in age as part of the upcoming age plugin system.

## Caveat

**Use at your own risk, and after your own careful evaluation.**

## Note on building

This assumes you have github.com/miekg/pkcs11 with [this pull request](https://github.com/miekg/pkcs11/pull/128)
applied.

## Usage

```
Usage:
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
    AGE_PKCS11_MODULE        Path to MODULE
    AGE_PKCS11_SLOT          Slot and token number
    AGE_PKCS11_USER_PIN      If not set, will be prompted for PIN
    AGE_PKCS11_HANDLE_FILE   Path to HANDLE
```

Performs an elastic curve Diffie-Hellman exchange to derive a shared
secret, which is used as an `age` Ed25519 private key. You must
supply a 'handle' file, which is a file containing a PEM-encoded
public half of a compatible key; this with the corresponding private
key in your PKCS11 token is used to perform a `CKM_ECDH1_DERIVE`
key derivation.

## Example usage

You will need a PKCS11 token, its pkcs11 module and generally have it
set up to work. Create an elliptic curve key pair on it - here's what
mine looks like on a Smartcard-HSM 4K:

```
Private Key Object; EC
  label:      Test ECDH Key
  ID:         01
  Usage:      sign, derive
Public Key Object; EC  EC_POINT 256 bits
  EC_POINT:   04410415dd1e942b3fea12381b7ab75c14060fe8f80c8bbad6cfea3f071f23aa8e5a7ce77d571117f9dd10d28112fb8bff032f343a73c0e989188d51685f5ccf396408
  EC_PARAMS:  06082a8648ce3d030107
  label:      Test ECDH Key
  ID:         01
  Usage:      verify
```

You will need to know the slot number and token id, be sure to set the
ID when you create the keypair. How you do all of this is highly 
dependent on your PKCS11 token or HSM.

Create a 'handle' file:

```
age-pkcs11 --new-handle -f new-handle.pem
```

This is equivalent to the `openssl` commands:
```
openssl ecparam -name prime256v1 -genkey -noout -out age-key-handle.pem
openssl ec -in age-key-handle.pem -pubout -out age-key-handle.pub.pem
rm age-key-handle.pem   # You no longer need this part
```

While you can use `age-pkcs11` to output the private key to a regular 
file, sending it to a named pipe keeps the key out of persistent storage:

```
mkfifo key-file
```

By using a named pipe, `age-pkcs11` will block until another process
reads from the pipe. So, run either

```
age-pkcs11 -r -o key-file
```

to output the public key, or

```
age-pkcs11 -i -o key-file
```

to output the private key. In another window, run `age` and point it at
`key-file` for either the recipient file or the identify file, as
necessary. In the above examples, the appropriate environment variables
were set, you could do that or supply the correct command line flags.

## TODO

 * Verify the derivation scheme I'm using below cryptographically
   makes sense
 * Verify the HKDF scheme I'm using also makes sense
 * Make more robust in terms of checking that the public key supplied
   matches the private key we're being asked to use for ECDH
 * Find an example test case for a PKCS11 token which requires the
   public key point to be sent as DER-encoded binary bytes
 * Should sample key above only have `derive` and not also `sign`?
 * More robust error handling

## Theory of operation

PKCS11 tokens that can support elliptic curves and implement 
`C_DeriveKey` seem to be somewhat common - I've got both a 
Smartcard-HSM+ and a Nitrokey (which are basically the same thing).
The Smartcard blog describes using an EC key to perform an
elliptic curve Diffie-Hellman exchange to generate a shared 
secret, which can then be used as a key for encryption. 

I'd like to use the [age encryption tool](https://age-encryption.org)
to encrypt material, while storing the key inside of a PKCS11 token.
With this scheme, we're not actually storing the key, but we are
using the key in the token to derive the actual key - encryption/decryption
operations still happen in the `age` binary. But, we can know that 
the ultimate secret is locked inside the PKCS11 token, and the derived
encryption key doesn't have to live outside of memory, which is good
enough for me. 

In this scheme we have to generate an external EC key, although we can
throw away the private part since all we need is the public part. In
effect, the public half of the key becomes an age key "handle"; useless
without the actual PKCS11 token but necessary to derive the shared
secret which can then be turned into an age Ed25519 key. 

The shared secret generated is passed through an HKDF as a sanity scheme.
