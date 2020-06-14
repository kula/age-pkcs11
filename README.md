# age-encryption.org with PKCS11 Tokens

**NOTE** Half-baked at this point. The key generation is complete, but
needs to be turned into something operationally useful, and the actual
using of the key needs to be done still.

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
