# Elliptic Curve Cryptography (ECC)

`CryptoBase` provides support for several elliptic curves, including those used in Bitcoin/Ethereum and NIST standards.

## Supported Curves

- **Secp256k1**: Used by Bitcoin, Ethereum, and many other cryptocurrencies.
- **Curve25519 / X25519**: Optimized for Diffie-Hellman key exchange.
- **Ed25519**: Optimized for digital signatures (see [Ed25519.md](./Ed25519.md)).
- **NIST P-256 / P-384 / P-521**: Standard NIST curves.

---

## Secp256k1

### Usage
```powershell
# Generate a new keypair
$kp = [Secp256k1]::GenerateKeyPair()
# $kp.PublicKey
# $kp.PrivateKey

# Sign data
$data = [System.Text.Encoding]::UTF8.GetBytes("Blockchain data")
$sig = [Secp256k1]::Sign($data, $kp.PrivateKey)

# Verify
$isValid = [Secp256k1]::Verify($data, $sig, $kp.PublicKey)
```

---

## Curve25519 (Diffie-Hellman)

Used for securely establishing a shared secret over an insecure channel.

### Usage
```powershell
# Alice generates keys
$aliceKeys = [Curve25519]::GenerateKeyPair()

# Bob generates keys
$bobKeys = [Curve25519]::GenerateKeyPair()

# Alice derives shared secret using Bob's public key
$aliceSecret = [Curve25519]::DeriveSharedSecret($aliceKeys.PrivateKey, $bobKeys.PublicKey)

# Bob derives shared secret using Alice's public key
$bobSecret = [Curve25519]::DeriveSharedSecret($bobKeys.PrivateKey, $aliceKeys.PublicKey)

# $aliceSecret should be equal to $bobSecret
```

---

## General ECDSA

Support for arbitrary curves via the `[Ecdsa]` class.

### Usage
```powershell
# Generate P-384 keys
$kp = [Ecdsa]::GenerateKeyPair('nistP384')
```
