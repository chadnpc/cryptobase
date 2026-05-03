# Post-Quantum Cryptography (PQC)

Post-Quantum Cryptography refers to cryptographic algorithms (usually public-key algorithms) that are thought to be secure against an attack by a quantum computer. `CryptoBase` provides wrappers and stubs for the latest NIST-standardized algorithms.

## Supported Algorithms

### ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
Standardized as FIPS 203 (formerly Kyber). Used for establishing a shared secret between two parties.

#### Usage
```powershell
$kem = [MLKem]::new()

# Generate a new keypair
$keys = $kem.GenerateKeyPair()
# $keys.PublicKey
# $keys.PrivateKey

# Alice encapsulates a secret for Bob
$enc = $kem.Encapsulate($keys.PublicKey)
# $enc.SharedSecret (the secret Alice now has)
# $enc.Ciphertext   (the encrypted secret to send to Bob)

# Bob decapsulates the secret using his private key
$bobSecret = $kem.Decapsulate($enc.Ciphertext, $keys.PrivateKey)
```

---

### ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
Standardized as FIPS 204 (formerly Dilithium). Used for digital signatures.

#### Usage
```powershell
$dsa = [MLDsa]::new()

# Generate a new keypair
$keys = $dsa.GenerateKeyPair()

# Sign a message
$message = [System.Text.Encoding]::UTF8.GetBytes("Critical PQC data")
$signature = $dsa.Sign($message, $keys.PrivateKey)

# Verify
$isValid = $dsa.Verify($message, $signature, $keys.PublicKey)
```

---

### SLH-DSA (Stateless Hash-based Digital Signature Algorithm)
Standardized as FIPS 205 (formerly SPHINCS+). A digital signature algorithm based on hash functions.

## Implementation Note

> **IMPORTANT**: These algorithms are currently implemented as **stubs** or **wrappers** for future .NET features. In current .NET versions, they use secure placeholders (like HMAC-SHA256) for functional testing, but should not be relied upon for actual quantum resistance until the environment supports the native FIPS standards.
