# Post-Quantum Cryptography (PQC)

Post-Quantum Cryptography refers to cryptographic algorithms (usually public-key algorithms) that are thought to be secure against an attack by a quantum computer. `CryptoBase` provides wrappers and stubs for the latest NIST-standardized algorithms.

## Supported Algorithms

### ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
Standardized as FIPS 203 (formerly Kyber). Used for establishing a shared secret between two parties.

#### Usage
```powershell
$kem = [MLKemCore]::new()

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
$dsa = [MLDsaCore]::new()

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


## API Documentation


## Enums

### MLDsaSecurityLevel
`powershell
enum MLDsaSecurityLevel {
  MLDsa44
  MLDsa65
  MLDsa87
}
``n
## Classes

### MLKemKeyPair

#### Properties

- $type $PublicKey
- $type $PrivateKey
- $type $Level

#### Methods

- `[void] MLKemKeyPair($pub, $priv, $level)`
- `[byte[]] Decapsulate($ciphertext)`

### MLKemEncapsulationResult

#### Properties

- $type $Ciphertext
- $type $SharedSecret

#### Methods

- `[void] MLKemEncapsulationResult($ct, $ss)`

### MLKemCore

#### Methods

- `[void] MLKemCore()`
- `static [bool] IsSupported()`
- `static [MLKemKeyPair] GenerateKeyPair()`
- `static [MLKemKeyPair] GenerateKeyPair($Level)`
- `static [MLKemEncapsulationResult] Encapsulate($PublicKey)`
- `static [byte[]] Decapsulate($Ciphertext, $PrivateKey)`
- `static [MLKemSecurityLevel] GetRecommendedLevel($securityBits)`
- `static [hashtable] GetLevelInfo($level)`

### MLKemBuilder

#### Properties

- $type $_securityLevel
- $type $_publicKey
- $type $_keyPair

#### Methods

- `static [MLKemBuilder] Create()`
- `[MLKemBuilder] WithSecurityLevel($level)`
- `[MLKemBuilder] WithSecurityBits($bits)`
- `[MLKemBuilder] WithPublicKey($publicKey)`
- `[MLKemBuilder] WithKeyPair($keyPair)`
- `[MLKemKeyPair] GenerateKeyPair()`
- `[MLKemEncapsulationResult] Encapsulate()`
- `[byte[]] Decapsulate($ciphertext)`

### MLDsaKeyPair

#### Properties

- $type $PublicKey
- $type $PrivateKey
- $type $Level

#### Methods

- `[void] MLDsaKeyPair($public, $private, $level)`

### MLDsaCore

#### Methods

- `[void] MLDsaCore()`
- `static [MLDsaKeyPair] GenerateKeyPair()`
- `static [MLDsaKeyPair] GenerateKeyPair($level)`
- `static [byte[]] Sign($message, $privateKey)`
- `static [byte[]] Sign($message, $privateKey, $context, $level)`
- `static [bool] Verify($message, $signature, $publicKey)`
- `static [bool] Verify($message, $signature, $publicKey, $context)`
- `static [int] GetSignatureSize($level)`

### MLDsaBuilder

#### Properties

- $type $_level
- $type $_keyPair
- $type $_publicKey
- $type $_data
- $type $_context

#### Methods

- `static [MLDsaBuilder] Create()`
- `[MLDsaBuilder] WithSecurityLevel($level)`
- `[MLDsaBuilder] WithKeyPair($keyPair)`
- `[MLDsaBuilder] WithPublicKey($publicKey)`
- `[MLDsaBuilder] WithData($data)`
- `[MLDsaBuilder] WithContext($context)`
- `[MLDsaKeyPair] GenerateKeyPair()`
- `[byte[]] Sign()`
- `[bool] Verify($signature)`

### SlhDsaKeyPair

#### Properties

- $type $PublicKey
- $type $PrivateKey
- $type $Level

#### Methods

- `[void] SlhDsaKeyPair($public, $private, $level)`

### SlhDsaCore

#### Methods

- `[void] SlhDsaCore()`
- `static [SlhDsaKeyPair] GenerateKeyPair()`
- `static [SlhDsaKeyPair] GenerateKeyPair($level)`
- `static [byte[]] Sign($message, $privateKey)`
- `static [byte[]] Sign($message, $privateKey, $context, $level)`
- `static [bool] Verify($message, $signature, $publicKey)`
- `static [bool] Verify($message, $signature, $publicKey, $context)`
- `static [int] GetSignatureSize($level)`

### SlhDsaBuilder

#### Properties

- $type $_level
- $type $_keyPair
- $type $_publicKey
- $type $_data
- $type $_context

#### Methods

- `static [SlhDsaBuilder] Create()`
- `[SlhDsaBuilder] WithSecurityLevel($level)`
- `[SlhDsaBuilder] WithKeyPair($keyPair)`
- `[SlhDsaBuilder] WithPublicKey($publicKey)`
- `[SlhDsaBuilder] WithData($data)`
- `[SlhDsaBuilder] WithContext($context)`
- `[SlhDsaKeyPair] GenerateKeyPair()`
- `[byte[]] Sign()`
- `[bool] Verify($signature)`



