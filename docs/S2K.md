# S2K

String-to-Key algorithms utilized predominantly by the OpenPGP standard to derive symmetric keys from passphrases.

## Usage Example

```powershell
$passPhrase = [System.Text.Encoding]::UTF8.GetBytes('OpenPGP_Pass')
$salt = [byte[]]::new(8); [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)

# Derive 32-byte key via Iterated & Salted S2K (RFC 4880)
$key = [S2K]::IteratedS2K($passPhrase, $salt, 65536, 32, [PgpHashAlgorithmId]::Sha256)
```

## Classes

### PgpS2KSpecifier

#### Properties

- $type $Type
- $type $HashAlgorithm
- $type $Salt
- $type $EncodedCount
- $type $Argon2Passes
- $type $Argon2Parallelism
- $type $Argon2MemoryExponent

#### Methods

- `[void] PgpS2KSpecifier()`
- `static [PgpS2KSpecifier] Read($data, $offset)`
- `[byte[]] Write()`
- `[long] GetIterationCount()`

### S2K

#### Methods

- `static [byte[]] SimpleS2K($password, $keySize, $hashAlgorithm)`
- `static [byte[]] SaltedS2K($password, $salt, $keySize, $hashAlgorithm)`
- `static [byte[]] IteratedS2K($password, $salt, $count, $keySize, $hashAlgorithm)`
- `static [byte[]] Argon2S2K($password, $salt, $memExp, $passes, $parallelism, $keySize)`
- `static [byte[]] Derive($password, $spec, $keySize)`
- `static [long] DecodeIterationCount($encodedCount)`
- `static [byte] EncodeIterationCount($count)`
- `static hidden [byte[]] DeriveWithPrefix($data, $keySize, $hashAlgorithmName)`
- `static hidden [byte[]] DeriveIteratedKey($combined, $count, $keySize, $hashAlgorithmName)`
- `static hidden [byte[]] HashData($data, $hashAlgorithmName)`
- `static hidden [int] GetHashSize($hashAlgorithmName)`



