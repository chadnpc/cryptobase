# Hkdf

HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869). Used to derive multiple keys from a single master secret.

## Usage Example

```powershell
$ikm = [System.Text.Encoding]::UTF8.GetBytes('MasterSecretData')
$salt = [System.Text.Encoding]::UTF8.GetBytes('RandomSalt')

# Extract PRK
$prk = [HkdfCore]::Extract($salt, $ikm, 'SHA256')

# Expand to required key length (e.g. 32 bytes for AES-256)
$key = [HkdfCore]::Expand($prk, [System.Text.Encoding]::UTF8.GetBytes('EncryptionKey'), 32, 'SHA256')
```

## Classes

### HkdfCore

#### Methods

- `static [int] GetHashLength($hashAlgorithm)`
- `static [HMAC] CreateHmac($hashAlgorithm, $key)`
- `static [void] ValidateParameters($ikm, $length, $hashAlgorithm)`
- `static [byte[]] Extract($ikm, $salt, $hashAlgorithm)`
- `static [byte[]] Expand($prk, $info, $length, $hashAlgorithm)`
- `static [byte[]] DeriveKey($ikm, $salt, $info, $length)`
- `static [byte[]] DeriveKey($ikm, $salt, $info, $length, $hashAlgorithm)`

### HkdfBuilder

#### Properties

- $type $_ikm
- $type $_salt
- $type $_info
- $type $_outputLength
- $type $_hashAlgorithm
- $type $_disposed

#### Methods

- `[void] HkdfBuilder()`
- `static [HkdfBuilder] Create()`
- `[HkdfBuilder] WithInputKeyMaterial($ikm)`
- `[HkdfBuilder] WithInputKeyMaterial($ikm)`
- `[HkdfBuilder] WithSalt($salt)`
- `[HkdfBuilder] WithRandomSalt()`
- `[HkdfBuilder] WithInfo($info)`
- `[HkdfBuilder] WithInfo($info)`
- `[HkdfBuilder] WithOutputLength($length)`
- `[HkdfBuilder] WithHashAlgorithm($hashAlgorithm)`
- `[HkdfBuilder] WithGeneralPurposePreset()`
- `[HkdfBuilder] WithHighSecurityPreset()`
- `[HkdfBuilder] WithTlsPreset()`
- `[byte[]] DeriveKey()`
- `[byte[]] Extract()`
- `[byte[]] Expand($prk)`
- `[byte[]] GetSalt()`
- `hidden [void] ClearIKM()`
- `hidden [void] ClearSalt()`
- `hidden [void] ClearInfo()`
- `[void] Dispose()`



