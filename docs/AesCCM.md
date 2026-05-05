# AesCCM

> **Note:** This documentation was automatically generated.

## Classes

### AesCcmEncryptionResult

#### Properties

- $type $Ciphertext
- $type $Nonce
- $type $TagSize

#### Methods

- `[int] get_CiphertextLength()`

### AesCcmCore

#### Properties

- $type $SupportedKeySizes
- $type $MinNonceSize
- $type $MaxNonceSize
- $type $DefaultNonceSize
- $type $MinTagSize
- $type $MaxTagSize
- $type $DefaultTagSize
- $type $BlockSize

#### Methods

- `static [void] ValidateParameters($key, $nonce, $tagSize, $plaintextLength)`
- `static [void] WriteLength($buffer, $offset, $length, $value)`
- `static [void] XorBlock($mac, $block)`
- `static [void] ComputeTag($tag, $plaintext, $associatedData, $nonce, $encryptor, $tagSize)`
- `static [void] EncryptCtr($ciphertext, $encryptedTag, $plaintext, $tag, $nonce, $encryptor)`
- `static [AesCcmEncryptionResult] Encrypt($plaintext, $key)`
- `static [AesCcmEncryptionResult] Encrypt($plaintext, $key, $nonce)`
- `static [AesCcmEncryptionResult] Encrypt($plaintext, $key, $nonce, $associatedData)`
- `static [AesCcmEncryptionResult] Encrypt($plaintext, $key, $nonce, $associatedData, $tagSize)`
- `static [AesCcmEncryptionResult] Encrypt($plaintext, $key, $nonce, $associatedData, $tagSize, $deterministicMode)`
- `static [byte[]] Decrypt($ciphertext, $key, $nonce)`
- `static [byte[]] Decrypt($ciphertext, $key, $nonce, $associatedData)`
- `static [byte[]] Decrypt($ciphertext, $key, $nonce, $associatedData, $tagSize)`

### AesCcmBuilder

#### Properties

- $type $_key
- $type $_nonce
- $type $_associatedData
- $type $_tagSize
- $type $_disposed

#### Methods

- `[void] AesCcmBuilder()`
- `static [AesCcmBuilder] Create()`
- `[AesCcmBuilder] WithKey($key)`
- `[AesCcmBuilder] WithNonce($nonce)`
- `[AesCcmBuilder] WithRandomNonce()`
- `[AesCcmBuilder] WithRandomNonce($nonceSize)`
- `[AesCcmBuilder] WithAssociatedData($associatedData)`
- `[AesCcmBuilder] WithTagSize($tagSize)`
- `[byte[]] Encrypt($plaintext)`
- `[byte[]] Decrypt($ciphertext)`
- `[byte[]] GetNonce()`
- `[void] Dispose()`


