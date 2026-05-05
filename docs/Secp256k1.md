# Secp256k1

> **Note:** This documentation was automatically generated.

## Classes

### Secp256k1

#### Methods

- `static [hashtable] GenerateKeyPair()`
- `static [byte[]] Sign($data, $privateKey)`
- `static [bool] Verify($data, $signature, $publicKey)`

### Secp256k1SignResult

#### Properties

- $type $Signature
- $type $PrivateKey
- $type $PublicKey

#### Methods

- `[void] Secp256k1SignResult()`
- `[void] Secp256k1SignResult($signature, $privateKey, $publicKey)`


