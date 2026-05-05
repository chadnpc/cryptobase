# Secp256k1

The Koblitz elliptic curve used primarily in Bitcoin and various blockchain environments for digital signatures.

## Usage Example

```powershell
$msg = [System.Text.Encoding]::UTF8.GetBytes('Blockchain Transaction')

# Generate signature
$keypair = [Secp256k1Key]::Generate()
$sig = [Secp256k1]::Sign($msg, $keypair.PrivateKey)

# Verify
$valid = [Secp256k1]::Verify($msg, $sig, $keypair.PublicKey)
```

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



