# EllipticCurve

Core mathematics for standard elliptic curves like Secp256k1 and NIST curves.

## Usage Example

```powershell
# Mostly used internally by the module for signature/DH calculation.
# Represents coordinates on a defined curve equation.
```

## Classes

### ECC

#### Properties

- $type $publicKeyXml
- $type $privateKeyXml

#### Methods

- `[void] ECC($publicKeyXml, $privateKeyXml)`
- `[byte[]] Encrypt($data, $password, $salt)`
- `[byte[]] Decrypt($data, $password)`
- `[byte[]] GenerateKey()`
- `[string] ExportKeyPair($file)`
- `[void] ImportKeyPair($filePath, $keyPairXml)`



