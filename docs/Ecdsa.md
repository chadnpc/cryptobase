# Ecdsa

Elliptic Curve Digital Signature Algorithm. Provides high-security signing using NIST curves.

## Usage Example

```powershell
$data = [System.Text.Encoding]::UTF8.GetBytes('Sign this!')

# Generate a new P-256 keypair
$keypair = [EcdsaKey]::Generate([ECCurveName]::nistP256)

# Sign data
$signature = [Ecdsa]::SignData($data, $keypair.PrivateKey, 'SHA256')

# Verify signature
$valid = [Ecdsa]::VerifyData($data, $signature, $keypair.PublicKey, 'SHA256')
```

## Classes

### Ecdsa

#### Properties

- $type $DefaultCurve

#### Methods

- `static [hashtable] GenerateKeyPair()`
- `static [hashtable] GenerateKeyPair($curveName)`
- `static [byte[]] Sign($data, $privateKey)`
- `static [bool] Verify($data, $signature, $publicKey)`



