# RSA

Standard RSA Public Key Cryptography implementation for encryption and signatures.

## Usage Example

```powershell
$data = [System.Text.Encoding]::UTF8.GetBytes('Secret')

# Generate keys
$keypair = [RSAKey]::Generate(2048)

# Encrypt with OAEP-SHA256
$cipher = [RSAManaged]::Encrypt($data, $keypair.PublicKey, [RSAPadding]::OaepSHA256)

# Decrypt
$plain = [RSAManaged]::Decrypt($cipher, $keypair.PrivateKey, [RSAPadding]::OaepSHA256)
```

## Classes

### RSA

#### Methods

- `static [byte[]] Encrypt($data, $publicKeyXml)`
- `static [byte[]] Decrypt($data, $privateKeyXml)`
- `static [byte[]] Encrypt($data, $PublicKeyXml, $password, $salt)`
- `static [byte[]] Decrypt($data, $privateKeyXml, $password)`
- `static [void] ExportKeyPair($publicKeyXml, $privateKeyXml, $filePath)`
- `static [psobject] LoadKeyPair($filePath)`
- `static [psobject] LoadKeyPair($filePath, $keyPairString)`
- `[byte[]] GenerateKey()`



