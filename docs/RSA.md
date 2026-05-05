# RSA

> **Note:** This documentation was automatically generated.

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


