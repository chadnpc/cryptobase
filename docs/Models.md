# Models

Defines Data Transfer Objects (DTOs) and structures to hold cryptographic payloads, keys, and results.

## Usage Example

```powershell
# Many methods return well-typed models instead of raw byte hashes or pscustomobject:
$result = [CryptoResult]::new()
$result.Ciphertext = $encryptedBytes
```
