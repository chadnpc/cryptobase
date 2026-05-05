# AesCfb

AES in Cipher Feedback (CFB) mode. Used primarily for legacy applications where block cipher streaming is required.

## Usage Example

```powershell
$key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
$iv = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)
$plain = [System.Text.Encoding]::UTF8.GetBytes('Secret Message')

# Encrypt (no authentication tag)
$ciphertext = [AesCfbManaged]::Encrypt($plain, $key, $iv, 128)

# Decrypt
$decrypted = [AesCfbManaged]::Decrypt($ciphertext, $key, $iv, 128)
```

## Classes

### AesCfb

#### Properties

- $type $BlockSize

#### Methods

- `static [byte[]] Encrypt($plainbytes, $key, $iv)`
- `static [byte[]] Decrypt($ciphertext, $key, $iv)`
- `static hidden [byte[]] ProcessCore($inData, $aes, $iv, $encrypting)`



