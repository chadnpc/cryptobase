# AesCtr

AES in Counter (CTR) mode. Converts AES into a stream cipher by generating a keystream through an incrementing counter.

## Usage Example

```powershell
$key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
$iv = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)
$plain = [System.Text.Encoding]::UTF8.GetBytes('Secret Stream')

# Encrypt
$ciphertext = [AesCtrManaged]::Encrypt($plain, $key, $iv)

# Decrypt (same operation as encrypt)
$decrypted = [AesCtrManaged]::Decrypt($ciphertext, $key, $iv)
```

## Classes

### AesCtr

#### Methods

- `static [Byte[]] Encrypt($Bytes, $Key, $IV)`
- `static [Byte[]] Decrypt($Bytes, $Key, $IV)`



