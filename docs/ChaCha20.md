# ChaCha20

ChaCha20 is a high-speed stream cipher that provides excellent performance without sacrificing security. 
This module includes the `ChaCha20Poly1305Managed` class which provides Authenticated Encryption with Associated Data (AEAD) using a 256-bit key and a 96-bit nonce.

## Usage Example

```powershell
$key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
$nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

$plainbytes = [System.Text.Encoding]::UTF8.GetBytes("Secret ChaCha20 Message")
$aad = [System.Text.Encoding]::UTF8.GetBytes("HeaderData")

# Encrypt the data
$ciphertext = [ChaCha20Poly1305Managed]::Encrypt($key, $nonce, $plainbytes, $aad)

# Decrypt the data
$decrypted = [ChaCha20Poly1305Managed]::Decrypt($key, $nonce, $ciphertext, $aad)
$decryptedString = [System.Text.Encoding]::UTF8.GetString($decrypted)
```

> **Note:** This documentation API reference was automatically generated.

## Classes

### ChaCha20Poly1305Managed

#### Properties

- `[byte[]]` `$Key`

#### Methods

- `[void] ChaCha20Poly1305Managed()`
- `[void] ChaCha20Poly1305Managed($key)`
- `static [uint] RotateLeft($value, $bits)`
- `static [void] QuarterRound($state, $a, $b, $c, $d)`
- `static [void] ChaCha20Block($keystream, $state, $offset)`
- `static [uint[]] InitializeState($key, $nonce, $counter)`
- `static [void] ComputePoly1305Mac($tag, $message, $key)`
- `[byte[]] Encrypt($plainbytes)`
- `[byte[]] Decrypt($ciphertext)`
- `static [byte[]] Encrypt($Key, $Nonce, $plainbytes, $AssociatedData)`
- `static [byte[]] Decrypt($Key, $Nonce, $Ciphertext, $AssociatedData)`


