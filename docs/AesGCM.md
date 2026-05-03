# AesGCM

Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM). GCM is an Authenticated Encryption with Associated Data (AEAD) mode that provides both confidentiality and data integrity.

## Usage

The `[AesGCM]` class provides a managed wrapper around the standard .NET `System.Security.Cryptography.AesGcm` class.

### Encrypting Data

```powershell
$key = [byte[]]::new(32) # 256-bit key
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)

$nonce = [byte[]]::new(12) # Standard GCM nonce size
[System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

$plaintext = [System.Text.Encoding]::UTF8.GetBytes("Secret message")
$ciphertext = [byte[]]::new($plaintext.Length)
$tag = [byte[]]::new(16) # Authentication tag

$aes = [AesGcm]::new($key)
try {
    # Optional Additional Authenticated Data (AAD)
    $aad = [System.Text.Encoding]::UTF8.GetBytes("context-data")
    
    $aes.Encrypt($nonce, $plaintext, $ciphertext, $tag, $aad)
}
finally {
    $aes.Dispose()
}

# The payload usually consists of Nonce + Tag + Ciphertext
$payload = $nonce + $tag + $ciphertext
```

### Decrypting Data

```powershell
$aes = [AesGcm]::new($key)
$decrypted = [byte[]]::new($ciphertext.Length)

try {
    $aes.Decrypt($nonce, $ciphertext, $tag, $decrypted, $aad)
    [System.Text.Encoding]::UTF8.GetString($decrypted) # "Secret message"
}
catch {
    Write-Error "Decryption failed or tag mismatch!"
}
finally {
    $aes.Dispose()
}
```

## Security Considerations

- **Key Reuse**: Never reuse a key/nonce pair. A nonce must be unique for every encryption with the same key.
- **Nonce Size**: While AES-GCM supports different nonce sizes, 12 bytes (96 bits) is the standard and recommended size.
- **Tag Size**: A 16-byte (128-bit) tag is recommended for maximum security.
