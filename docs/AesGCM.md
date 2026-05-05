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

$plainbytes = [System.Text.Encoding]::UTF8.GetBytes("Secret message")
$ciphertext = [byte[]]::new($plainbytes.Length)
$tag = [byte[]]::new(16) # Authentication tag

$aes = [AesGcm]::new($key)
try {
    # Optional Additional Authenticated Data (AAD)
    $aad = [System.Text.Encoding]::UTF8.GetBytes("context-data")
    
    $aes.Encrypt($nonce, $plainbytes, $ciphertext, $tag, $aad)
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


## API Documentation


## Classes

### AesGCM

#### Methods

- `static [byte[]] Encrypt($bytes)`
- `static [byte[]] Encrypt($Bytes, $Password)`
- `static [byte[]] Encrypt($Bytes, $Password, $Salt)`
- `static [string] Encrypt($text, $Password, $iterations)`
- `static [byte[]] Encrypt($Bytes, $Password, $iterations)`
- `static [byte[]] Encrypt($Bytes, $Password, $Salt, $iterations)`
- `static [byte[]] Encrypt($Bytes, $Password, $iterations, $Compression)`
- `static [byte[]] Encrypt($Bytes, $Password, $Salt, $associatedData, $iterations)`
- `static [byte[]] Encrypt($Bytes, $Password, $Salt, $associatedData)`
- `static [byte[]] Encrypt($Bytes, $Password, $Salt, $associatedData, $Compression, $iterations)`
- `static [void] Encrypt($File)`
- `static [void] Encrypt($File, $Password)`
- `static [void] Encrypt($File, $Password, $OutPath)`
- `static [void] Encrypt($File, $Password, $OutPath, $iterations)`
- `static [void] Encrypt($File, $Password, $OutPath, $iterations, $Compression)`
- `static [byte[]] Decrypt($bytes)`
- `static [byte[]] Decrypt($Bytes, $Password)`
- `static [byte[]] Decrypt($Bytes, $Password, $Salt)`
- `static [string] Decrypt($text, $Password, $iterations)`
- `static [byte[]] Decrypt($Bytes, $Password, $iterations)`
- `static [byte[]] Decrypt($Bytes, $Password, $Salt, $iterations)`
- `static [byte[]] Decrypt($Bytes, $Password, $iterations, $Compression)`
- `static [byte[]] Decrypt($Bytes, $Password, $Salt, $associatedData, $iterations)`
- `static [byte[]] Decrypt($Bytes, $Password, $Salt, $associatedData)`
- `static [byte[]] Decrypt($Bytes, $Password, $Salt, $associatedData, $Compression, $iterations)`
- `static [void] Decrypt($File)`
- `static [void] Decrypt($File, $password)`
- `static [void] Decrypt($File, $Password, $OutPath)`
- `static [void] Decrypt($File, $Password, $OutPath, $iterations)`
- `static [void] Decrypt($File, $Password, $OutPath, $iterations, $Compression)`



