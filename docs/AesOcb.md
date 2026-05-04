# AES-OCB (Offset Codebook Mode)

AES-OCB is an Authenticated Encryption with Associated Data (AEAD) mode that is extremely fast and efficient, providing both confidentiality and integrity in a single pass.

## Usage

The `[AesOcb]` class provides a pure PowerShell implementation of the OCB mode (v3).

### Encrypting Data

```powershell
$key = [byte[]]::new(32) # 256-bit key
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)

$nonce = [byte[]]::new(12) # OCB supports nonces up to 15 bytes, 12 is standard
[System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

$plainbytes = [System.Text.Encoding]::UTF8.GetBytes("Data for OCB")
$tag = [byte[]]::new(16) # Authentication tag

$ocb = [AesOcb]::new($key)
# Optional AAD
$aad = [System.Text.Encoding]::UTF8.GetBytes("header")

$ciphertext = $ocb.Encrypt($nonce, $plainbytes, $tag, $aad)
```

### Decrypting Data

```powershell
try {
    $decrypted = $ocb.Decrypt($nonce, $ciphertext, $tag, $aad)
    [System.Text.Encoding]::UTF8.GetString($decrypted) # "Data for OCB"
}
catch {
    Write-Error "OCB Authentication failed!"
}
```

## Performance Note

OCB is generally faster than GCM in software implementations because it requires fewer operations per block. However, it was previously encumbered by patents (which have now expired or been granted free licenses for most uses).
