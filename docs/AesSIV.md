# AES-SIV (Synthetic Initialization Vector)

AES-SIV (RFC 5297) is a **Deterministic Authenticated Encryption** mode. Unlike GCM or OCB, it is "nonce-reuse resistant." If you reuse a nonce (or use no nonce at all), the only information leaked is that the same plaintext was encrypted twice.

## Usage

The `[AesSIV]` class provides support for the SIV mode.

### Encrypting Data

```powershell
$key = [byte[]]::new(32) # SIV uses 256-bit keys for AES-128 or 512-bit for AES-256
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)

$plainbytes = [System.Text.Encoding]::UTF8.GetBytes("SIV is safe")
$aad = [System.Text.Encoding]::UTF8.GetBytes("authenticated-context")

# Encrypt (returns SIV tag + ciphertext)
$result = [AesSIV]::Encrypt($key, $plainbytes, $aad)
```

### Decrypting Data

```powershell
try {
    $decrypted = [AesSIV]::Decrypt($key, $result, $aad)
}
catch {
    Write-Error "Integrity check failed!"
}
```

## When to use SIV?

Use AES-SIV when you cannot guarantee that nonces will never be reused (e.g., in stateless systems or embedded devices without good entropy), or when you need deterministic encryption (where the same input always produces the same output) without sacrificing authentication.


## API Documentation


## Classes

### AesSIV

#### Properties

- $type $_key

#### Methods

- `[void] AesSIV()`
- `[void] AesSIV($Key)`
- `[byte[]] Encrypt($data)`
- `[byte[]] Decrypt($CipherBytes)`
- `static [byte[]] Encrypt($Key, $data)`
- `static [byte[]] Encrypt($Key, $data, $AssociatedData)`
- `static [byte[]] Decrypt($Key, $data)`
- `static [byte[]] Decrypt($Key, $data, $AssociatedData)`
- `static hidden [byte[]] EncryptGCM($Key, $data, $AssociatedData)`
- `static hidden [byte[]] DecryptGCM($Key, $Data, $Aad)`
- `static [int] NonceSize()`
- `static [int] TagSize()`



