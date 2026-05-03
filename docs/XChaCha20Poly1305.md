# XChaCha20Poly1305

XChaCha20-Poly1305 is an Authenticated Encryption with Associated Data (AEAD) algorithm. It is a variant of ChaCha20-Poly1305 that uses a 192-bit nonce, making it much safer to use with randomly generated nonces.

## Usage

The `[XChaCha20Poly1305]` class provides static methods for encryption and decryption.

### Encrypting Data

```powershell
$key = [byte[]]::new(32) # 256-bit key
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)

$nonce = [byte[]]::new(24) # 192-bit nonce
[System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

$plaintext = [System.Text.Encoding]::UTF8.GetBytes("Hello from XChaCha20!")

# Encrypt (returns ciphertext + 16-byte tag)
$ciphertextWithTag = [XChaCha20Poly1305]::Encrypt($plaintext, $key, $nonce)
```

### Decrypting Data

```powershell
try {
    $decrypted = [XChaCha20Poly1305]::Decrypt($ciphertextWithTag, $key, $nonce)
    [System.Text.Encoding]::UTF8.GetString($decrypted) # "Hello from XChaCha20!"
}
catch {
    Write-Error "Authentication failed!"
}
```

### Authentication Only (MAC)

If you only need to ensure data integrity without encryption, you can use `Authenticate` and `Verify`.

```powershell
# Generate a 16-byte authentication tag
$tag = [XChaCha20Poly1305]::Authenticate($plaintext, $key, $nonce)

# Verify the tag
$isValid = [XChaCha20Poly1305]::Verify($plaintext, $tag, $key, $nonce)
```

## Why XChaCha20?

Standard ChaCha20 uses a 96-bit nonce. While sufficient for many uses, it is risky to generate randomly if you encrypt a large number of messages with the same key (due to the Birthday Paradox). 

**XChaCha20** extends the nonce to 192 bits, which is large enough to be safely generated randomly for an practically unlimited number of messages with the same key.
