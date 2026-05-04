# XSalsa20

XSalsa20 is a stream cipher based on the Salsa20 algorithm, but with an extended 192-bit nonce. Like XChaCha20, the extended nonce makes it safe to use with randomly generated nonces.

## Usage

The `[XSalsa20]` class provides static methods for encryption and decryption. Note that since it is a stream cipher, encryption and decryption are identical operations.

### Basic Encryption/Decryption

```powershell
$key = [byte[]]::new(32) # 256-bit key
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)

$nonce = [byte[]]::new(24) # 192-bit nonce
[System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

$data = [System.Text.Encoding]::UTF8.GetBytes("Streaming data...")

# Encrypt
$ciphertext = [XSalsa20]::Encrypt($data, $key, $nonce)

# Decrypt (same method)
$plainbytes = [XSalsa20]::Decrypt($ciphertext, $key, $nonce)
```

### Encryption with Counter Offset
If you need to start encryption from a specific block offset (e.g., for random access within a large file).

```powershell
$counter = [uint]1000 # Start at block 1000
$ciphertext = [XSalsa20]::Encrypt($data, $key, $nonce, $counter)
```

## Security Note

XSalsa20 is a **pure stream cipher** and does **not** provide built-in authentication (integrity). For most applications, you should use an AEAD mode like **XChaCha20-Poly1305** or **AES-GCM**. 

If you use XSalsa20, you must combine it with a MAC (like Poly1305 or HMAC) to ensure the ciphertext has not been tampered with.
