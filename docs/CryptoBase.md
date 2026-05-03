# CryptoBase

The `[CryptoBase]` is the main class, it provides high-level convenience methods for common cryptographic tasks.

## Data Protection

These methods use **PBKDF2-SHA256** (120,000 iterations) to derive a 256-bit key from a password, and then use **AES-GCM** for authenticated encryption.

### ProtectData
Encrypts plaintext with a password.

```powershell
$plaintext = [System.Text.Encoding]::UTF8.GetBytes("Secret message")
$password = "your-password"

# Basic protection
$protected = [CryptoBase]::ProtectData($plaintext, $password)

# Protection with Additional Authenticated Data (AAD)
$aad = [System.Text.Encoding]::UTF8.GetBytes("header-info")
$protected = [CryptoBase]::ProtectData($plaintext, $password, $aad)
```

### UnprotectData
Decrypts a protected payload.

```powershell
$decrypted = [CryptoBase]::UnprotectData($protected, $password)
[System.Text.Encoding]::UTF8.GetString($decrypted) # "Secret message"
```


## Message Signing

Uses **Secp256k1** (the Bitcoin curve) for digital signatures.

### SignMessage
Generates a new keypair and signs the data.

```powershell
$data = [System.Text.Encoding]::UTF8.GetBytes("Message to sign")
$result = [CryptoBase]::SignMessage($data)

$result.Signature  # The signature bytes
$result.PublicKey  # The generated public key
$result.PrivateKey # The generated private key
```

### VerifyMessage
Verifies a signature against a public key.

```powershell
$isValid = [CryptoBase]::VerifyMessage($data, $signature, $publicKey)
```


## File Obfuscation

Provides simple file-level encryption with integrity checking using **CRC24**.

### ObfuscateFile
```powershell
[CryptoBase]::ObfuscateFile("source.txt", "source.enc", $password)
```

### DeobfuscateFile
```powershell
[CryptoBase]::DeobfuscateFile("source.enc", "decrypted.txt", $password)
```


## Secure String Handling

Utilities for working with `System.Security.SecureString`.

### SecureStringToString
Safely converts a `SecureString` to a plain string in memory (use with caution).
```powershell
$plain = [CryptoBase]::SecureStringToString($secureString)
```

### ReadSecureString
Prompts the user for a password and returns the plain string.
```powershell
$pass = [CryptoBase]::ReadSecureString()
```
