**Main class and cmdlet overview**

The `[cryptobase]` is the main class, it provides high-level convenience methods for common cryptographic tasks.

## **CLI and Pipeline Usage**

The `Invoke-CryptoBase` cmdlet (alias: `cryptobase`) provides a CLI-like experience and supports pipeline input. By utilizing single-parameter method overloads, you can pipe data directly into cryptographic operations. If a method requires a password but you don't provide one, you will be prompted securely via `Read-Host -AsSecureString`.

```powershell
# View manual-style help
cryptobase GetHelp

# Sign a message via pipeline
"This is my secret message" | cryptobase SignMessage

# Encrypt data (will prompt for password interactively)
"Sensitive Data" | cryptobase ProtectData > secret.bin

# Decrypt data (will prompt for password interactively)
# Note: Invoke-CryptoBase automatically handles byte unrolling from the pipeline
Get-Content secret.bin -AsByteStream | cryptobase UnprotectData

# Obfuscate a file (prompts for password and creates file.txt.enc)
"file.txt" | cryptobase ObfuscateFile
```

> [!TIP]
> The `cryptobase` cmdlet is designed to be pipeline-friendly. When piping bytes, it automatically accumulates them into a single payload before processing. It also ensures that output byte arrays are returned as single objects (using `-NoEnumerate`), preventing them from being unrolled into individual bytes in the next pipeline stage.

## **Data Protection**

`ProtectData` / `UnprotectData` use **Argon2id** (64 MiB memory, 3 iterations, parallelism 4) to derive a 256-bit key from a password, and then use **AES-256-GCM** for authenticated encryption.

### ProtectData
Encrypts plaintext with a password.

```powershell
$plainbytes = [System.Text.Encoding]::UTF8.GetBytes("Secret message")
$password = "your-password"

# Basic protection
$protected = [cryptobase]::ProtectData($plainbytes, $password)

# Protection with Additional Authenticated Data (AAD)
$aad = [System.Text.Encoding]::UTF8.GetBytes("header-info")
$protected = [cryptobase]::ProtectData($plainbytes, $password, $aad)
```

### UnprotectData
Decrypts a protected payload.

```powershell
$decrypted = [cryptobase]::UnprotectData($protected, $password)
[System.Text.Encoding]::UTF8.GetString($decrypted) # "Secret message"
```

**Nerd-Approved Hybrids**

**ProtectDataCascade**
Paranoid cascade mode: **AES-256-GCM (inner)** wrapped by **XChaCha20-Poly1305 (outer)**, with independent keys derived from a 64-byte Argon2id output.

```powershell
$plainbytes = [System.Text.Encoding]::UTF8.GetBytes("Classified")
$password = "correct horse battery staple"

$cascade = [cryptobase]::ProtectDataCascade($plainbytes, $password)
$opened = [cryptobase]::UnprotectDataCascade($cascade, $password)
```

**CreateSealedBox**
Asymmetric authenticated payload mode: **NIST P-256 ECDH + HKDF-SHA256 + XChaCha20-Poly1305**.

```powershell
$sender = [Curve25519]::GenerateKeyPair()
$recipient = [Curve25519]::GenerateKeyPair()
$msg = [System.Text.Encoding]::UTF8.GetBytes("sealed hello")

$sealed = [cryptobase]::CreateSealedBox($msg, $sender.PrivateKey, $recipient.PublicKey)
```

**ProtectDataQuantumHybrid**
Post-quantum hybrid encapsulation mode: **NIST P-256 ECDH + ML-KEM**, combined with **BLAKE3** into a hybrid symmetric secret used by XChaCha20-Poly1305.

```powershell
$recipientP256 = [Curve25519]::GenerateKeyPair()
$mlKem = [MLKemCore]::new()
$recipientKem = $mlKem.GenerateKeyPair()
$payload = [System.Text.Encoding]::UTF8.GetBytes("future-proof payload")

$result = [cryptobase]::ProtectDataQuantumHybrid($payload, $recipientP256.PublicKey, $recipientKem.PublicKey)
$result.Ciphertext
$result.EphemeralCurvePub
$result.KemCiphertext
```

## Message Signing

Uses **Secp256k1** (the Bitcoin curve) for digital signatures.

### SignMessage
Generates a new keypair and signs the data.

```powershell
$data = [System.Text.Encoding]::UTF8.GetBytes("Message to sign")
$result = [cryptobase]::SignMessage($data)

$result.Signature  # The signature bytes
$result.PublicKey  # The generated public key
$result.PrivateKey # The generated private key
```

### VerifyMessage
Verifies a signature against a public key.

```powershell
$isValid = [cryptobase]::VerifyMessage($data, $signature, $publicKey)
```

## File Obfuscation

Provides simple file-level encryption with integrity checking using **CRC24**.

### ObfuscateFile
```powershell
[cryptobase]::ObfuscateFile("source.txt", "source.enc", $password)
```

### DeobfuscateFile
```powershell
[cryptobase]::DeobfuscateFile("source.enc", "decrypted.txt", $password)
```

## Secure String Handling

Utilities for working with `System.Security.SecureString`.

### SecureStringToString
Safely converts a `SecureString` to a plain string in memory (use with caution).
```powershell
$plain = [cryptobase]::SecureStringToString($secureString)
```

### ReadSecureString
Prompts the user for a password and returns the plain string.
```powershell
$pass = [cryptobase]::ReadSecureString()
```

## Pipeline & Stream Operations

Since the `cryptobase` cmdlet supports pipeline unrolling and binary streams, you can build complex cryptographic processing chains entirely in the command line without creating intermediate files.

### Encrypt, Encode, and Obfuscate Pipeline

Encrypt a string, convert to Base64, and output to a stream.
```powershell
# In a single pipeline string -> bytes -> AesGCM -> Base64 string
"Secret Data" | cryptobase ProtectData | ConvertTo-Base64
```

### Decrypt an Armored Payload

```powershell
# Assume encoded.txt contains an ASCII armored AES-encrypted payload
Get-Content encoded.txt -Raw | Decode-Armor | cryptobase UnprotectData > plaintext.bin
```

### High-level Certificate and Key Automation

You can also leverage the core types for rapid development of PKI logic.
```powershell
# Rapid generation and signing with ephemeral keys
$pqc = [cryptobase]::ProtectDataQuantumHybrid($data, $receiverP256, $receiverKem)

# Verify the resulting Hybrid object
$pqc.Ciphertext
$pqc.EphemeralCurvePub
$pqc.KemCiphertext
```
