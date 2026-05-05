## [cryptobase](https://www.powershellgallery.com/packages/cryptobase)

🔥 Provides classes to speed up your cryptographic needs.

[![Downloads](https://img.shields.io/powershellgallery/dt/cryptobase.svg?style=flat&logo=powershell&color=blue)](https://www.powershellgallery.com/packages/cryptobase)

**Features**

- **AEAD Encryption**: AES-GCM, AES-CCM, AES-OCB, and XChaCha20-Poly1305.
- **Hashing & MACs**: BLAKE3, SHA-3 (Keccak), BLAKE2b, KMAC, HMAC.
- **Password Hashing**: Argon2 (id/i/d), Scrypt, BCrypt (with SHA-3 extensions), PBKDF2.
- **Elliptic Curve Cryptography**: Ed25519, Curve25519, Secp256k1 (Bitcoin/Ethereum).
- **Post-Quantum Cryptography (PQC)**: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (Sphincs+).
- **Advanced Protocols**: OPAQUE (PAKE), Noise Protocol Framework, OpenPGP Armor.
- **Utilities**: OTP (TOTP/HOTP), Key Derivation (HKDF), Credentials Management, File Obfuscation.

**📦 Installation**

```PowerShell
# Install from PSGallery
Install-Module cryptobase -Scope CurrentUser

# Import the module
Import-Module cryptobase
```

**🗐 Testing (before opening a PR)**

```PowerShell
Import-Module ./cryptobase.psd1
./Test-Module.ps1 -SkipBuildOutput
```

or test the `./BuildOutput/`

```PowerShell
./Test-Module.ps1
```

**💡 Quick Examples**

**High-Level Data Protection**
Easily encrypt and decrypt data with a password using the main `[CryptoBase]` class.

```powershell
$password = "my-ultra-secure-password"
$data = [System.Text.Encoding]::UTF8.GetBytes("Hello World")

# Encrypt (uses Argon2id + AES-256-GCM)
$encrypted = [CryptoBase]::ProtectData($data, $password)

# Decrypt
$decrypted = [CryptoBase]::UnprotectData($encrypted, $password)
[System.Text.Encoding]::UTF8.GetString($decrypted) # "Hello World"
```


**Modern Hybrid Cascades**
Paranoid double-wrap mode with independent keys for AES-256-GCM and XChaCha20-Poly1305.

```powershell
$password = "my-ultra-secure-password"
$data = [System.Text.Encoding]::UTF8.GetBytes("Top secret")
$cascade = [CryptoBase]::ProtectDataCascade($data, $password)
$plain = [CryptoBase]::UnprotectDataCascade($cascade, $password)
```

**Post-Quantum Hybrids**
Hybrid encryption that combines NIST P-256 ECDH with ML-KEM encapsulation.

```powershell
$recipientP256 = [Curve25519]::GenerateKeyPair()
$mlKem = [MLKemCore]::new()
$recipientKem = $mlKem.GenerateKeyPair()
$payload = [System.Text.Encoding]::UTF8.GetBytes("future-proof")
$hybrid = [CryptoBase]::ProtectDataQuantumHybrid($payload, $recipientP256.PublicKey, $recipientKem.PublicKey)
```

**Password Hashing (BCrypt)**
Standard password hashing for your applications.

```powershell
$hash = [BCrypt]::HashPassword('my_secret')
$isValid = [BCrypt]::Verify('my_secret', $hash) # Returns $true
```

**📚 Documentation**

For a complete list of classes and their usage, see:

- **[Usage docs](./docs/README.md)**: Categorized list of all major primitives.
- **[OPAQUE Protocol](./docs/Opaque.md)**: Detailed guide for secure password authentication.
- **[More about the main class](./docs/CryptoBase.md)** and cmdlet overview.


**⚖️ License**

This project is licensed under the [MIT License](LICENSE).
