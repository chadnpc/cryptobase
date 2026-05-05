# Key Derivation Functions (KDF)

Key Derivation Functions are used to derive cryptographically strong keys from passwords or other secret material.

## PBKDF2 (Password-Based Key Derivation Function 2)

The most common KDF, used to turn a password into a symmetric key.

### Usage
```powershell
$password = [System.Text.Encoding]::UTF8.GetBytes("user-password")
$salt = [byte[]]::new(16)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)

# Derive 32-byte key using 100,000 iterations of SHA256
$key = [Pbkdf2]::DeriveKey($password, $salt, 100000, 32, "SHA256")
```

---

## HKDF (HMAC-based Key Derivation Function)

Used to "extract" and "expand" keys from entropy or existing master keys (RFC 5869).

### Usage
```powershell
$masterKey = [byte[]]::new(32)
$salt = [System.Text.Encoding]::UTF8.GetBytes("session-salt")
$info = [System.Text.Encoding]::UTF8.GetBytes("app-context-v1")

# Derive a sub-key
$subKey = [HkdfCore]::DeriveKey("SHA256", $masterKey, 32, $salt, $info)
```

---

## S2K (String-to-Key)

Implements the OpenPGP String-to-Key algorithms (Simple, Salted, Iterated and Salted).

### Usage
```powershell
# Iterate and Salted S2K
$key = [S2K]::IteratedAndSalted([HashType]::SHA256, $password, $salt, 65536)
```
