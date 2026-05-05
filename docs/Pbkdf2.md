# Pbkdf2

Password-Based Key Derivation Function 2. A standard algorithm for deriving keys from passwords using thousands of iterations.

## Usage Example

```powershell
$password = [System.Text.Encoding]::UTF8.GetBytes('MyPassword')
$salt = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)

# Derive a 256-bit key using HMAC-SHA256 and 600,000 iterations
$key = [Pbkdf2]::DeriveKey($password, $salt, 600000, 32, 'SHA256')
```

## Classes

### Pbkdf2

#### Methods

- `static [byte[]] DeriveKey($password, $salt, $iterations, $outputLength, $hashAlgorithm)`
- `static [byte[]] DeriveKey($password, $salt, $iterations, $outputLength, $hashAlgorithm)`



