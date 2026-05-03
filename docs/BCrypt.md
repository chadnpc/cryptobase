# BCrypt (Password Hashing)

BCrypt is a password hashing function based on the Blowfish cipher. It is designed to be computationally expensive to thwart brute-force attacks. `CryptoBase` provides both standard BCrypt and an enhanced version using HMAC-SHA3.

## Standard BCrypt

Uses the traditional BCrypt algorithm (version 2a/2b).

### Usage

```powershell
# Hash a password (default work factor = 11)
$hash = [BCrypt]::HashPassword('my_secret')

# Hash with custom work factor (e.g., 12 for 2x more compute)
$hash = [BCrypt]::HashPassword('my_secret', 12)

# Verify a password
$isValid = [BCrypt]::Verify('my_secret', $hash) # Returns $true
```

### Inspecting Hashes
You can interrogate a hash to see its settings and work factor.

```powershell
$info = [BCrypt]::InterrogateHash($hash)
# $info.Version    - e.g., "2b"
# $info.WorkFactor - e.g., 11
# $info.Salt       - The salt used
```

---

## Enhanced BCrypt (V3)

`[BCryptExtendedV3]` provides an enhanced version of BCrypt that incorporates **HMAC-SHA3** with an internal secret key (pepper). This protects hashes even if the database is compromised, provided the internal key remains secure.

### Usage

```powershell
$hmacKey = 'internal-secret-key-pepper'

# Hash a password with HMAC-SHA3 pre-processing
$hash = [BCryptExtendedV3]::HashPassword($hmacKey, 'my_secret')

# Verify
$isValid = [BCryptExtendedV3]::Verify($hmacKey, 'my_secret', $hash)
```

## Advanced Features

### Verbose Logging
Enable verbose output to see the progress of the hashing operation (especially useful for high work factors).

```powershell
$VerbosePreference = 'Continue'
[BCrypt]::HashPassword('my_secret')
```

### Parallel Hashing
BCrypt is single-threaded by design. To hash multiple passwords in parallel, you should use PowerShell's `ForEach-Object -Parallel` or Background Jobs.
