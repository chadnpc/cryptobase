# Argon2 (Password Hashing)

Argon2 is the winner of the Password Hashing Competition (PHC) and is the current industry recommendation for secure password hashing. It is specifically designed to be memory-hard, making it resistant to GPU and ASIC brute-force attacks.

## Variants

`CryptoBase` provides three variants:
- **Argon2id**: The recommended choice (hybrid). It resists both side-channel and GPU attacks.
- **Argon2i**: Optimized to resist side-channel attacks.
- **Argon2d**: Optimized to resist GPU attacks (faster but may be vulnerable to side-channels).

## Usage

The `[Argon2id]`, `[Argon2i]`, and `[Argon2d]` classes share the same API.

### High-Level Instance API (Recommended)
Generates a random salt and returns a colon-separated string: `salt_b64:hash_b64`.

```powershell
$password = [System.Text.Encoding]::UTF8.GetBytes("user-password")
$argon = [Argon2id]::new()

# Hash (using default memory cost 64MB, 3 iterations)
$hashString = $argon.Hash($password)
# Example result: "v8L2f...:x9M3k..."

# Verify
$isValid = $argon.Verify($hashString, $password)
```

### Static API (Advanced)
Allows manual control over memory, iterations, and parallelism.

```powershell
$salt = [byte[]]::new(16)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)

$hash = [Argon2id]::Hash(
    $password, 
    $salt, 
    65536, # Memory (KB)
    3,     # Iterations
    4,     # Parallelism
    32     # Output Length
)

# Verify
$isValid = [Argon2id]::Verify($password, $salt, $hash, 65536, 3, 4)
```

## Security Parameters

- **MemoryKB**: Amount of memory to use. Higher is better (e.g., 65536 = 64MB).
- **Iterations**: Number of passes over the memory.
- **Parallelism**: Number of threads to use.

> **Note**: This implementation uses PBKDF2-SHA256 as a secure fallback if a native Argon2 library is not detected in the environment.
