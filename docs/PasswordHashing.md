# PasswordHashing

High-level utilities for securely hashing passwords for storage. Features modern algorithms like Argon2.

## Usage Example

```powershell
$password = 'CorrectHorseBatteryStaple'

# Hash the password
$hash = [PasswordHashing]::HashPassword($password)

# Verify the password later
$isValid = [PasswordHashing]::VerifyPassword($password, $hash)
```

## Classes

### Argon2id

#### Methods

- `[void] Argon2id()`
- `[string] Hash($Password)`
- `[bool] Verify($HashString, $Password)`
- `static [byte[]] Hash($Password, $Salt, $MemoryKB, $Iterations, $Parallelism, $HashLength)`
- `static [bool] Verify($Password, $Salt, $Hash, $MemoryKB, $Iterations, $Parallelism)`

### Argon2i

#### Methods

- `static [byte[]] Hash($Password, $Salt, $MemoryKB, $Iterations, $Parallelism, $HashLength)`
- `static [bool] Verify($Password, $Salt, $Hash, $MemoryKB, $Iterations, $Parallelism)`

### Argon2d

#### Methods

- `static [byte[]] Hash($Password, $Salt, $MemoryKB, $Iterations, $Parallelism, $HashLength)`
- `static [bool] Verify($Password, $Salt, $Hash, $MemoryKB, $Iterations, $Parallelism)`

### Scrypt

#### Methods

- `[void] Scrypt()`
- `[string] Hash($Password)`
- `[bool] Verify($HashString, $Password)`
- `static [byte[]] DeriveKey($Password, $Salt, $Cost, $BlockSize, $Parallelism, $KeyLength)`



