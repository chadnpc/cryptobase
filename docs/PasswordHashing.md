# PasswordHashing

> **Note:** This documentation was automatically generated.

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


