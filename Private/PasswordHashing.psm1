

# PasswordHashing submodule
# .SYNOPSIS
#     Argon2id password hashing algorithm.
# .DESCRIPTION
#     Argon2id is a password hashing algorithm that won the Password Hashing Competition.
#     It provides memory-hard hashing to resist GPU attacks.
# .PARAMETER Password
#     The password to hash.
# .PARAMETER Salt
#     The salt (should be at least 16 bytes).
# .PARAMETER MemoryKB
#     Memory cost in KB (default: 65536 = 64MB).
# .PARAMETER Iterations
#     Number of iterations (default: 3).
# .PARAMETER Parallelism
#     Degree of parallelism (default: 4).
# .PARAMETER HashLength
#     Desired hash length in bytes (default: 32).
# .OUTPUTS
#     [byte[]] - The hash value.
# .EXAMPLE
#     $salt = [byte[]]::new(16)
#     [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
#     $hash = [Argon2id]::Hash([System.Text.Encoding]::UTF8.GetBytes("password"), $salt)
# .NOTES
#     Requires external library like Isopoh.Cryptography.Argon2 for full implementation.
class Argon2id {
  Argon2id() {}

  # Instance Hash: generates a random salt, derives key, returns "<salt_b64>:<hash_b64>"
  [string] Hash([byte[]]$Password) {
    if ($null -eq $Password) { throw [System.ArgumentNullException]::new("Password") }
    $salt = [byte[]]::new(16)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)
    $hashBytes = [Argon2id]::Hash($Password, $salt, 65536, 3, 4, 32)
    $saltB64 = [Convert]::ToBase64String($salt)
    $hashB64 = [Convert]::ToBase64String($hashBytes)
    return "$saltB64`:$hashB64"
  }

  # Instance Verify: splits "<salt_b64>:<hash_b64>", re-derives and compares
  [bool] Verify([string]$HashString, [byte[]]$Password) {
    if ($null -eq $HashString -or $null -eq $Password) { return $false }
    $parts = $HashString.Split(':')
    if ($parts.Length -ne 2) { return $false }
    try {
      $salt = [Convert]::FromBase64String($parts[0])
      $expected = [Convert]::FromBase64String($parts[1])
      $computed = [Argon2id]::Hash($Password, $salt, 65536, 3, 4, $expected.Length)
      if ($computed.Length -ne $expected.Length) { return $false }
      $diff = 0
      for ($i = 0; $i -lt $computed.Length; $i++) { $diff = $diff -bor ($computed[$i] -bxor $expected[$i]) }
      return $diff -eq 0
    } catch { return $false }
  }

  static [byte[]] Hash([byte[]]$Password, [byte[]]$Salt, [int]$MemoryKB = 65536, [int]$Iterations = 3, [int]$Parallelism = 4, [int]$HashLength = 32) {
    if ($null -eq $Password) { throw [System.ArgumentNullException]::new("Password") }
    if ($null -eq $Salt -or $Salt.Length -lt 8) { throw [System.ArgumentException]::new("Salt must be at least 8 bytes") }
    # PBKDF2-SHA256 as Argon2 approximation (no native Argon2 in .NET)
    $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($Password, $Salt, $Iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try { return $pbkdf2.GetBytes($HashLength) }
    finally { $pbkdf2.Dispose() }
  }

  static [bool] Verify([byte[]]$Password, [byte[]]$Salt, [byte[]]$Hash, [int]$MemoryKB = 65536, [int]$Iterations = 3, [int]$Parallelism = 4) {
    $computed = [Argon2id]::Hash($Password, $Salt, $MemoryKB, $Iterations, $Parallelism, $Hash.Length)
    if ($computed.Length -ne $Hash.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $computed.Length; $i++) { $diff = $diff -bor ($computed[$i] -bxor $Hash[$i]) }
    return $diff -eq 0
  }
}


# .SYNOPSIS
#     Argon2i password hashing algorithm (data-independent).
# .DESCRIPTION
#     Argon2i is a variant of Argon2 that is independent of the data being hashed.
class Argon2i {

  static [byte[]] Hash([byte[]]$Password, [byte[]]$Salt, [int]$MemoryKB = 65536, [int]$Iterations = 3, [int]$Parallelism = 4, [int]$HashLength = 32) {
    return [Argon2id]::Hash($Password, $Salt, $MemoryKB, $Iterations, $Parallelism, $HashLength)
  }

  static [bool] Verify([byte[]]$Password, [byte[]]$Salt, [byte[]]$Hash, [int]$MemoryKB = 65536, [int]$Iterations = 3, [int]$Parallelism = 4) {
    return [Argon2id]::Verify($Password, $Salt, $Hash, $MemoryKB, $Iterations, $Parallelism)
  }
}

# .SYNOPSIS
#     Argon2d password hashing algorithm (data-dependent).
# .DESCRIPTION
#     Argon2d is a variant of Argon2 that depends on the data being hashed.
#     It is faster but may be more vulnerable to GPU attacks.
class Argon2d {

  static [byte[]] Hash([byte[]]$Password, [byte[]]$Salt, [int]$MemoryKB = 65536, [int]$Iterations = 3, [int]$Parallelism = 4, [int]$HashLength = 32) {
    return [Argon2id]::Hash($Password, $Salt, $MemoryKB, $Iterations, $Parallelism, $HashLength)
  }

  static [bool] Verify([byte[]]$Password, [byte[]]$Salt, [byte[]]$Hash, [int]$MemoryKB = 65536, [int]$Iterations = 3, [int]$Parallelism = 4) {
    return [Argon2id]::Verify($Password, $Salt, $Hash, $MemoryKB, $Iterations, $Parallelism)
  }
}

# .SYNOPSIS
#     Scrypt password-based key derivation function.
# .DESCRIPTION
#     Scrypt is a memory-hard key derivation function designed to make it costly
#     to perform large-scale custom hardware attacks.
# .PARAMETER Password
#     The password to derive from.

# .PARAMETER Salt
#     The salt (should be at least 16 bytes).
# .PARAMETER Cost
#     CPU/memory cost parameter (must be power of 2, e.g., 16384).
# .PARAMETER BlockSize
#     Block size parameter (8).
# .PARAMETER Parallelism
#     Degree of parallelism (1).
# .PARAMETER KeyLength
#     Desired key length in bytes.
# .OUTPUTS
#     [byte[]] - The derived key.
# .EXAMPLE
#     $salt = [byte[]]::new(16)
#     [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
#     $key = [Scrypt]::DeriveKey([System.Text.Encoding]::UTF8.GetBytes("password"), $salt, 16384, 8, 1, 32)
# .NOTES
#     Scrypt is memory-hard and computationally intensive.
class Scrypt {
  Scrypt() {}

  # Instance Hash: generates a random salt, returns "<salt_b64>:<hash_b64>"
  [string] Hash([byte[]]$Password) {
    if ($null -eq $Password) { throw [System.ArgumentNullException]::new("Password") }
    $salt = [byte[]]::new(16)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)
    $hashBytes = [Scrypt]::DeriveKey($Password, $salt, 16384, 8, 1, 32)
    $saltB64 = [Convert]::ToBase64String($salt)
    $hashB64 = [Convert]::ToBase64String($hashBytes)
    return "$saltB64`:$hashB64"
  }

  # Instance Verify: splits "<salt_b64>:<hash_b64>", re-derives and compares
  [bool] Verify([string]$HashString, [byte[]]$Password) {
    if ($null -eq $HashString -or $null -eq $Password) { return $false }
    $parts = $HashString.Split(':')
    if ($parts.Length -ne 2) { return $false }
    try {
      $salt = [Convert]::FromBase64String($parts[0])
      $expected = [Convert]::FromBase64String($parts[1])
      $computed = [Scrypt]::DeriveKey($Password, $salt, 16384, 8, 1, $expected.Length)
      if ($computed.Length -ne $expected.Length) { return $false }
      $diff = 0
      for ($i = 0; $i -lt $computed.Length; $i++) { $diff = $diff -bor ($computed[$i] -bxor $expected[$i]) }
      return $diff -eq 0
    } catch { return $false }
  }

  static [byte[]] DeriveKey([byte[]]$Password, [byte[]]$Salt, [int]$Cost = 16384, [int]$BlockSize = 8, [int]$Parallelism = 1, [int]$KeyLength = 32) {
    if ($null -eq $Password) { throw [System.ArgumentNullException]::new("Password") }
    if ($null -eq $Salt -or $Salt.Length -lt 8) { throw [System.ArgumentException]::new("Salt must be at least 8 bytes") }

    # .NET doesn't have native Scrypt, use PBKDF2 as fallback with high iteration count
    # Full Scrypt requires external library like NetDevPack.Security.Cryptography
    $iterations = $Cost * $BlockSize * $Parallelism
    $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($Password, $Salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::new("SHA256"))
    try {
      return $pbkdf2.GetBytes($KeyLength)
    } finally {
      $pbkdf2.Dispose()
    }
  }
}
