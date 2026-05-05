#!/usr/bin/env pwsh
using namespace System
using namespace System.Collections.Generic
using namespace System.Security.Cryptography

using module ./Utilities.psm1
using module ./PasswordHashing.psm1
using module ./Enums.psm1

class PgpS2KSpecifier {
  [S2KType] $Type
  [PgpHashAlgorithmId] $HashAlgorithm
  [byte[]] $Salt
  [byte] $EncodedCount
  [int] $Argon2Passes
  [int] $Argon2Parallelism
  [int] $Argon2MemoryExponent

  PgpS2KSpecifier() {}

  static [PgpS2KSpecifier] Read([byte[]]$data, [ref]$offset) {
    if ($data.Length -lt $offset.Value + 2) { throw [ArgumentException]::new("Data too short for S2K specifier.") }

    $spec = [PgpS2KSpecifier]::new()
    $spec.Type = [S2KType]$data[$offset.Value]
    $spec.HashAlgorithm = [PgpHashAlgorithmId]$data[$offset.Value + 1]

    switch ($spec.Type) {
      ([S2KType]::Simple) {
        $offset.Value += 2
        break
      }
      ([S2KType]::Salted) {
        if ($data.Length -lt $offset.Value + 10) { throw [ArgumentException]::new("Data too short for Salted S2K.") }
        $spec.Salt = [byte[]]::new(8)
        [Array]::Copy($data, $offset.Value + 2, $spec.Salt, 0, 8)
        $offset.Value += 10
        break
      }
      ([S2KType]::IteratedAndSalted) {
        if ($data.Length -lt $offset.Value + 11) { throw [ArgumentException]::new("Data too short for Iterated S2K.") }
        $spec.Salt = [byte[]]::new(8)
        [Array]::Copy($data, $offset.Value + 2, $spec.Salt, 0, 8)
        $spec.EncodedCount = $data[$offset.Value + 10]
        $offset.Value += 11
        break
      }
      ([S2KType]::Argon2) {
        if ($data.Length -lt $offset.Value + 21) { throw [ArgumentException]::new("Data too short for Argon2 S2K.") }
        $spec.Salt = [byte[]]::new(16)
        [Array]::Copy($data, $offset.Value + 2, $spec.Salt, 0, 16)
        $spec.Argon2MemoryExponent = [int]$data[$offset.Value + 18]
        $spec.Argon2Passes = [int]$data[$offset.Value + 19]
        $spec.Argon2Parallelism = [int]$data[$offset.Value + 20]
        $offset.Value += 21
        break
      }
      default {
        throw [ArgumentException]::new("Unknown S2K type: $($spec.Type)")
      }
    }
    return $spec
  }

  [byte[]] Write() {
    $res = $null
    $res = switch ($this.Type) {
      ([S2KType]::Simple) {
        [byte[]]@([byte]$this.Type, [byte]$this.HashAlgorithm)
        break
      }
      ([S2KType]::Salted) {
        [byte[]]$r = [byte[]]::new(10)
        $r[0] = [byte]$this.Type
        $r[1] = [byte]$this.HashAlgorithm
        [void][Array]::Copy($this.Salt, 0, $r, 2, 8)
        $r; break
      }
      ([S2KType]::IteratedAndSalted) {
        [byte[]]$r = [byte[]]::new(11)
        $r[0] = [byte]$this.Type
        $r[1] = [byte]$this.HashAlgorithm
        [Array]::Copy($this.Salt, 0, $r, 2, 8)
        $r[10] = $this.EncodedCount
        $r; break
      }
      ([S2KType]::Argon2) {
        [byte[]]$r = [byte[]]::new(21)
        $r[0] = [byte]$this.Type
        $r[1] = [byte]$this.HashAlgorithm
        [Array]::Copy($this.Salt, 0, $r, 2, 16)
        $r[18] = [byte]$this.Argon2MemoryExponent
        $r[19] = [byte]$this.Argon2Passes
        $r[20] = [byte]$this.Argon2Parallelism
        $r; break
      }
    }
    return $res
  }

  [long] GetIterationCount() {
    if ($this.Type -ne [S2KType]::IteratedAndSalted) { return 0 }
    return [S2K]::DecodeIterationCount($this.EncodedCount)
  }
}

class S2K : CryptobaseUtils {
  static [byte[]] SimpleS2K([byte[]]$password, [int]$keySize, [PgpHashAlgorithmId]$hashAlgorithm) {
    return [S2K]::DeriveWithPrefix($password, $keySize, $hashAlgorithm.ToString())
  }

  static [byte[]] SaltedS2K([byte[]]$password, [byte[]]$salt, [int]$keySize, [PgpHashAlgorithmId]$hashAlgorithm) {
    if ($salt.Length -ne 8) { throw [ArgumentException]::new("Salt must be 8 bytes.") }
    $combined = [byte[]]::new($salt.Length + $password.Length)
    [Array]::Copy($salt, 0, $combined, 0, $salt.Length)
    [Array]::Copy($password, 0, $combined, $salt.Length, $password.Length)
    return [S2K]::DeriveWithPrefix($combined, $keySize, $hashAlgorithm.ToString())
  }

  static [byte[]] IteratedS2K([byte[]]$password, [byte[]]$salt, [long]$count, [int]$keySize, [PgpHashAlgorithmId]$hashAlgorithm) {
    if ($salt.Length -ne 8) { throw [ArgumentException]::new("Salt must be 8 bytes.") }
    $combined = [byte[]]::new($salt.Length + $password.Length)
    [Array]::Copy($salt, 0, $combined, 0, $salt.Length)
    [Array]::Copy($password, 0, $combined, $salt.Length, $password.Length)

    if ($count -lt $combined.Length) { $count = $combined.Length }
    return [S2K]::DeriveIteratedKey($combined, $count, $keySize, $hashAlgorithm.ToString())
  }

  static [byte[]] Argon2S2K([byte[]]$password, [byte[]]$salt, [int]$memExp, [int]$passes, [int]$parallelism, [int]$keySize) {
    # Argon2 Memory = 2^exponent KB
    $memKB = [int][Math]::Pow(2, $memExp)
    return [Argon2id]::Hash($password, $salt, $memKB, $passes, $parallelism, $keySize)
  }

  static [byte[]] Derive([byte[]]$password, [PgpS2KSpecifier]$spec, [int]$keySize) {
    $d = $null
    $d = switch ($spec.Type) {
      ([S2KType]::Simple) {
        [S2K]::SimpleS2K($password, $keySize, $spec.HashAlgorithm)
        break
      }
      ([S2KType]::Salted) {
        [S2K]::SaltedS2K($password, $spec.Salt, $keySize, $spec.HashAlgorithm)
        break
      }
      ([S2KType]::IteratedAndSalted) {
        [S2K]::IteratedS2K($password, $spec.Salt, $spec.GetIterationCount(), $keySize, $spec.HashAlgorithm)
        break
      }
      ([S2KType]::Argon2) {
        [S2K]::Argon2S2K($password, $spec.Salt, $spec.Argon2MemoryExponent, $spec.Argon2Passes, $spec.Argon2Parallelism, $keySize)
        break
      }
      default {
        throw [ArgumentException]::new("Unsupported S2K type: $($spec.Type)")
      }
    }
    return $d
  }

  static [long] DecodeIterationCount([byte]$encodedCount) {
    return (16L + ($encodedCount -band 15)) -shl (($encodedCount -shr 4) + 6)
  }

  static [byte] EncodeIterationCount([long]$count) {
    for ($c = 0; $c -le 255; $c++) {
      if ([S2K]::DecodeIterationCount([byte]$c) -ge $count) {
        return [byte]$c
      }
    }
    return 255
  }

  static hidden [byte[]] DeriveWithPrefix([byte[]]$data, [int]$keySize, [string]$hashAlgorithmName) {
    $hashSize = [S2K]::GetHashSize($hashAlgorithmName)
    $result = [byte[]]::new($keySize)
    $offset = 0
    $prefixCount = 0

    while ($offset -lt $keySize) {
      $inputbytes = [byte[]]::new($prefixCount + $data.Length)
      # Zeros are already there
      [Array]::Copy($data, 0, $inputbytes, $prefixCount, $data.Length)

      $hash = [S2K]::HashData($inputbytes, $hashAlgorithmName)
      $copyLen = [Math]::Min($hashSize, $keySize - $offset)
      [Array]::Copy($hash, 0, $result, $offset, $copyLen)

      $offset += $hashSize
      $prefixCount++
    }
    return $result
  }

  static hidden [byte[]] DeriveIteratedKey([byte[]]$combined, [long]$count, [int]$keySize, [string]$hashAlgorithmName) {
    $hashSize = [S2K]::GetHashSize($hashAlgorithmName)
    $result = [byte[]]::new($keySize)
    $offset = 0
    $prefixCount = 0

    while ($offset -lt $keySize) {
      $ih = [IncrementalHash]::CreateHash([HashAlgorithmName]::new($hashAlgorithmName.ToUpperInvariant()))
      if ($prefixCount -gt 0) {
        $ih.AppendData([byte[]]::new($prefixCount))
      }

      $remaining = $count
      while ($remaining -gt 0) {
        $chunk = [int][Math]::Min($remaining, [long]$combined.Length)
        $ih.AppendData($combined, 0, $chunk)
        $remaining -= $chunk
      }

      $hash = $ih.GetHashAndReset()
      $copyLen = [Math]::Min($hashSize, $keySize - $offset)
      [Array]::Copy($hash, 0, $result, $offset, $copyLen)

      $offset += $hashSize
      $prefixCount++
      $ih.Dispose()
    }
    return $result
  }

  static hidden [byte[]] HashData([byte[]]$data, [string]$hashAlgorithmName) {
    $result = $null
    $result = switch ($hashAlgorithmName.ToUpperInvariant()) {
      "SHA256" { [SHA256]::HashData($data); break }
      "SHA384" { [SHA384]::HashData($data); break }
      "SHA512" { [SHA512]::HashData($data); break }
      "SHA1" { [SHA1]::HashData($data); break }
      "MD5" { [MD5]::HashData($data); break }
      default { throw [ArgumentException]::new("Unsupported hash algorithm: $hashAlgorithmName") }
    }
    return $result
  }

  static hidden [int] GetHashSize([string]$hashAlgorithmName) {
    $size = $null
    $size = switch ($hashAlgorithmName.ToUpperInvariant()) {
      "SHA256" { 32; break }
      "SHA384" { 48; break }
      "SHA512" { 64; break }
      "SHA1" { 20; break }
      "MD5" { 16; break }
      default { throw [ArgumentException]::new("Unsupported hash algorithm: $hashAlgorithmName") }
    }
    return $size
  }
}
