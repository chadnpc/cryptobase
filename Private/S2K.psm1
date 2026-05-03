#!/usr/bin/env pwsh
using namespace System
using namespace System.Collections.Generic
using namespace System.Security.Cryptography

using module ./Utilities.psm1

enum S2KType : byte {
  Simple = 0
  Salted = 1
  Reserved = 2
  IteratedAndSalted = 3
  Argon2 = 4
}

class S2K : CryptobaseUtils {
  static [byte[]] SimpleS2K([byte[]]$password, [int]$keySize, [string]$hashAlgorithm) {
    return [S2K]::DeriveWithPrefix($password, $keySize, $hashAlgorithm)
  }

  static [byte[]] SaltedS2K([byte[]]$password, [byte[]]$salt, [int]$keySize, [string]$hashAlgorithm) {
    if ($salt.Length -ne 8) { throw [ArgumentException]::new("Salt must be 8 bytes.") }
    $combined = [byte[]]::new($salt.Length + $password.Length)
    [Array]::Copy($salt, 0, $combined, 0, $salt.Length)
    [Array]::Copy($password, 0, $combined, $salt.Length, $password.Length)
    return [S2K]::DeriveWithPrefix($combined, $keySize, $hashAlgorithm)
  }

  static [byte[]] IteratedS2K([byte[]]$password, [byte[]]$salt, [long]$count, [int]$keySize, [string]$hashAlgorithm) {
    if ($salt.Length -ne 8) { throw [ArgumentException]::new("Salt must be 8 bytes.") }
    $combined = [byte[]]::new($salt.Length + $password.Length)
    [Array]::Copy($salt, 0, $combined, 0, $salt.Length)
    [Array]::Copy($password, 0, $combined, $salt.Length, $password.Length)

    if ($count -lt $combined.Length) { $count = $combined.Length }
    return [S2K]::DeriveIteratedKey($combined, $count, $keySize, $hashAlgorithm)
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
      $ih = [IncrementalHash]::CreateHash([HashAlgorithmName]::new($hashAlgorithmName))
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
    switch ($hashAlgorithmName.ToUpperInvariant()) {
      "SHA256" { $result = [SHA256]::HashData($data) }
      "SHA384" { $result = [SHA384]::HashData($data) }
      "SHA512" { $result = [SHA512]::HashData($data) }
      "SHA1" { $result = [SHA1]::HashData($data) }
      "MD5" { $result = [MD5]::HashData($data) }
      default { throw [ArgumentException]::new("Unsupported hash algorithm: $hashAlgorithmName") }
    }
    return $result
  }

  static hidden [int] GetHashSize([string]$hashAlgorithmName) {
    $result = $null
    switch ($hashAlgorithmName.ToUpperInvariant()) {
      "SHA256" { $result = 32 }
      "SHA384" { $result = 48 }
      "SHA512" { $result = 64 }
      "SHA1" { $result = 20 }
      "MD5" { $result = 16 }
      default { throw [ArgumentException]::new("Unsupported hash algorithm: $hashAlgorithmName") }
    }
    return $result
  }
}

