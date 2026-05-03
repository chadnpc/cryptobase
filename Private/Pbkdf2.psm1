#!/usr/bin/env pwsh
using namespace System
using namespace System.Collections.Generic
using namespace System.Security.Cryptography

using module ./Utilities.psm1

class Pbkdf2 : CryptobaseUtils {
  static [byte[]] DeriveKey([byte[]]$password, [byte[]]$salt, [int]$iterations, [int]$outputLength, [string]$hashAlgorithm) {
    if ($null -eq $password) { throw [ArgumentNullException]::new("password") }
    if ($null -eq $salt) { throw [ArgumentNullException]::new("salt") }
    if ($iterations -lt 1) { throw [ArgumentException]::new("Iterations must be positive") }
    if ($outputLength -le 0) { throw [ArgumentException]::new("Output length must be positive") }

    $alg = [HashAlgorithmName]::new($hashAlgorithm)
    return [Rfc2898DeriveBytes]::Pbkdf2($password, $salt, $iterations, $alg, $outputLength)
  }

  static [byte[]] DeriveKey([string]$password, [byte[]]$salt, [int]$iterations, [int]$outputLength, [string]$hashAlgorithm) {
    if ([string]::IsNullOrEmpty($password)) { throw [ArgumentException]::new("Password cannot be null or empty") }
    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($password)
    try {
      return [Pbkdf2]::DeriveKey($passwordBytes, $salt, $iterations, $outputLength, $hashAlgorithm)
    } finally {
      [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
    }
  }
}

