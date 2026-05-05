#!/usr/bin/env pwsh
using namespace System
using namespace System.Security.Cryptography
using namespace System.Text

# HKDF (HMAC-based Key Derivation Function) implementation
# RFC 5869 compliant implementation for extracting and expanding keys

class HkdfCore {
  static [int] GetHashLength([string]$hashAlgorithm) {
    $l = 0
    $l = switch ($hashAlgorithm.ToUpper()) {
      "SHA1" { 20; break }
      "SHA256" { 32; break }
      "SHA384" { 48; break }
      "SHA512" { 64; break }
      default { throw [ArgumentException]::new("Unsupported hash algorithm: $hashAlgorithm") }
    }
    return $l
  }

  static [HMAC] CreateHmac([string]$hashAlgorithm, [byte[]]$key) {
    $hmac = $null
    $hmac = switch ($hashAlgorithm.ToUpper()) {
      "SHA1" { [HMACSHA1]::new($key) ; break }
      "SHA256" { [HMACSHA256]::new($key); break }
      "SHA384" { [HMACSHA384]::new($key); break }
      "SHA512" { [HMACSHA512]::new($key); break }
      default { throw [ArgumentException]::new("Unsupported hash algorithm: $hashAlgorithm") }
    }
    return $hmac
  }

  static [void] ValidateParameters([byte[]]$ikm, [int]$length, [string]$hashAlgorithm) {
    if ($null -eq $ikm -or $ikm.Length -eq 0) {
      throw [ArgumentException]::new("Input key material cannot be empty")
    }
    if ($length -le 0) {
      throw [ArgumentException]::new("Length must be positive")
    }
    $hashLength = [HkdfCore]::GetHashLength($hashAlgorithm)
    if ($length -gt 255 * $hashLength) {
      throw [ArgumentException]::new("Length too large for $hashAlgorithm (max: $(255 * $hashLength))")
    }
  }

  static [byte[]] Extract([byte[]]$ikm, [byte[]]$salt, [string]$hashAlgorithm) {
    if ($null -eq $ikm -or $ikm.Length -eq 0) {
      throw [ArgumentException]::new("Input key material cannot be empty")
    }

    $hashLength = [HkdfCore]::GetHashLength($hashAlgorithm)
    $actualSalt = if ($null -eq $salt -or $salt.Length -eq 0) { [byte[]]::new($hashLength) } else { [byte[]]$salt.Clone() }

    $hmac = [HkdfCore]::CreateHmac($hashAlgorithm, $actualSalt)
    try {
      return $hmac.ComputeHash($ikm)
    } finally {
      $hmac.Dispose()
      [Array]::Clear($actualSalt, 0, $actualSalt.Length)
    }
  }

  static [byte[]] Expand([byte[]]$prk, [byte[]]$info, [int]$length, [string]$hashAlgorithm) {
    if ($null -eq $prk -or $prk.Length -eq 0) {
      throw [ArgumentException]::new("Pseudorandom key cannot be empty")
    }
    if ($length -le 0) {
      throw [ArgumentException]::new("Length must be positive")
    }

    $hashLength = [HkdfCore]::GetHashLength($hashAlgorithm)
    if ($length -gt 255 * $hashLength) {
      throw [ArgumentException]::new("Length too large (max: $(255 * $hashLength))")
    }

    $n = [int][Math]::Ceiling($length / $hashLength)
    $okm = [byte[]]::new($length)
    $t = [byte[]]::new(0)

    $hmac = [HkdfCore]::CreateHmac($hashAlgorithm, $prk)
    try {
      for ($i = 1; $i -le $n; $i++) {
        # T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        $temp = [System.IO.MemoryStream]::new()
        if ($t.Length -gt 0) { $temp.Write($t, 0, $t.Length) }
        if ($null -ne $info -and $info.Length -gt 0) { $temp.Write($info, 0, $info.Length) }
        $temp.WriteByte([byte]$i)

        $t = $hmac.ComputeHash($temp.ToArray())
        $temp.Dispose()

        $copyLength = [Math]::Min($hashLength, $length - (($i - 1) * $hashLength))
        [Array]::Copy($t, 0, $okm, ($i - 1) * $hashLength, $copyLength)
      }
      return $okm
    } finally {
      $hmac.Dispose()
      [Array]::Clear($t, 0, $t.Length)
    }
  }

  static [byte[]] DeriveKey([byte[]]$ikm, [byte[]]$salt, [byte[]]$info, [int]$length) {
    return [HkdfCore]::DeriveKey($ikm, $salt, $info, $length, "SHA256")
  }

  static [byte[]] DeriveKey([byte[]]$ikm, [byte[]]$salt, [byte[]]$info, [int]$length, [string]$hashAlgorithm) {
    [HkdfCore]::ValidateParameters($ikm, $length, $hashAlgorithm)

    $prk = [HkdfCore]::Extract($ikm, $salt, $hashAlgorithm)
    try {
      return [HkdfCore]::Expand($prk, $info, $length, $hashAlgorithm)
    } finally {
      [Array]::Clear($prk, 0, $prk.Length)
    }
  }
}

class HkdfBuilder : IDisposable {
  hidden [byte[]] $_ikm
  hidden [byte[]] $_salt
  hidden [byte[]] $_info
  hidden [int] $_outputLength = 32
  hidden [string] $_hashAlgorithm = "SHA256"
  hidden [bool] $_disposed = $false

  HkdfBuilder() {}

  static [HkdfBuilder] Create() { return [HkdfBuilder]::new() }

  [HkdfBuilder] WithInputKeyMaterial([byte[]]$ikm) {
    if ($null -eq $ikm -or $ikm.Length -eq 0) { throw [ArgumentException]::new("IKM cannot be empty") }
    $this.ClearIKM()
    $this._ikm = [byte[]]$ikm.Clone()
    return $this
  }

  [HkdfBuilder] WithInputKeyMaterial([string]$ikm) {
    return $this.WithInputKeyMaterial([Encoding]::UTF8.GetBytes($ikm))
  }

  [HkdfBuilder] WithSalt([byte[]]$salt) {
    $this.ClearSalt()
    $this._salt = if ($null -eq $salt) { $null } else { [byte[]]$salt.Clone() }
    return $this
  }

  [HkdfBuilder] WithRandomSalt() {
    $this.ClearSalt()
    $hashLen = [HkdfCore]::GetHashLength($this._hashAlgorithm)
    $this._salt = [byte[]]::new($hashLen)
    [RandomNumberGenerator]::Fill($this._salt)
    return $this
  }

  [HkdfBuilder] WithInfo([byte[]]$info) {
    $this.ClearInfo()
    $this._info = if ($null -eq $info) { $null } else { [byte[]]$info.Clone() }
    return $this
  }

  [HkdfBuilder] WithInfo([string]$info) {
    return $this.WithInfo([Encoding]::UTF8.GetBytes($info))
  }

  [HkdfBuilder] WithOutputLength([int]$length) {
    if ($length -le 0) { throw [ArgumentException]::new("Output length must be positive") }
    $this._outputLength = $length
    return $this
  }

  [HkdfBuilder] WithHashAlgorithm([string]$hashAlgorithm) {
    [void][HkdfCore]::GetHashLength($hashAlgorithm) # Validate
    $this._hashAlgorithm = $hashAlgorithm
    return $this
  }

  [HkdfBuilder] WithGeneralPurposePreset() {
    $this._hashAlgorithm = "SHA256"
    return $this
  }

  [HkdfBuilder] WithHighSecurityPreset() {
    $this._hashAlgorithm = "SHA512"
    $this._outputLength = 64
    return $this
  }

  [HkdfBuilder] WithTlsPreset() {
    $this._hashAlgorithm = "SHA256"
    return $this
  }

  [byte[]] DeriveKey() {
    if ($this._disposed) { throw [ObjectDisposedException]::new("HkdfBuilder") }
    if ($null -eq $this._ikm) { throw [InvalidOperationException]::new("IKM not set") }
    return [HkdfCore]::DeriveKey($this._ikm, $this._salt, $this._info, $this._outputLength, $this._hashAlgorithm)
  }

  [byte[]] Extract() {
    if ($this._disposed) { throw [ObjectDisposedException]::new("HkdfBuilder") }
    if ($null -eq $this._ikm) { throw [InvalidOperationException]::new("IKM not set") }
    return [HkdfCore]::Extract($this._ikm, $this._salt, $this._hashAlgorithm)
  }

  [byte[]] Expand([byte[]]$prk) {
    if ($this._disposed) { throw [ObjectDisposedException]::new("HkdfBuilder") }
    return [HkdfCore]::Expand($prk, $this._info, $this._outputLength, $this._hashAlgorithm)
  }

  [byte[]] GetSalt() {
    return if ($null -eq $this._salt) { $null } else { [byte[]]$this._salt.Clone() }
  }

  hidden [void] ClearIKM() {
    if ($null -ne $this._ikm) { [Array]::Clear($this._ikm, 0, $this._ikm.Length); $this._ikm = $null }
  }
  hidden [void] ClearSalt() {
    if ($null -ne $this._salt) { [Array]::Clear($this._salt, 0, $this._salt.Length); $this._salt = $null }
  }
  hidden [void] ClearInfo() {
    if ($null -ne $this._info) { [Array]::Clear($this._info, 0, $this._info.Length); $this._info = $null }
  }

  [void] Dispose() {
    if (-not $this._disposed) {
      $this.ClearIKM()
      $this.ClearSalt()
      $this.ClearInfo()
      $this._disposed = $true
    }
  }
}