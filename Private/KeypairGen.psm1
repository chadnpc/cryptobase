#!/usr/bin/env pwsh
using namespace System.Security
using namespace System.Security.Cryptography

using module ./Exceptions.psm1

#region KeypairGen_Dataclasses

class Keypair {
  [AsymmetricAlgorithm] $Algorithm
  [byte[]] $PublicKey
  [byte[]] $PrivateKey
  [int] $KeySize
  [datetime] $CreatedAt
  [string] $CurveName
  [hashtable] $Parameters

  Keypair() {
    $this.CreatedAt = [datetime]::UtcNow
    $this.Parameters = @{}
  }

  Keypair([AsymmetricAlgorithm]$algorithm) {
    $this.Algorithm = $algorithm
    $this.CreatedAt = [datetime]::UtcNow
    $this.Parameters = @{}
  }

  [string] ToBase64Public() {
    if ($null -eq $this.PublicKey) { return $null }
    return [Convert]::ToBase64String($this.PublicKey)
  }

  [string] ToBase64Private() {
    if ($null -eq $this.PrivateKey) { return $null }
    return [Convert]::ToBase64String($this.PrivateKey)
  }

  [string] ToHexPublic() {
    if ($null -eq $this.PublicKey) { return $null }
    return [KeypairHelper]::BytesToHex($this.PublicKey)
  }

  [string] ToHexPrivate() {
    if ($null -eq $this.PrivateKey) { return $null }
    return [KeypairHelper]::BytesToHex($this.PrivateKey)
  }

  [System.Security.SecureString] ToSecureStringPrivate() {
    if ($null -eq $this.PrivateKey) { return $null }
    return [KeypairHelper]::ToSecureString($this.PrivateKey)
  }

  [int] GetKeySizeInBits() {
    if ($this.KeySize -gt 0) { return $this.KeySize }
    if ($null -ne $this.PublicKey -and $this.PublicKey.Length -gt 0) { return $this.PublicKey.Length * 8 }
    if ($null -ne $this.PrivateKey -and $this.PrivateKey.Length -gt 0) { return $this.PrivateKey.Length * 8 }
    return 0
  }

  [bool] HasPrivateKey() {
    return $null -ne $this.PrivateKey -and $this.PrivateKey.Length -gt 0
  }

  [bool] HasPublicKey() {
    return $null -ne $this.PublicKey -and $this.PublicKey.Length -gt 0
  }

  [hashtable] ToHashtable() {
    return @{
      Algorithm        = $this.Algorithm.ToString()
      PublicKeyBase64  = $this.ToBase64Public()
      PrivateKeyBase64 = $this.ToBase64Private()
      KeySize          = $this.KeySize
      CreatedAt        = $this.CreatedAt.ToString('o')
      CurveName        = $this.CurveName
      Parameters       = $this.Parameters
    }
  }

  static [Keypair] FromHashtable([hashtable]$data) {
    if ($null -eq $data) { throw [System.ArgumentNullException]::new('data') }

    $kp = [Keypair]::new()
    if ($data.ContainsKey('Algorithm') -and $null -ne $data.Algorithm) {
      $kp.Algorithm = [AsymmetricAlgorithm]::Parse([AsymmetricAlgorithm], [string]$data.Algorithm)
    }

    if ($data.ContainsKey('KeySize')) { $kp.KeySize = [int]$data.KeySize }
    if ($data.ContainsKey('CreatedAt') -and $data.CreatedAt) { $kp.CreatedAt = [datetime]::Parse([string]$data.CreatedAt) }
    if ($data.ContainsKey('CurveName')) { $kp.CurveName = [string]$data.CurveName }
    if ($data.ContainsKey('Parameters') -and $data.Parameters -is [hashtable]) { $kp.Parameters = $data.Parameters }

    if ($data.ContainsKey('PublicKeyBase64') -and $data.PublicKeyBase64) {
      $kp.PublicKey = [Convert]::FromBase64String([string]$data.PublicKeyBase64)
    }

    if ($data.ContainsKey('PrivateKeyBase64') -and $data.PrivateKeyBase64) {
      $kp.PrivateKey = [Convert]::FromBase64String([string]$data.PrivateKeyBase64)
    }

    return $kp
  }

  [string] ToString() {
    return "Keypair[Algorithm=$($this.Algorithm), KeySize=$($this.KeySize), Curve=$($this.CurveName)]"
  }
}

class NamedKeypair : Keypair {
  [string] $Name
  [string] $Description
  [string[]] $Tags
  [string] $Owner
  [datetime] $ExpiresAt

  NamedKeypair() : base() {
    $this.Tags = @()
  }

  NamedKeypair([AsymmetricAlgorithm]$algorithm, [string]$name) : base($algorithm) {
    $this.Name = $name
    $this.Tags = @()
  }

  [bool] IsExpired() {
    if ($null -eq $this.ExpiresAt) { return $false }
    return [datetime]::UtcNow -gt $this.ExpiresAt
  }

  [void] AddTag([string]$tag) {
    if ([string]::IsNullOrWhiteSpace($tag)) { return }
    if ($null -eq $this.Tags) { $this.Tags = @() }
    if ($this.Tags -notcontains $tag) { $this.Tags += $tag }
  }

  [void] RemoveTag([string]$tag) {
    if ($null -eq $this.Tags) { return }
    $this.Tags = @($this.Tags | Where-Object { $_ -ne $tag })
  }
}

class KeypairGenerationResult {
  [bool] $Success
  [Keypair] $Keypair
  [string] $ErrorMessage
  [string[]] $Warnings
  [TimeSpan] $Duration
  [datetime] $GeneratedAt

  KeypairGenerationResult() {
    $this.Warnings = @()
    $this.GeneratedAt = [datetime]::UtcNow
  }

  static [KeypairGenerationResult] Successful([Keypair]$keypair, [TimeSpan]$duration) {
    $result = [KeypairGenerationResult]::new()
    $result.Success = $true
    $result.Keypair = $keypair
    $result.Duration = $duration
    return $result
  }

  static [KeypairGenerationResult] Failed([string]$errorMessage, [TimeSpan]$duration) {
    $result = [KeypairGenerationResult]::new()
    $result.Success = $false
    $result.ErrorMessage = $errorMessage
    $result.Duration = $duration
    return $result
  }

  [void] AddWarning([string]$warning) {
    if ([string]::IsNullOrWhiteSpace($warning)) { return }
    $this.Warnings += $warning
  }
}

#endregion


#region KeypairGen_UtilityClasses

class KeypairHelper {
  static [byte[]] HexToBytes([string]$hex) {
    if ([string]::IsNullOrWhiteSpace($hex)) { return [byte[]]@() }
    if ($hex.StartsWith('0x')) { $hex = $hex.Substring(2) }
    if (($hex.Length % 2) -ne 0) { throw [System.FormatException]::new('Hex string must contain an even number of characters.') }

    $bytes = [byte[]]::new($hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
      $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    return $bytes
  }

  static [string] BytesToHex([byte[]]$bytes) {
    if ($null -eq $bytes) { return $null }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
  }

  static [string] BytesToBase64([byte[]]$bytes) {
    if ($null -eq $bytes) { return $null }
    return [Convert]::ToBase64String($bytes)
  }

  static [byte[]] Base64ToBytes([string]$base64) {
    if ([string]::IsNullOrWhiteSpace($base64)) { return [byte[]]@() }
    return [Convert]::FromBase64String($base64)
  }

  static [System.Security.SecureString] ToSecureString([byte[]]$bytes) {
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    return [xconvert]::ToSecurestring($text)
  }

  static [byte[]] FromSecureString([System.Security.SecureString]$secureString) {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    try {
      $text = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
      return [System.Text.Encoding]::UTF8.GetBytes($text)
    } finally {
      [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
  }

  static [int] GetKeySizeForCurve([string]$curveName) {
    if ([string]::IsNullOrWhiteSpace($curveName)) { return 0 }
    $s = switch ($curveName.ToLowerInvariant()) {
      'secp256k1' { 256; break }
      'secp256r1' { 256; break }
      'secp384r1' { 384; break }
      'secp521r1' { 521; break }
      'ed25519' { 256; break }
      'ed448' { 448; break }
      'x25519' { 256; break }
      'x448' { 448; break }
      default { return 0 }
    }
    return $s
  }

  static [bool] IsSupportedAlgorithm([AsymmetricAlgorithm]$algorithm) {
    $unsupported = @(
      [AsymmetricAlgorithm]::KYBER,
      [AsymmetricAlgorithm]::DILITHIUM,
      [AsymmetricAlgorithm]::SPHINCS,
      [AsymmetricAlgorithm]::ELGAMAL,
      [AsymmetricAlgorithm]::X25519,
      [AsymmetricAlgorithm]::X448,
      [AsymmetricAlgorithm]::CURVE25519
    )

    return $unsupported -notcontains $algorithm
  }
}

#endregion

#region KeypairGen_mainclass
# .SYNOPSIS
#   KeypairGenerator class library for PowerShell.
# .EXAMPLE
# # Generate an RSA keypair
# $rsa = [KeypairGen]::Generate([AsymmetricAlgorithm]::RSA, 2048)
# $rsa.ToBase64Public()
# # Generate ECDSA keypair
# $ecdsa = [KeypairGen]::Generate([AsymmetricAlgorithm]::ECDSA, 256, 'secp256r1')
# # Use manager
# $manager = [KeypairManager]::new()
# $manager.Add('signing', $rsa)
# $manager.Get('signing')
# .Notes
# - Post-quantum and some curve algorithms listed in `AsymmetricAlgorithm` are placeholders for future implementation.
# - Current implementation focuses on stable .NET-backed algorithms and class-based API completeness.
class KeypairGen {
  static [bool] $VerboseOutput = $false

  static [Keypair] Generate([AsymmetricAlgorithm]$Algorithm) {
    return [KeypairGen]::Generate($Algorithm, 0, $null)
  }

  static [Keypair] Generate([AsymmetricAlgorithm]$Algorithm, [int]$KeySize) {
    return [KeypairGen]::Generate($Algorithm, $KeySize, $null)
  }

  static [Keypair] Generate([AsymmetricAlgorithm]$Algorithm, [int]$KeySize, [string]$Curve) {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew(); $kp = $null
    try {
      $resolvedCurve = $Curve

      $kp = switch ($Algorithm) {
        ([AsymmetricAlgorithm]::RSA) {
          $size = if ($KeySize -gt 0) { $KeySize } else { 2048 }
          [KeypairGen]::GenerateRSA($size)
          break
        }
        ([AsymmetricAlgorithm]::DSA) {
          $size = if ($KeySize -gt 0) { $KeySize } else { 2048 }
          [KeypairGen]::GenerateDSA($size)
          break
        }
        ([AsymmetricAlgorithm]::DIFFIE_HELLMAN) {
          $size = if ($KeySize -gt 0) { $KeySize } else { 2048 }
          [KeypairGen]::GenerateDiffieHellman($size)
          break
        }
        ([AsymmetricAlgorithm]::ECDSA) {
          if ([string]::IsNullOrWhiteSpace($resolvedCurve)) {
            $resolvedCurve = if ($KeySize -ge 384) { 'secp384r1' } else { 'secp256r1' }
          }
          [KeypairGen]::GenerateECDsa($resolvedCurve)
          break
        }
        ([AsymmetricAlgorithm]::ECDH) {
          if ([string]::IsNullOrWhiteSpace($resolvedCurve)) {
            $resolvedCurve = if ($KeySize -ge 384) { 'secp384r1' } else { 'secp256r1' }
          }
          [KeypairGen]::GenerateECDH($resolvedCurve)
          break
        }
        ([AsymmetricAlgorithm]::SECP256K1) { [KeypairGen]::GenerateECDH('secp256k1'); break }
        ([AsymmetricAlgorithm]::SECP256R1) { [KeypairGen]::GenerateECDsa('secp256r1'); break }
        ([AsymmetricAlgorithm]::SECP384R1) { [KeypairGen]::GenerateECDsa('secp384r1'); break }
        ([AsymmetricAlgorithm]::SECP521R1) { [KeypairGen]::GenerateECDsa('secp521r1'); break }
        ([AsymmetricAlgorithm]::ED25519) { [KeypairGen]::GenerateEdCurve('ed25519'); break }
        ([AsymmetricAlgorithm]::ED448) { [KeypairGen]::GenerateEdCurve('ed448'); break }
        default {
          throw [KeyGenerationException]::new("Algorithm '$Algorithm' is not currently implemented in this library-only module.", $Algorithm)
        }
      }
    } catch {
      throw [KeyGenerationException]::new("Failed to generate keypair for $Algorithm : $($_.Exception.Message)", $Algorithm)
    } finally {
      $stopwatch.Stop()
      if ([KeypairGen]::VerboseOutput) {
        Write-Verbose "Generated $Algorithm keypair in $($stopwatch.ElapsedMilliseconds)ms"
      }
    }
    return $kp
  }

  static [KeypairGenerationResult] GenerateWithResult([AsymmetricAlgorithm]$Algorithm, [int]$KeySize, [string]$Curve) {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
      $kp = [KeypairGen]::Generate($Algorithm, $KeySize, $Curve)
      $stopwatch.Stop()
      return [KeypairGenerationResult]::Successful($kp, $stopwatch.Elapsed)
    } catch {
      $stopwatch.Stop()
      return [KeypairGenerationResult]::Failed($_.Exception.Message, $stopwatch.Elapsed)
    }
  }

  static [KeypairGenerationResult] GenerateWithResult([AsymmetricAlgorithm]$Algorithm) {
    return [KeypairGen]::GenerateWithResult($Algorithm, 0, $null)
  }

  static [Keypair] GenerateRSA([int]$keySize) {
    $rsa = [System.Security.Cryptography.RSA]::Create($keySize)
    try {
      $kp = [Keypair]::new([AsymmetricAlgorithm]::RSA)
      $kp.KeySize = $keySize
      $kp.PublicKey = $rsa.ExportRSAPublicKey()
      $kp.PrivateKey = $rsa.ExportRSAPrivateKey()
      return $kp
    } finally {
      $rsa.Dispose()
    }
  }

  static [Keypair] GenerateDSA([int]$keySize) {
    $dsa = [System.Security.Cryptography.DSA]::Create($keySize)
    try {
      $kp = [Keypair]::new([AsymmetricAlgorithm]::DSA)
      $kp.KeySize = $keySize
      $kp.PublicKey = $dsa.ExportSubjectPublicKeyInfo()
      $kp.PrivateKey = $dsa.ExportPkcs8PrivateKey()
      return $kp
    } finally {
      $dsa.Dispose()
    }
  }

  static [Keypair] GenerateDiffieHellman([int]$keySize) {
    $dh = [System.Security.Cryptography.ECDiffieHellman]::Create()
    try {
      $dh.KeySize = $keySize
      $kp = [Keypair]::new([AsymmetricAlgorithm]::DIFFIE_HELLMAN)
      $kp.KeySize = $keySize
      $kp.PublicKey = $dh.ExportSubjectPublicKeyInfo()
      $kp.PrivateKey = $dh.ExportPkcs8PrivateKey()
      return $kp
    } finally {
      $dh.Dispose()
    }
  }

  static [Keypair] GenerateECDsa([string]$curveName) {
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName($curveName))
    try {
      $kp = [Keypair]::new([AsymmetricAlgorithm]::ECDSA)
      $kp.CurveName = $curveName
      $kp.KeySize = [KeypairHelper]::GetKeySizeForCurve($curveName)
      $kp.PublicKey = $ecdsa.ExportSubjectPublicKeyInfo()
      $kp.PrivateKey = $ecdsa.ExportPkcs8PrivateKey()
      return $kp
    } finally {
      $ecdsa.Dispose()
    }
  }

  static [Keypair] GenerateECDH([string]$curveName) {
    $ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName($curveName))
    try {
      $kp = [Keypair]::new([AsymmetricAlgorithm]::ECDH)
      $kp.CurveName = $curveName
      $kp.KeySize = [KeypairHelper]::GetKeySizeForCurve($curveName)
      $kp.PublicKey = $ecdh.ExportSubjectPublicKeyInfo()
      $kp.PrivateKey = $ecdh.ExportPkcs8PrivateKey()
      return $kp
    } finally {
      $ecdh.Dispose()
    }
  }

  static [Keypair] GenerateEdCurve([string]$curveName) {
    $isEd448   = $curveName -ieq 'ed448'
    $algorithm = if ($isEd448) { [AsymmetricAlgorithm]::ED448 } else { [AsymmetricAlgorithm]::ED25519 }
    $typeName  = if ($isEd448) {
      "System.Security.Cryptography.Ed448, System.Security.Cryptography"
    } else {
      "System.Security.Cryptography.Ed25519, System.Security.Cryptography"
    }

    $edType = [System.type]::GetType($typeName)
    if ($null -ne $edType) {
      $ed = $edType::new()
      try {
        $kp = [Keypair]::new($algorithm)
        $kp.CurveName  = $curveName
        $kp.KeySize    = [KeypairHelper]::GetKeySizeForCurve($curveName)
        $kp.PublicKey  = $ed.ExportSubjectPublicKeyInfo()
        $kp.PrivateKey = $ed.ExportPkcs8PrivateKey()
        return $kp
      } finally {
        $ed.Dispose()
      }
    }

    # For Ed25519 without .NET 8: generate a random seed as PrivateKey.
    # Callers should use [Ed25519]::new().GenerateKeyPair() for full key pair with public key.
    if (-not $isEd448) {
      $seed = [byte[]]::new(32)
      [System.Security.Cryptography.RandomNumberGenerator]::Fill($seed)
      $kp = [Keypair]::new([AsymmetricAlgorithm]::ED25519)
      $kp.CurveName  = 'ed25519'
      $kp.KeySize    = 256
      $kp.PrivateKey = $seed
      # PublicKey will be $null here; use [Ed25519]::GetPublicKey() to derive it
      return $kp
    }

    throw [System.PlatformNotSupportedException]::new("$curveName requires .NET 8+ or external library")
  }

  static [object[]] GetAlgorithmInfo() {
    return @(
      [pscustomobject]@{ Name = 'RSA'; Native = $true; KeySizes = @(1024, 2048, 3072, 4096) },
      [pscustomobject]@{ Name = 'DSA'; Native = $true; KeySizes = @(1024, 2048, 3072) },
      [pscustomobject]@{ Name = 'DIFFIE_HELLMAN'; Native = $true; KeySizes = @(1024, 2048, 3072, 4096) },
      [pscustomobject]@{ Name = 'ECDSA'; Native = $true; Curves = @('secp256r1', 'secp384r1', 'secp521r1') },
      [pscustomobject]@{ Name = 'ECDH'; Native = $true; Curves = @('secp256k1', 'secp256r1', 'secp384r1', 'secp521r1') },
      [pscustomobject]@{ Name = 'ED25519'; Native = $true; Curves = @('ed25519') },
      [pscustomobject]@{ Name = 'ED448'; Native = $true; Curves = @('ed448') },
      [pscustomobject]@{ Name = 'X25519'; Native = $false; Notes = 'Not implemented in this module yet' },
      [pscustomobject]@{ Name = 'X448'; Native = $false; Notes = 'Not implemented in this module yet' },
      [pscustomobject]@{ Name = 'KYBER'; Native = $false; Notes = 'Requires external post-quantum library' }
    )
  }
  static [void] TestKeypairGenerator() {
    # Basic smoke tests for KeypairGenerator class library.
    Write-Host '--- KeypairGenerator Smoke Tests ---'

    $rsa = [KeypairGen]::Generate([AsymmetricAlgorithm]::RSA, 2048)
    Write-Host "RSA: $($rsa.Algorithm), size=$($rsa.KeySize), hasPrivate=$($rsa.HasPrivateKey())"

    $ecdsa = [KeypairGen]::Generate([AsymmetricAlgorithm]::ECDSA, 256, 'secp256r1')
    Write-Host "ECDSA: curve=$($ecdsa.CurveName), pubLen=$($ecdsa.PublicKey.Length)"

    $result = [KeypairGen]::GenerateWithResult([AsymmetricAlgorithm]::DSA)
    Write-Host "GenerateWithResult success=$($result.Success), durationMs=$($result.Duration.TotalMilliseconds)"

    $named = [NamedKeypair]::new([AsymmetricAlgorithm]::RSA, 'demo')
    $named.Description = 'Demo key'
    $named.AddTag('demo')
    $named.PublicKey = $rsa.PublicKey
    $named.PrivateKey = $rsa.PrivateKey
    $named.KeySize = $rsa.KeySize
    Write-Host "Named: name=$($named.Name), tags=$($named.Tags -join ',')"

    $mgr = [KeypairManager]::new()
    $mgr.Add('rsa', $rsa)
    $mgr.Add('ecdsa', $ecdsa)
    Write-Host "Manager count=$($mgr.GetNames().Count), contains-rsa=$($mgr.Contains('rsa'))"
    Write-Host 'All smoke tests completed.'
  }
}

#endregion

#region KeypairGen_Manager

class KeypairManager {
  [hashtable] $Keypairs
  [string] $DefaultPath

  KeypairManager() {
    $this.Keypairs = @{}
  }

  KeypairManager([string]$path) {
    $this.Keypairs = @{}
    $this.DefaultPath = $path
  }

  [void] Add([string]$name, [Keypair]$keypair) {
    if ([string]::IsNullOrWhiteSpace($name)) { throw [System.ArgumentException]::new('Name cannot be empty.', 'name') }
    if ($null -eq $keypair) { throw [System.ArgumentNullException]::new('keypair') }
    $this.Keypairs[$name] = $keypair
  }

  [void] Remove([string]$name) {
    if ($this.Keypairs.ContainsKey($name)) { [void]$this.Keypairs.Remove($name) }
  }

  [Keypair] Get([string]$name) {
    if (-not $this.Keypairs.ContainsKey($name)) { return $null }
    return [Keypair]$this.Keypairs[$name]
  }

  [bool] Contains([string]$name) {
    return $this.Keypairs.ContainsKey($name)
  }

  [string[]] GetNames() {
    return [string[]]$this.Keypairs.Keys
  }

  [Keypair[]] GetAllByAlgorithm([AsymmetricAlgorithm]$algorithm) {
    $result = New-Object System.Collections.Generic.List[Keypair]
    foreach ($kp in $this.Keypairs.Values) {
      if ($kp.Algorithm -eq $algorithm) {
        [void]$result.Add([Keypair]$kp)
      }
    }
    return $result.ToArray()
  }

  [void] Save([string]$path) {
    $target = if ([string]::IsNullOrWhiteSpace($path)) { $this.DefaultPath } else { $path }
    if ([string]::IsNullOrWhiteSpace($target)) { throw [System.ArgumentException]::new('Path is required.', 'path') }

    $data = @{}
    foreach ($entry in $this.Keypairs.GetEnumerator()) {
      $data[$entry.Key] = $entry.Value.ToHashtable()
    }

    $data | ConvertTo-Json -Depth 20 | Set-Content -Path $target -Encoding UTF8
  }

  [void] Load([string]$path) {
    $target = if ([string]::IsNullOrWhiteSpace($path)) { $this.DefaultPath } else { $path }
    if ([string]::IsNullOrWhiteSpace($target)) { throw [System.ArgumentException]::new('Path is required.', 'path') }
    if (-not (Test-Path -Path $target)) { throw [System.IO.FileNotFoundException]::new("File not found: $target") }

    $json = Get-Content -Path $target -Raw
    $content = ConvertFrom-Json -InputObject $json -AsHashtable

    foreach ($name in $content.Keys) {
      $this.Keypairs[$name] = [Keypair]::FromHashtable([hashtable]$content[$name])
    }
  }
}

#endregion
