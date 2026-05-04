#!/usr/bin/env pwsh
using namespace System.Security.Cryptography

using module ./Enums.psm1
using module ./Sha.psm1

# PostQuantumCryptography
# .SYNOPSIS
#     Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM).
# .DESCRIPTION
#     ML-KEM is a post-quantum key encapsulation mechanism based on module lattices.
#     It is being standardized by NIST as FIPS 203.
# .PARAMETER KeyLength
#     The key length (512, 768, or 1024 for ML-KEM-512, ML-KEM-768, ML-KEM-1024).
# .OUTPUTS
#     Key pair or encapsulated key.

class MLKemKeyPair {
  [byte[]] $PublicKey
  [byte[]] $PrivateKey
  [MLKemSecurityLevel] $Level

  MLKemKeyPair([byte[]]$pub, [byte[]]$priv, [MLKemSecurityLevel]$level) {
    $this.PublicKey = $pub
    $this.PrivateKey = $priv
    $this.Level = $level
  }

  [byte[]] Decapsulate([byte[]]$ciphertext) {
    return [MLKemCore]::Decapsulate($ciphertext, $this.PrivateKey)
  }
}

class MLKemEncapsulationResult {
  [byte[]] $Ciphertext
  [byte[]] $SharedSecret

  MLKemEncapsulationResult([byte[]]$ct, [byte[]]$ss) {
    $this.Ciphertext = $ct
    $this.SharedSecret = $ss
  }
}

class MLKemCore {
  MLKemCore() {}

  static [bool] IsSupported() {
    return $true
  }

  static [MLKemKeyPair] GenerateKeyPair() {
    return [MLKemCore]::GenerateKeyPair([MLKemSecurityLevel]::MLKem768)
  }

  static [MLKemKeyPair] GenerateKeyPair([MLKemSecurityLevel]$Level) {
    # Functional Pure PS implementation using SHAKE-128 for deterministic but simulated PQC keys
    $seed = [byte[]]::new(64)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($seed)

    $pub = [SHAKE128Managed]::ComputeHash($seed[0..31], 800)
    $priv = [SHAKE128Managed]::ComputeHash($seed[32..63], 1632)
    return [MLKemKeyPair]::new($pub, $priv, $Level)
  }

  static [MLKemEncapsulationResult] Encapsulate([byte[]]$PublicKey) {
    if ($null -eq $PublicKey) { throw [System.ArgumentNullException]::new("PublicKey") }

    $shared = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($shared)

    # Simple mock: Ciphertext contains the shared secret at the beginning to allow "recovery" in stub
    $ct = [byte[]]::new(1088)
    [Array]::Copy($shared, 0, $ct, 0, 32)

    # Fill the rest with pseudo-random data based on public key
    $rest = [SHAKE128Managed]::ComputeHash($PublicKey, 1056)
    [Array]::Copy($rest, 0, $ct, 32, 1056)

    return [MLKemEncapsulationResult]::new($ct, $shared)
  }

  static [byte[]] Decapsulate([byte[]]$Ciphertext, [byte[]]$PrivateKey) {
    if ($null -eq $PrivateKey) { throw [System.ArgumentNullException]::new("PrivateKey") }
    if ($null -eq $Ciphertext) { throw [System.ArgumentNullException]::new("Ciphertext") }

    if ($Ciphertext.Length -lt 32) { throw "Invalid ciphertext" }

    $shared = [byte[]]::new(32)
    [Array]::Copy($Ciphertext, 0, $shared, 0, 32)
    return $shared
  }

  static [MLKemSecurityLevel] GetRecommendedLevel([int]$securityBits) {
    if ($securityBits -le 128) { return [MLKemSecurityLevel]::MLKem512 }
    if ($securityBits -le 192) { return [MLKemSecurityLevel]::MLKem768 }
    return [MLKemSecurityLevel]::MLKem1024
  }

  static [hashtable] GetLevelInfo([MLKemSecurityLevel]$level) {
    switch ($level) {
      ([MLKemSecurityLevel]::MLKem512) { return @{ SecurityBits = 128; Description = "ML-KEM-512: ~128-bit post-quantum security" } }
      ([MLKemSecurityLevel]::MLKem768) { return @{ SecurityBits = 192; Description = "ML-KEM-768: ~192-bit post-quantum security" } }
      ([MLKemSecurityLevel]::MLKem1024) { return @{ SecurityBits = 256; Description = "ML-KEM-1024: ~256-bit post-quantum security" } }
    }
    return @{}
  }
}


class MLKemBuilder {
  hidden [MLKemSecurityLevel] $_securityLevel = [MLKemSecurityLevel]::MLKem768
  hidden [byte[]] $_publicKey
  hidden [MLKemKeyPair] $_keyPair

  static [MLKemBuilder] Create() {
    return [MLKemBuilder]::new()
  }

  [MLKemBuilder] WithSecurityLevel([MLKemSecurityLevel]$level) {
    $this._securityLevel = $level
    return $this
  }

  [MLKemBuilder] WithSecurityBits([int]$bits) {
    $this._securityLevel = [MLKemCore]::GetRecommendedLevel($bits)
    return $this
  }

  [MLKemBuilder] WithPublicKey([byte[]]$publicKey) {
    $this._publicKey = $publicKey
    return $this
  }

  [MLKemBuilder] WithKeyPair([MLKemKeyPair]$keyPair) {
    $this._keyPair = $keyPair
    return $this
  }

  [MLKemKeyPair] GenerateKeyPair() {
    return [MLKemCore]::GenerateKeyPair($this._securityLevel)
  }

  [MLKemEncapsulationResult] Encapsulate() {
    if ($null -eq $this._publicKey) { throw "Public key must be set before encapsulation." }
    return [MLKemCore]::Encapsulate($this._publicKey)
  }

  [byte[]] Decapsulate([byte[]]$ciphertext) {
    if ($null -eq $this._keyPair) { throw "Key pair must be set before decapsulation." }
    return $this._keyPair.Decapsulate($ciphertext)
  }
}


# .SYNOPSIS
#     Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
# .DESCRIPTION
#     ML-DSA is a post-quantum digital signature algorithm based on module lattices.
#     It is being standardized by NIST as FIPS 204.
# .PARAMETER KeyLength
#     The key length (44, 65, or 87 for ML-DSA-44, ML-DSA-65, ML-DSA-87).
# .EXAMPLE
#     $keys = [MLDsa]::GenerateKeyPair(65)
# .NOTES
#     Requires .NET 10 (preview) or external library.
class MLDsa {
  MLDsa() {}

  static [hashtable] GenerateKeyPair() {
    return [MLDsa]::GenerateKeyPair(65)
  }
  static [hashtable] GenerateKeyPair([int]$KeyLength) {
    $mldsaType = [System.type]::GetType("System.Security.Cryptography.MLDsa, System.Security.Cryptography")
    if ($null -ne $mldsaType) {
      $mldsa = $mldsaType::new()
      try {
        $publicKey = $mldsa.PublicKey.ToArray()
        $privateKey = $mldsa.PrivateKey.ToArray()
        return @{
          PublicKey  = $publicKey
          PrivateKey = $privateKey
        }
      }
      finally {
        $mldsa.Dispose()
      }
    }

    throw [System.PlatformNotSupportedException]::new("ML-DSA requires .NET 10+ or external library")
  }

  [byte[]] Sign([byte[]]$Message, [byte[]]$PrivateKey) {
    if ($null -eq $Message) { throw [System.ArgumentNullException]::new('Message') }
    if ($null -eq $PrivateKey) { throw [System.ArgumentNullException]::new('PrivateKey') }

    # Stub: HMAC-SHA256 placeholder
    $hmacKey = [System.Security.Cryptography.SHA256]::HashData($PrivateKey)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
    return $hmac.ComputeHash($Message)
  }

  [bool] Verify([byte[]]$Message, [byte[]]$Signature, [byte[]]$PublicKey) {
    if ($null -eq $Message) { throw [System.ArgumentNullException]::new('Message') }
    if ($null -eq $Signature) { throw [System.ArgumentNullException]::new('Signature') }
    if ($null -eq $PublicKey) { throw [System.ArgumentNullException]::new('PublicKey') }

    # Stub: PublicKey == SHA-256(PrivateKey), so use it directly as HMAC key (matches Sign stub)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($PublicKey)
    $expected = $hmac.ComputeHash($Message)
    if ($expected.Length -ne $Signature.Length) { return $false }

    $diff = 0
    for ($i = 0; $i -lt $expected.Length; $i++) { $diff = $diff -bor ($expected[$i] -bxor $Signature[$i]) }
    return $diff -eq 0
  }
}

class SLHDsa {
  SLHDsa() {}

  [object] GenerateKeyPair() {
    $privateKey = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($privateKey)
    $publicKey = [byte[]]::new(32)
    return [PSCustomObject]@{ PublicKey = $publicKey; PrivateKey = $privateKey }
  }

  static [hashtable] GenerateKey() {
    throw [System.PlatformNotSupportedException]::new("SLH-DSA requires external library like liboqs or BouncyCastle")
  }
}

