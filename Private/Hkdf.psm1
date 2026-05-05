#!/usr/bin/env pwsh
using namespace System.Security.Cryptography


#HKDFKeyDerivation
# .SYNOPSIS
#     HMAC-based Key Derivation Function (HKDF).
# .DESCRIPTION
#     HKDF is a key derivation function defined in RFC 5869.
#     It derives one or more secret keys from a master key.
# .PARAMETER IKM
#     The input key material.
# .PARAMETER Salt
#     Optional salt value (can be empty).
# .PARAMETER Info
#     Optional context and application specific information.
# .PARAMETER OutputLength
#     The desired length of the output key.
# .OUTPUTS
#     [byte[]] - The derived key.
# .EXAMPLE
#     $ikm = [System.Text.Encoding]::UTF8.GetBytes("master-key")
#     $salt = [System.Text.Encoding]::UTF8.GetBytes("salt")
#     $info = [System.Text.Encoding]::UTF8.GetBytes("app-info")
#     [HkdfCore]::DeriveKey($ikm, $salt, $info, 32)
class HkdfCore {
  static [byte[]] DeriveKey([byte[]]$IKM, [byte[]]$Salt, [byte[]]$Info, [int]$OutputLength) {
    if ($null -eq $IKM) { throw [System.ArgumentNullException]::new("IKM") }
    if ($OutputLength -le 0) { throw [System.ArgumentOutOfRangeException]::new("OutputLength") }

    # Try .NET 8+ native implementation first
    $hkdfType = [System.type]::GetType("System.Security.Cryptography.Hkdf, System.Security.Cryptography")
    if ($null -ne $hkdfType) {
      $hkdf = $hkdfType::new()
      try {
        return $hkdf.DeriveKey($IKM, $Salt, $Info, $OutputLength)
      }
      finally {
        $hkdf.Dispose()
      }
    }

    # Fall back to manual HKDF implementation
    return [HkdfCore]::HkdfExpand(
      [HkdfCore]::HkdfExtract($IKM, $Salt),
      $Info,
      $OutputLength
    )
  }

  static [byte[]] HkdfExtract([byte[]]$IKM, [byte[]]$Salt) {
    if ($null -eq $IKM) { throw [System.ArgumentNullException]::new("IKM") }
    if ($null -eq $Salt) { $Salt = [byte[]]::new(0) }

    $hmac = [System.Security.Cryptography.HMACSHA256]::new()
    try {
      $hmac.Key = $Salt
      return $hmac.ComputeHash($IKM)
    }
    finally {
      $hmac.Dispose()
    }
  }

  static [byte[]] HkdfExpand([byte[]]$PRK, [byte[]]$Info, [int]$OutputLength) {
    if ($null -eq $PRK) { throw [System.ArgumentNullException]::new("PRK") }
    if ($OutputLength -le 0) { throw [System.ArgumentOutOfRangeException]::new("OutputLength") }
    if ($OutputLength -gt 255 * 32) { throw [System.ArgumentOutOfRangeException]::new("OutputLength too large") }

    $hashLen = 32  # SHA256
    $n = [Math]::Ceiling($OutputLength / $hashLen)
    $T = [byte[]]::new(0)
    $OKM = [byte[]]::new($OutputLength)

    $hmac = [System.Security.Cryptography.HMACSHA256]::new()
    try {
      $hmac.Key = $PRK

      for ($i = 1; $i -le $n; $i++) {
        $temp = [System.IO.MemoryStream]::new()
        if ($i -gt 1) {
          $temp.Write($T, 0, $T.Length)
        }
        if ($null -ne $Info) {
          $temp.Write($Info, 0, $Info.Length)
        }
        $temp.WriteByte([byte]$i)

        $T = $hmac.ComputeHash($temp.ToArray())

        [Array]::Copy($T, 0, $OKM, ($i - 1) * $hashLen, [Math]::Min($hashLen, $OutputLength - ($i - 1) * $hashLen))
      }

      return $OKM
    }
    finally {
      $hmac.Dispose()
    }
  }
}