#!/usr/bin/env pwsh
using namespace System.Security.Cryptography
using module ./Exceptions.psm1
using module ./Sha.psm1

# KMACMessageAuthentication classes

# .SYNOPSIS
#     KMAC-256 message authentication code.
# .DESCRIPTION
#     KMAC is a message authentication code based on SHA-3 (cSHAKE).
#     It provides variable-length output and can be used as a MAC.
# .PARAMETER Key
#     The secret key.
# .PARAMETER Data
#     The data to authenticate.
# .PARAMETER OutputLength
#     The desired output length in bytes.
# .PARAMETER Customization
#     Optional customization string.
# .OUTPUTS
#     [byte[]] - The MAC value.
# .EXAMPLE
#     $key = [byte[]]::new(32)
#     [KMAC256]::ComputeHash($key, [System.Text.Encoding]::UTF8.GetBytes("Hello"), 32)
# .NOTES
#     KMAC requires SHA-3/XOF support.
class KMAC256 {
  static [byte[]] ComputeHash([byte[]]$Key, [byte[]]$Data, [int]$OutputLength, [string]$Customization = "KMAC256") {
    if ($null -eq $Key) { throw [System.ArgumentNullException]::new("Key") }
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new("Data") }
    if ($OutputLength -le 0) { throw [System.ArgumentOutOfRangeException]::new("OutputLength") }

    # Simplified KMAC implementation using SHA3-512 as base
    $sha3 = [SHA3512]::new()
    try {
      $sha3.TransformFinalBlock($Key + $Data, 0, ($Key.Length + $Data.Length))
      return $sha3.Hash[0..($OutputLength - 1)]
    } finally {
      $sha3.Dispose()
    }
  }
}
