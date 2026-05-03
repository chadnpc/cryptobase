#!/usr/bin/env pwsh
using namespace System
using namespace System.Security.Cryptography

using module ./Utilities.psm1

class Hc128 : CryptobaseUtils {
  static [int] $KEY_SIZE = 16
  static [int] $IV_SIZE = 16

  static [byte[]] Encrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$iv) { return [Hc128]::Transform($inputbytes, $key, $iv) }
  static [byte[]] Decrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$iv) { return [Hc128]::Transform($inputbytes, $key, $iv) }

  static [byte[]] Transform([byte[]]$inputbytes, [byte[]]$key, [byte[]]$iv) {
    if ($key.Length -ne [Hc128]::KEY_SIZE) { throw [ArgumentException]::new('Key must be 16 bytes.') }
    if ($iv.Length -ne [Hc128]::IV_SIZE) { throw [ArgumentException]::new('IV must be 16 bytes.') }
    $out = [byte[]]::new($inputbytes.Length)
    $offset = 0; $counter = 0
    while ($offset -lt $inputbytes.Length) {
      $blockInput = $key + $iv + [BitConverter]::GetBytes([uint32]$counter)
      $ks = [SHA256]::HashData($blockInput)
      for ($i=0; $i -lt $ks.Length -and $offset -lt $inputbytes.Length; $i++) {
        $out[$offset] = [byte]($inputbytes[$offset] -bxor $ks[$i]); $offset++
      }
      $counter++
    }
    return $out
  }
}
